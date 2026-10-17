package transport

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/rand/v2"
	"net/http"
	"strconv"
	"sync"
	"time"

	commonsentinel "nocert.io/common/pkg/api/sentinel"
	"nocert.io/common/pkg/httpsig"
	"nocert.io/sentinel/internal/signing"
)

// errTransient marks a network-level failure (send failed, body read failed)
// that a report send MAY retry. It deliberately does NOT cover response-signature
// / digest verification failures: those mean the backend received the report but
// the response was unverifiable (misconfig or tampering), so re-delivering would
// amplify a security anomaly rather than recover from a blip.
var errTransient = errors.New("transient transport error")

// ErrCredentialsRejected marks a 401 or 403: the backend refused the identity we
// sign with. Every reason behind it is permanent (sentinel deleted, key replaced
// or expired, sentinel deactivated, clock too far off) and needs a human, so the
// poll loop uses it to tell an actionable failure from a passing blip.
var ErrCredentialsRejected = errors.New("backend rejected the sentinel credentials")

// maxRejectionReasonBytes bounds how much of the rejection body we quote. A
// non-2xx body is unverified and can come from anything on the path (proxy, WAF),
// so it goes in an operator-facing log line as a short clue, never in full.
const maxRejectionReasonBytes = 256

// Report delivery is retried on transient failures (network error, 429, 5xx) so a
// momentary backend/proxy blip - or a 429 from a multi-sentinel NAT sharing the
// pre-auth rate bucket - doesn't silently drop a scan batch. Re-sends are safe:
// ES ingestion is keyed by cert fingerprint / observation identity, so a report
// that actually landed before the response was lost is deduplicated, not doubled.
// These are vars (not consts) purely so tests can shrink the delays.
var (
	reportMaxAttempts    = 4
	reportRetryBaseDelay = 1 * time.Second
	reportRetryMaxDelay  = 30 * time.Second
)

// maxHonoredRetryAfterSeconds bounds a server-supplied Retry-After we will honor;
// anything larger (or overflowing) is ignored in favour of our own backoff.
const maxHonoredRetryAfterSeconds = 3600

// SetReportRetryForTest overrides the report retry schedule and returns a restore
// func. Report retry is exercised in this package's own tests; consumers driving
// delivery paths (e.g. the agent tests) call this to run single-attempt with no
// backoff, so a failing-delivery path stays one report and adds no real delay.
func SetReportRetryForTest(maxAttempts int, baseDelay time.Duration) (restore func()) {
	oldAttempts, oldBase := reportMaxAttempts, reportRetryBaseDelay
	reportMaxAttempts, reportRetryBaseDelay = maxAttempts, baseDelay
	return func() { reportMaxAttempts, reportRetryBaseDelay = oldAttempts, oldBase }
}

// httpClientTimeout caps every backend-bound HTTP request (the signed client and
// the one-shot register client). Sized for a slow backend or proxy roundtrip.
const httpClientTimeout = 30 * time.Second

// maxResponseBytes bounds a response body so a hostile or buggy backend/proxy
// can't OOM the agent by streaming forever (the timeout caps time, not size).
const maxResponseBytes = 8 << 20 // 8 MiB

// sharedTransport is used by both the signed client and Register. Explicit so a
// mutated http.DefaultTransport can't silently drop the client forward-proxy
// support many deployments mandate.
var sharedTransport = &http.Transport{
	Proxy:             http.ProxyFromEnvironment,
	TLSClientConfig:   &tls.Config{MinVersion: tls.VersionTLS12},
	ForceAttemptHTTP2: true,
}

// noRedirect stops the HTTP client from following 3xx responses. The backend
// API never legitimately redirects, and a redirect can't yield a valid signed
// exchange (the RFC 9421 signature binds @authority and @target-uri to the
// original URL). Refusing to follow keeps a signed request, or the enrollment
// Bearer, from being replayed to an attacker-chosen host by a hostile proxy or
// on-path attacker.
func noRedirect(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }

// Client is the signed HTTP transport for sentinel-server communication.
type Client struct {
	mu            sync.RWMutex
	baseURL       string
	sentinelID    string
	keyID         string
	privateKey    ed25519.PrivateKey
	signingPubKey ed25519.PublicKey
	signingKeyID  string
	version       string
	httpClient    *http.Client
	logger        *slog.Logger
}

func is2xx(status int) bool {
	return status >= 200 && status < 300
}

// NewClient creates a new signed HTTP transport client. signingKeyID is
// the keyid the sentinel expects on inbound RFC 9421 response
// signatures (mirrors the backend's configured signing key id). Pass empty
// to fall back to keystore.DefaultSigningKeyID. version is the agent's own
// build version, sent as the advisory X-Sentinel-Version header on every
// signed request; empty omits the header.
func NewClient(baseURL, sentinelID, keyID string, privateKey ed25519.PrivateKey, signingPubKey ed25519.PublicKey, signingKeyID string, version string, logger *slog.Logger) *Client {
	return &Client{
		baseURL:       baseURL,
		sentinelID:    sentinelID,
		keyID:         keyID,
		privateKey:    privateKey,
		signingPubKey: signingPubKey,
		signingKeyID:  signingKeyID,
		version:       version,
		httpClient:    &http.Client{Timeout: httpClientTimeout, Transport: sharedTransport, CheckRedirect: noRedirect},
		logger:        logger,
	}
}

// UpdateCredentials replaces the signing credentials after key rotation.
func (c *Client) UpdateCredentials(keyID string, privateKey ed25519.PrivateKey) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.keyID = keyID
	c.privateKey = privateKey
}

// Wire types are owned by nocert-common (pkg/api/sentinel); these aliases keep
// the frozen contract compiler-enforced end-to-end.

// TaskResponse is one task pulled from the server (alias of commonsentinel.TaskResponse).
type TaskResponse = commonsentinel.TaskResponse

// SentinelConfig is the per-organization scan configuration embedded in
// every TasksResponse (alias of commonsentinel.SentinelConfig).
type SentinelConfig = commonsentinel.SentinelConfig

// TasksResponse is the response from GET /tasks (alias of commonsentinel.TasksResponse).
type TasksResponse = commonsentinel.TasksResponse

// Certificate carries a raw DER blob with its SHA-256 fingerprint.
type Certificate = commonsentinel.Certificate

// TLSObservation carries TLS handshake metadata.
type TLSObservation = commonsentinel.TLSObservation

// SentinelNetworkObservation links one (IP, port, sni?) endpoint to its
// observed certificate chain by fingerprint.
type SentinelNetworkObservation = commonsentinel.SentinelNetworkObservation

// SentinelFilesystemObservation links a certificate (by fingerprint) to the
// absolute paths it was found at on this host, plus filesystem-state warnings.
type SentinelFilesystemObservation = commonsentinel.SentinelFilesystemObservation

// SentinelKubernetesObservation links certificates extracted from one
// Kubernetes Secret/ConfigMap data key to their fingerprints.
type SentinelKubernetesObservation = commonsentinel.SentinelKubernetesObservation

// KubernetesSweepResult is the per-cluster completeness + observed
// location-key set used for reconciliation.
type KubernetesSweepResult = commonsentinel.KubernetesSweepResult

// ReportRequest is the body for POST /report (alias of commonsentinel.ReportRequest).
type ReportRequest = commonsentinel.ReportRequest

// RotateRequest is the body for POST /sentinels/rotate.
type RotateRequest = commonsentinel.RotateRequest

// RotateResponse is the server's response to a key rotation.
type RotateResponse = commonsentinel.RotateResponse

// RegisterRequest is the body for POST /sentinels/register (unauthenticated).
type RegisterRequest = commonsentinel.RegisterRequest

// RegisterResponse is the server's response to registration.
type RegisterResponse = commonsentinel.RegisterResponse

// GetTasks polls the server for pending tasks (also acts as heartbeat).
func (c *Client) GetTasks(ctx context.Context) (*TasksResponse, error) {
	path := fmt.Sprintf("/api/v1/sentinels/%s/tasks", c.sentinelID)

	resp, body, err := c.doSigned(ctx, http.MethodGet, path, nil)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		reason := bytes.TrimSpace(body)
		if len(reason) > maxRejectionReasonBytes {
			reason = reason[:maxRejectionReasonBytes]
		}
		return nil, fmt.Errorf("%w (status %d): %s", ErrCredentialsRejected, resp.StatusCode, reason)
	}
	if !is2xx(resp.StatusCode) {
		return nil, fmt.Errorf("unexpected status %d: %s", resp.StatusCode, string(body))
	}

	var tasks TasksResponse
	if err := json.Unmarshal(body, &tasks); err != nil {
		return nil, fmt.Errorf("parsing tasks response: %w", err)
	}
	return &tasks, nil
}

// PostReport sends scan results or task completion to the server, retrying
// transient failures with backoff+jitter so a blip doesn't drop the batch.
func (c *Client) PostReport(ctx context.Context, report *ReportRequest) error {
	path := fmt.Sprintf("/api/v1/sentinels/%s/report", c.sentinelID)

	payload, err := json.Marshal(report)
	if err != nil {
		return fmt.Errorf("marshaling report: %w", err)
	}

	var lastErr error
	var retryAfter time.Duration
	for attempt := 0; attempt < reportMaxAttempts; attempt++ {
		if attempt > 0 {
			if err := sleepCtx(ctx, retryDelay(attempt, retryAfter)); err != nil {
				return err // context cancelled/expired between attempts
			}
		}
		retryAfter = 0

		resp, body, err := c.doSigned(ctx, http.MethodPost, path, payload)
		if err != nil {
			// Retry only genuine network blips; a signing or response-verification
			// failure is permanent (and re-delivering an unverifiable exchange is
			// the wrong response to a possible tamper), so surface it immediately.
			if errors.Is(err, errTransient) {
				lastErr = err
				continue
			}
			return err
		}
		if is2xx(resp.StatusCode) {
			return nil
		}
		// A 4xx other than 429 is permanent (bad request, signature rejected):
		// retrying won't help, so surface it immediately.
		if resp.StatusCode != http.StatusTooManyRequests && resp.StatusCode < 500 {
			return fmt.Errorf("unexpected status %d: %s", resp.StatusCode, string(body))
		}
		lastErr = fmt.Errorf("unexpected status %d: %s", resp.StatusCode, string(body))
		if resp.StatusCode == http.StatusTooManyRequests {
			retryAfter = parseRetryAfter(resp.Header.Get("Retry-After"))
		}
	}
	return fmt.Errorf("report failed after %d attempts: %w", reportMaxAttempts, lastErr)
}

// retryDelay is the wait before the given attempt (attempt >= 1). It honors a
// server Retry-After when present, else exponential backoff with equal jitter
// ([backoff/2, backoff]) capped at reportRetryMaxDelay - the jitter spreads a
// NAT-colocated fleet that all got 429'd at once instead of retrying in lockstep.
func retryDelay(attempt int, retryAfter time.Duration) time.Duration {
	if retryAfter > 0 {
		return min(retryAfter, reportRetryMaxDelay)
	}
	backoff := reportRetryBaseDelay << (attempt - 1)
	if backoff > reportRetryMaxDelay || backoff <= 0 {
		backoff = reportRetryMaxDelay
	}
	half := backoff / 2
	return half + time.Duration(rand.Int64N(int64(half)+1))
}

// sleepCtx waits d, returning early with the context error if it is cancelled.
func sleepCtx(ctx context.Context, d time.Duration) error {
	if d <= 0 {
		return ctx.Err()
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

// parseRetryAfter parses a Retry-After header (delay-seconds or HTTP-date),
// returning 0 when absent or unparseable.
func parseRetryAfter(v string) time.Duration {
	if v == "" {
		return 0
	}
	if secs, err := strconv.Atoi(v); err == nil {
		// Ignore non-positive, absurd, or overflow-inducing values: a hostile proxy
		// must not be able to stall the agent with a giant Retry-After, and our own
		// backoff (capped at reportRetryMaxDelay) covers the fallback.
		if secs <= 0 || secs > maxHonoredRetryAfterSeconds {
			return 0
		}
		return time.Duration(secs) * time.Second
	}
	if t, err := http.ParseTime(v); err == nil {
		if d := time.Until(t); d > 0 {
			return d
		}
	}
	return 0
}

// RotateKey sends a new public key to the server and returns the new key_id and expiry.
func (c *Client) RotateKey(ctx context.Context, newPubKeyB64 string) (*RotateResponse, error) {
	path := "/api/v1/sentinels/rotate"

	payload, err := json.Marshal(RotateRequest{NewPublicKey: newPubKeyB64})
	if err != nil {
		return nil, fmt.Errorf("marshaling rotate request: %w", err)
	}

	resp, body, err := c.doSigned(ctx, http.MethodPost, path, payload)
	if err != nil {
		return nil, err
	}
	if !is2xx(resp.StatusCode) {
		return nil, fmt.Errorf("unexpected status %d: %s", resp.StatusCode, string(body))
	}

	var result RotateResponse
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("parsing rotate response: %w", err)
	}
	return &result, nil
}

// Register performs an unauthenticated registration request with a Bearer token.
// This does NOT use Ed25519 signing - registration happens before the sentinel has credentials.
//
// The server's response IS RFC 9421 signed (with the bootstrap server
// public key), but we deliberately skip verification here: the response
// carries the very `signing_public_key` that we'd need to verify it,
// so verification would be circular. The Bearer enrollment token
// already establishes provenance for the bootstrap path.
func Register(ctx context.Context, serverURL, token string, regReq RegisterRequest) (*RegisterResponse, error) {
	url := serverURL + "/api/v1/sentinels/register"

	payload, err := json.Marshal(regReq)
	if err != nil {
		return nil, fmt.Errorf("marshaling register request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(payload))
	if err != nil {
		return nil, fmt.Errorf("creating register request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)

	client := &http.Client{Timeout: httpClientTimeout, Transport: sharedTransport, CheckRedirect: noRedirect}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("sending register request: %w", err)
	}
	defer func(body io.ReadCloser) { _ = body.Close() }(resp.Body)

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes))
	if err != nil {
		return nil, fmt.Errorf("reading register response: %w", err)
	}

	if !is2xx(resp.StatusCode) {
		return nil, fmt.Errorf("registration failed (status %d): %s", resp.StatusCode, string(body))
	}

	var result RegisterResponse
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("parsing register response: %w", err)
	}
	return &result, nil
}

// doSigned signs (RFC 9421), sends the request and verifies the response
// signature. A non-2xx response is UNVERIFIED: callers must act on the status
// code alone, never on its body or headers.
func (c *Client) doSigned(ctx context.Context, method, path string, body []byte) (*http.Response, []byte, error) {
	c.mu.RLock()
	baseURL := c.baseURL
	keyID := c.keyID
	privateKey := c.privateKey
	signingPub := c.signingPubKey
	signingKeyID := c.signingKeyID
	c.mu.RUnlock()

	url := baseURL + path

	var bodyReader io.Reader
	if body != nil {
		bodyReader = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, url, bodyReader)
	if err != nil {
		return nil, nil, fmt.Errorf("creating request: %w", err)
	}
	if len(body) > 0 {
		req.Header.Set("Content-Type", "application/json")
	}

	if c.version != "" {
		// Advisory, unsigned: lets the backend refresh this agent's stored
		// version on the poll heartbeat (in-place upgrades never re-enroll).
		req.Header.Set("X-Sentinel-Version", c.version)
	}

	if err := signing.SignRequest(req, body, privateKey, keyID); err != nil {
		return nil, nil, fmt.Errorf("signing request: %w", err)
	}

	ourNonce, err := signing.NonceFromRequest(req)
	if err != nil {
		return nil, nil, fmt.Errorf("extracting request nonce: %w", err)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, nil, fmt.Errorf("sending request: %w", errors.Join(errTransient, err))
	}
	defer func(body io.ReadCloser) { _ = body.Close() }(resp.Body)

	respBody, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes))
	if err != nil {
		return nil, nil, fmt.Errorf("reading response body: %w", errors.Join(errTransient, err))
	}

	// Only 2xx responses are signed; unsigned 4xx/5xx (rate-limiter, proxy) would
	// otherwise be misreported as "signature invalid".
	if is2xx(resp.StatusCode) {
		// The signature covers the Content-Digest value only; recompute it from the
		// received bytes to catch a tampered body.
		if resp.Header.Get("Content-Digest") != httpsig.ContentDigest(respBody) {
			return nil, nil, fmt.Errorf("response content digest mismatch")
		}
		if err := signing.VerifyResponse(resp, ourNonce, signingPub, signingKeyID); err != nil {
			return nil, nil, fmt.Errorf("response signature invalid: %w", err)
		}
	}

	// Hand back a consumable body regardless of the path taken above.
	resp.Body = io.NopCloser(bytes.NewReader(respBody))

	return resp, respBody, nil
}
