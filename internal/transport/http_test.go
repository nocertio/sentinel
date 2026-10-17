package transport

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"nocert.io/common/pkg/httpsig"
)

type closeTrackingBody struct {
	io.ReadCloser
	closed bool
}

func (b *closeTrackingBody) Close() error {
	b.closed = true
	return b.ReadCloser.Close()
}

type closeTrackingTransport struct {
	http.RoundTripper
	body *closeTrackingBody
}

func (t *closeTrackingTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	resp, err := t.RoundTripper.RoundTrip(req)
	if err == nil {
		t.body = &closeTrackingBody{ReadCloser: resp.Body}
		resp.Body = t.body
	}
	return resp, err
}

func TestDoSignedClosesOriginalResponseBody(t *testing.T) {
	c := newReportClient(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = w.Write([]byte("unavailable"))
	})
	tr := &closeTrackingTransport{RoundTripper: c.httpClient.Transport}
	c.httpClient.Transport = tr
	resp, _, err := c.doSigned(context.Background(), http.MethodGet, "/tasks", nil)
	if err != nil {
		t.Fatal(err)
	}
	if tr.body == nil || !tr.body.closed {
		t.Fatal("original response body was not closed")
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil || string(body) != "unavailable" {
		t.Fatalf("replacement response body: %q, error: %v", body, err)
	}
}

// fastRetriesForTest shrinks the report retry delays so retry tests run instantly,
// restoring the defaults afterwards.
func fastRetriesForTest(t *testing.T) {
	t.Helper()
	oldBase, oldMax := reportRetryBaseDelay, reportMaxAttempts
	reportRetryBaseDelay = time.Millisecond
	t.Cleanup(func() { reportRetryBaseDelay = oldBase; reportMaxAttempts = oldMax })
}

// newReportClient builds a signed client against a server whose handler is h. The
// server signing key matches the client's expected key, so a signed 2xx verifies;
// unsigned 4xx/5xx responses exercise the retry decisions (doSigned only verifies 2xx).
func newReportClient(t *testing.T, h http.HandlerFunc) *Client {
	t.Helper()
	sentinelPriv := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x11}, ed25519.SeedSize))
	serverPriv := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x22}, ed25519.SeedSize))
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	return NewClient(srv.URL, "sentinel-id-1", "sentinel-1", sentinelPriv, serverPriv.Public().(ed25519.PublicKey), "server-1", "1.2.3", logger)
}

// TestPostReport_RetriesTransientThenSucceeds pins report-delivery durability: two
// transient 429s are retried and the batch is delivered (signed 202) rather than
// silently dropped.
func TestPostReport_RetriesTransientThenSucceeds(t *testing.T) {
	fastRetriesForTest(t)

	sentinelPriv := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x11}, ed25519.SeedSize))
	serverPriv := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x22}, ed25519.SeedSize))
	const signingKeyID = "server-1"

	var attempts int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if atomic.AddInt32(&attempts, 1) < 3 {
			w.WriteHeader(http.StatusTooManyRequests) // transient, unsigned
			return
		}
		details, err := httpsig.RequestDetails(r)
		if err != nil {
			t.Errorf("parse signature-input: %v", err)
			http.Error(w, "no nonce", http.StatusBadRequest)
			return
		}
		respBody := []byte(`{"accepted":true}`)
		digest, si, sg := httpsig.SignResponse(http.StatusAccepted, respBody, details.Nonce, serverPriv, signingKeyID)
		w.Header().Set("Content-Digest", digest)
		w.Header().Set("Signature-Input", si)
		w.Header().Set("Signature", sg)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusAccepted)
		_, _ = w.Write(respBody)
	}))
	t.Cleanup(srv.Close)

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	c := NewClient(srv.URL, "sentinel-id-1", "sentinel-1", sentinelPriv, serverPriv.Public().(ed25519.PublicKey), signingKeyID, "1.2.3", logger)

	if err := c.PostReport(context.Background(), &ReportRequest{}); err != nil {
		t.Fatalf("PostReport should have succeeded after retries: %v", err)
	}
	if got := atomic.LoadInt32(&attempts); got != 3 {
		t.Fatalf("expected 3 attempts (2x429 + 1x202), got %d", got)
	}
}

// TestPostReport_PermanentErrorNotRetried: a 4xx other than 429 fails immediately.
func TestPostReport_PermanentErrorNotRetried(t *testing.T) {
	fastRetriesForTest(t)
	var attempts int32
	c := newReportClient(t, func(w http.ResponseWriter, _ *http.Request) {
		atomic.AddInt32(&attempts, 1)
		http.Error(w, "bad request", http.StatusBadRequest)
	})
	if err := c.PostReport(context.Background(), &ReportRequest{}); err == nil {
		t.Fatal("expected error on 400")
	}
	if got := atomic.LoadInt32(&attempts); got != 1 {
		t.Fatalf("400 must not be retried, got %d attempts", got)
	}
}

// TestPostReport_ExhaustsRetriesOn5xx: a persistent 5xx retries up to the cap then errors.
func TestPostReport_ExhaustsRetriesOn5xx(t *testing.T) {
	fastRetriesForTest(t)
	var attempts int32
	c := newReportClient(t, func(w http.ResponseWriter, _ *http.Request) {
		atomic.AddInt32(&attempts, 1)
		http.Error(w, "boom", http.StatusInternalServerError)
	})
	if err := c.PostReport(context.Background(), &ReportRequest{}); err == nil {
		t.Fatal("expected error after exhausting retries")
	}
	if got := atomic.LoadInt32(&attempts); got != int32(reportMaxAttempts) {
		t.Fatalf("expected %d attempts, got %d", reportMaxAttempts, got)
	}
}

// TestPostReport_UnverifiableResponseNotRetried: a 2xx whose signature/digest
// can't be verified is a permanent (security) failure, not a transient blip, so
// the report is not re-delivered.
func TestPostReport_UnverifiableResponseNotRetried(t *testing.T) {
	fastRetriesForTest(t)
	var attempts int32
	c := newReportClient(t, func(w http.ResponseWriter, _ *http.Request) {
		atomic.AddInt32(&attempts, 1)
		w.WriteHeader(http.StatusOK) // 200 but unsigned → verification fails
		_, _ = w.Write([]byte(`{"accepted":true}`))
	})
	if err := c.PostReport(context.Background(), &ReportRequest{}); err == nil {
		t.Fatal("expected error on an unverifiable response")
	}
	if got := atomic.LoadInt32(&attempts); got != 1 {
		t.Fatalf("an unverifiable (non-transient) response must not be retried, got %d attempts", got)
	}
}

func TestParseRetryAfter(t *testing.T) {
	if got := parseRetryAfter("5"); got != 5*time.Second {
		t.Fatalf("delay-seconds: got %v want 5s", got)
	}
	for _, v := range []string{"", "garbage", "0", "-3", "99999999999999"} { // last one overflows Duration
		if got := parseRetryAfter(v); got != 0 {
			t.Fatalf("parseRetryAfter(%q) = %v, want 0", v, got)
		}
	}
}

func TestSharedTransportTLSMinimum(t *testing.T) {
	if sharedTransport.TLSClientConfig == nil {
		t.Fatal("shared transport has no TLS configuration")
	}
	if got := sharedTransport.TLSClientConfig.MinVersion; got != tls.VersionTLS12 {
		t.Fatalf("minimum TLS version = %d, want TLS 1.2", got)
	}
	if !sharedTransport.ForceAttemptHTTP2 {
		t.Fatal("HTTP/2 must remain enabled with the custom TLS configuration")
	}
}

func TestBackendTransportRejectsUntrustedCertificate(t *testing.T) {
	var called atomic.Bool
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		called.Store(true)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	tr := sharedTransport.Clone()
	defer tr.CloseIdleConnections()
	client := &http.Client{Transport: tr, Timeout: time.Second}
	resp, err := client.Get(srv.URL)
	if resp != nil {
		_ = resp.Body.Close()
	}
	var untrusted x509.UnknownAuthorityError
	if !errors.As(err, &untrusted) {
		t.Fatalf("backend connection must reject an untrusted certificate, got %v", err)
	}
	if called.Load() {
		t.Fatal("HTTP request reached an unauthenticated backend")
	}
}

// TestDoSigned_RoundTrip wires up a fake backend that:
//   - verifies the inbound RFC 9421 signature (canonical httpsign lib),
//   - extracts the request nonce, and
//   - signs the response with tag = request nonce.
//
// It then invokes c.doSigned (indirectly via GetTasks) and asserts the
// transport accepts the response and parses the body.
func TestDoSigned_RoundTrip(t *testing.T) {
	// Sentinel keypair (signs the request).
	sentinelSeed := bytes.Repeat([]byte{0x11}, ed25519.SeedSize)
	sentinelPriv := ed25519.NewKeyFromSeed(sentinelSeed)
	sentinelPub := sentinelPriv.Public().(ed25519.PublicKey)

	// Server keypair (signs the response).
	serverSeed := bytes.Repeat([]byte{0x22}, ed25519.SeedSize)
	serverPriv := ed25519.NewKeyFromSeed(serverSeed)
	signingPub := serverPriv.Public().(ed25519.PublicKey)

	const sentinelKeyID = "sentinel-1"
	const signingKeyID = "server-1"

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify the inbound RFC 9421 signature.
		if err := httpsig.VerifyRequest(r, sentinelPub, sentinelKeyID, nil); err != nil {
			t.Errorf("server verify request: %v", err)
			http.Error(w, err.Error(), http.StatusUnauthorized)
			return
		}

		// Extract nonce from the inbound Signature-Input so we can bind
		// the response to it via the `tag` parameter.
		details, err := httpsig.RequestDetails(r)
		if err != nil || details.Nonce == "" {
			t.Errorf("server parse signature-input: %v", err)
			http.Error(w, "no nonce", http.StatusBadRequest)
			return
		}
		reqNonce := details.Nonce

		// Build the response body.
		respBody, err := json.Marshal(TasksResponse{
			Config: SentinelConfig{
				IPRanges:                   []string{"10.0.0.0/24"},
				Ports:                      []int{443},
				ScanNetworkIntervalSeconds: 3600,
				ScanEnabled:                true,
			},
			Tasks: []TaskResponse{
				{ID: "task-1", Type: "network_scan"},
			},
		})
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}

		// Sign the response with tag = request nonce.
		digest, si, sg := httpsig.SignResponse(http.StatusOK, respBody, reqNonce, serverPriv, signingKeyID)
		w.Header().Set("Content-Digest", digest)
		w.Header().Set("Signature-Input", si)
		w.Header().Set("Signature", sg)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		if _, err := w.Write(respBody); err != nil {
			t.Errorf("server write: %v", err)
		}
	}))
	defer srv.Close()

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	c := NewClient(srv.URL, "sentinel-id-1", sentinelKeyID, sentinelPriv, signingPub, signingKeyID, "1.2.3", logger)

	tasks, err := c.GetTasks(context.Background())
	if err != nil {
		t.Fatalf("GetTasks: %v", err)
	}
	if len(tasks.Tasks) != 1 || tasks.Tasks[0].ID != "task-1" {
		t.Errorf("unexpected tasks: %+v", tasks)
	}
}

// TestDoSigned_RejectsResponseWithWrongTag asserts the transport
// refuses a response whose tag does not match the request nonce we
// just sent (replay defense).
func TestDoSigned_RejectsResponseWithWrongTag(t *testing.T) {
	sentinelSeed := bytes.Repeat([]byte{0x11}, ed25519.SeedSize)
	sentinelPriv := ed25519.NewKeyFromSeed(sentinelSeed)

	serverSeed := bytes.Repeat([]byte{0x22}, ed25519.SeedSize)
	serverPriv := ed25519.NewKeyFromSeed(serverSeed)
	signingPub := serverPriv.Public().(ed25519.PublicKey)

	const sentinelKeyID = "sentinel-1"
	const signingKeyID = "server-1"

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		respBody, _ := json.Marshal(TasksResponse{})

		// Deliberately tag with a value that does NOT match the inbound
		// request nonce.
		digest, si, sg := httpsig.SignResponse(http.StatusOK, respBody, "not-the-real-nonce", serverPriv, signingKeyID)
		w.Header().Set("Content-Digest", digest)
		w.Header().Set("Signature-Input", si)
		w.Header().Set("Signature", sg)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		if _, err := w.Write(respBody); err != nil {
			t.Errorf("server write: %v", err)
		}
	}))
	defer srv.Close()

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	c := NewClient(srv.URL, "sentinel-id-1", sentinelKeyID, sentinelPriv, signingPub, signingKeyID, "1.2.3", logger)

	if _, err := c.GetTasks(context.Background()); err == nil {
		t.Errorf("expected GetTasks to fail on bad response tag, got nil")
	} else if !strings.Contains(err.Error(), "signature") {
		t.Errorf("expected signature error, got %v", err)
	}
}

// TestDoSigned_UnsignedErrorResponseSurfacesStatus asserts that an unsigned
// error response (e.g. a 429 from a rate-limiter middleware, which never
// signs) is surfaced as its HTTP status - not misreported as a signature
// failure. Signature verification applies to 2xx responses only.
func TestDoSigned_UnsignedErrorResponseSurfacesStatus(t *testing.T) {
	sentinelSeed := bytes.Repeat([]byte{0x11}, ed25519.SeedSize)
	sentinelPriv := ed25519.NewKeyFromSeed(sentinelSeed)
	serverSeed := bytes.Repeat([]byte{0x22}, ed25519.SeedSize)
	signingPub := ed25519.NewKeyFromSeed(serverSeed).Public().(ed25519.PublicKey)

	// Rate-limiter style: a plain, unsigned 429 - no Signature headers.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, `{"error":"rate limit exceeded"}`, http.StatusTooManyRequests)
	}))
	defer srv.Close()

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	c := NewClient(srv.URL, "sentinel-id-1", "sentinel-1", sentinelPriv, signingPub, "server-1", "1.2.3", logger)

	_, err := c.GetTasks(context.Background())
	if err == nil {
		t.Fatal("expected an error for a 429 response")
	}
	if strings.Contains(err.Error(), "signature") {
		t.Fatalf("a 429 must not be reported as a signature error, got: %v", err)
	}
	if !strings.Contains(err.Error(), "429") {
		t.Fatalf("error should surface the 429 status, got: %v", err)
	}
}

// TestGetTasks_RejectedCredentialsAreDistinguishable asserts the statuses that
// mean "this identity is refused" are surfaced as such, carrying the server's
// reason: the poll loop escalates on them, so they must not be flattened into a
// generic status error. 403 covers a deactivated sentinel and an expired key,
// which are as permanent as an unknown one (rotation is signed too).
func TestGetTasks_RejectedCredentialsAreDistinguishable(t *testing.T) {
	for status, reason := range map[int]string{
		http.StatusUnauthorized: "unknown sentinel",
		http.StatusForbidden:    "sentinel key expired",
	} {
		c := newReportClient(t, func(w http.ResponseWriter, _ *http.Request) {
			http.Error(w, `{"error":"`+reason+`"}`, status)
		})

		_, err := c.GetTasks(context.Background())
		if !errors.Is(err, ErrCredentialsRejected) {
			t.Fatalf("status %d: expected a credential rejection, got: %v", status, err)
		}
		if !strings.Contains(err.Error(), reason) {
			t.Fatalf("status %d: the server reason must survive into the error, got: %v", status, err)
		}
	}
}

// TestGetTasks_RejectionReasonIsBounded: the rejection body is unverified and
// can come from any proxy on the path, and it lands in a log line, so only a
// short clue is quoted.
func TestGetTasks_RejectionReasonIsBounded(t *testing.T) {
	c := newReportClient(t, func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, strings.Repeat("A", 64<<10), http.StatusUnauthorized)
	})

	_, err := c.GetTasks(context.Background())
	if !errors.Is(err, ErrCredentialsRejected) {
		t.Fatalf("expected a credential rejection, got: %v", err)
	}
	if n := strings.Count(err.Error(), "A"); n != maxRejectionReasonBytes {
		t.Fatalf("quoted %d bytes of the rejection body, want %d", n, maxRejectionReasonBytes)
	}
}

// TestDoSigned_RejectsBodyNotMatchingDigest asserts a 2xx whose body does not
// match its own Content-Digest header is rejected - the response body-tamper
// defense symmetric to the backend's request-side check.
func TestDoSigned_RejectsBodyNotMatchingDigest(t *testing.T) {
	sentinelSeed := bytes.Repeat([]byte{0x11}, ed25519.SeedSize)
	sentinelPriv := ed25519.NewKeyFromSeed(sentinelSeed)
	serverSeed := bytes.Repeat([]byte{0x22}, ed25519.SeedSize)
	serverPriv := ed25519.NewKeyFromSeed(serverSeed)
	signingPub := serverPriv.Public().(ed25519.PublicKey)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		details, _ := httpsig.RequestDetails(r)
		signed, _ := json.Marshal(TasksResponse{})
		// Sign over `signed`, but put different bytes on the wire.
		digest, si, sg := httpsig.SignResponse(http.StatusOK, signed, details.Nonce, serverPriv, "server-1")
		w.Header().Set("Content-Digest", digest)
		w.Header().Set("Signature-Input", si)
		w.Header().Set("Signature", sg)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"tasks":[{"id":"injected"}]}`))
	}))
	defer srv.Close()

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	c := NewClient(srv.URL, "sentinel-id-1", "sentinel-1", sentinelPriv, signingPub, "server-1", "1.2.3", logger)

	if _, err := c.GetTasks(context.Background()); err == nil {
		t.Fatal("expected an error for a body that does not match its Content-Digest")
	} else if !strings.Contains(err.Error(), "digest") {
		t.Fatalf("expected a content digest mismatch error, got: %v", err)
	}
}

// TestDoSigned_UnsignedSuccessFailsClosed asserts a 2xx carrying a valid
// Content-Digest but NO Signature-Input is rejected - an unsigned success must
// never be silently accepted just because its digest matches.
func TestDoSigned_UnsignedSuccessFailsClosed(t *testing.T) {
	sentinelSeed := bytes.Repeat([]byte{0x11}, ed25519.SeedSize)
	sentinelPriv := ed25519.NewKeyFromSeed(sentinelSeed)
	serverSeed := bytes.Repeat([]byte{0x22}, ed25519.SeedSize)
	signingPub := ed25519.NewKeyFromSeed(serverSeed).Public().(ed25519.PublicKey)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		respBody, _ := json.Marshal(TasksResponse{})
		// Valid digest, but no Signature-Input / Signature at all.
		w.Header().Set("Content-Digest", httpsig.ContentDigest(respBody))
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(respBody)
	}))
	defer srv.Close()

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	c := NewClient(srv.URL, "sentinel-id-1", "sentinel-1", sentinelPriv, signingPub, "server-1", "1.2.3", logger)

	if _, err := c.GetTasks(context.Background()); err == nil {
		t.Fatal("expected an unsigned 2xx to be rejected")
	} else if !strings.Contains(err.Error(), "signature") {
		t.Fatalf("expected a signature error, got: %v", err)
	}
}

// TestDoSigned_SendsVersionHeader asserts the advisory X-Sentinel-Version
// header carries the version passed to NewClient on every signed request.
func TestDoSigned_SendsVersionHeader(t *testing.T) {
	sentinelSeed := bytes.Repeat([]byte{0x11}, ed25519.SeedSize)
	sentinelPriv := ed25519.NewKeyFromSeed(sentinelSeed)
	sentinelPub := sentinelPriv.Public().(ed25519.PublicKey)

	serverSeed := bytes.Repeat([]byte{0x22}, ed25519.SeedSize)
	serverPriv := ed25519.NewKeyFromSeed(serverSeed)
	signingPub := serverPriv.Public().(ed25519.PublicKey)

	const sentinelKeyID = "sentinel-1"
	const signingKeyID = "server-1"

	var gotVersion string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotVersion = r.Header.Get("X-Sentinel-Version")

		if err := httpsig.VerifyRequest(r, sentinelPub, sentinelKeyID, nil); err != nil {
			t.Errorf("server verify request: %v", err)
			http.Error(w, err.Error(), http.StatusUnauthorized)
			return
		}
		details, err := httpsig.RequestDetails(r)
		if err != nil || details.Nonce == "" {
			t.Errorf("server parse signature-input: %v", err)
			http.Error(w, "no nonce", http.StatusBadRequest)
			return
		}

		respBody, err := json.Marshal(TasksResponse{})
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		digest, si, sg := httpsig.SignResponse(http.StatusOK, respBody, details.Nonce, serverPriv, signingKeyID)
		w.Header().Set("Content-Digest", digest)
		w.Header().Set("Signature-Input", si)
		w.Header().Set("Signature", sg)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		if _, err := w.Write(respBody); err != nil {
			t.Errorf("server write: %v", err)
		}
	}))
	defer srv.Close()

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	c := NewClient(srv.URL, "sentinel-id-1", sentinelKeyID, sentinelPriv, signingPub, signingKeyID, "1.2.3", logger)

	if _, err := c.GetTasks(context.Background()); err != nil {
		t.Fatalf("GetTasks: %v", err)
	}
	if gotVersion != "1.2.3" {
		t.Errorf("expected X-Sentinel-Version %q, got %q", "1.2.3", gotVersion)
	}
}

// TestRegister_StatusInErrorDiscriminates4xx5xx asserts Register surfaces the
// numeric status in its error, so the caller's retry logic (retry 5xx, give up
// on 4xx) can key on it.
func TestRegister_StatusInErrorDiscriminates4xx5xx(t *testing.T) {
	cases := []struct {
		name   string
		status int
		want   string
	}{
		{"client error not retryable", http.StatusForbidden, "status 403"},
		{"server error retryable", http.StatusBadGateway, "status 502"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				http.Error(w, "nope", tc.status)
			}))
			defer srv.Close()

			_, err := Register(context.Background(), srv.URL, "enroll-token", RegisterRequest{})
			if err == nil {
				t.Fatalf("expected an error for status %d", tc.status)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("expected error to contain %q, got: %v", tc.want, err)
			}
		})
	}
}

// TestUpdateCredentials_RotatesKeyID asserts UpdateCredentials swaps the keyid
// stamped on the next request's Signature-Input.
func TestUpdateCredentials_RotatesKeyID(t *testing.T) {
	oldPriv := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x11}, ed25519.SeedSize))
	newPriv := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x33}, ed25519.SeedSize))

	serverPriv := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x22}, ed25519.SeedSize))
	signingPub := serverPriv.Public().(ed25519.PublicKey)

	const newKeyID = "sentinel-rotated"
	const signingKeyID = "server-1"

	var seenKeyID string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		details, err := httpsig.RequestDetails(r)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		seenKeyID = details.KeyID

		respBody, _ := json.Marshal(TasksResponse{})
		digest, si, sg := httpsig.SignResponse(http.StatusOK, respBody, details.Nonce, serverPriv, signingKeyID)
		w.Header().Set("Content-Digest", digest)
		w.Header().Set("Signature-Input", si)
		w.Header().Set("Signature", sg)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(respBody)
	}))
	defer srv.Close()

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	c := NewClient(srv.URL, "sentinel-id-1", "sentinel-old", oldPriv, signingPub, signingKeyID, "1.2.3", logger)

	c.UpdateCredentials(newKeyID, newPriv)

	if _, err := c.GetTasks(context.Background()); err != nil {
		t.Fatalf("GetTasks after rotation: %v", err)
	}
	if seenKeyID != newKeyID {
		t.Fatalf("expected keyid %q on the wire after rotation, got %q", newKeyID, seenKeyID)
	}
}
