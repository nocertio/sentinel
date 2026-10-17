package sentinel

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	commonsentinel "nocert.io/common/pkg/api/sentinel"
	"nocert.io/common/pkg/httpsig"
	"nocert.io/sentinel/internal/config"
	"nocert.io/sentinel/internal/filesystem"
	"nocert.io/sentinel/internal/keystore"
	"nocert.io/sentinel/internal/kubernetes"
	"nocert.io/sentinel/internal/scanner"
	"nocert.io/sentinel/internal/transport"
)

func boolPtr(v bool) *bool { return &v }

// reportRecorder is a test backend that captures every /report body. By
// default it replies 500 (unsigned), so callers can exercise failed batches.
// With accept=true it emits the signed 200 response required by the transport.
type reportRecorder struct {
	statuses []string
	reports  []transport.ReportRequest
	accept   bool
	// onReport, if set, is called (in the request goroutine) for each decoded
	// report - lets a test react to a specific report without polling.
	onReport func(transport.ReportRequest)
}

const testBackendSigningKeyID = "sig-test"

func testBackendSigningKey() ed25519.PrivateKey {
	return ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x5a}, ed25519.SeedSize))
}

func (r *reportRecorder) server(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		body, _ := io.ReadAll(req.Body)
		var rr transport.ReportRequest
		if err := json.Unmarshal(body, &rr); err == nil {
			r.statuses = append(r.statuses, rr.Status)
			r.reports = append(r.reports, rr)
			if r.onReport != nil {
				r.onReport(rr)
			}
		}
		if r.accept {
			details, err := httpsig.RequestDetails(req)
			if err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			respBody := []byte(`{"accepted":true}`)
			digest, sigInput, sig := httpsig.SignResponse(
				http.StatusOK, respBody, details.Nonce,
				testBackendSigningKey(), testBackendSigningKeyID,
			)
			w.Header().Set("Content-Digest", digest)
			w.Header().Set("Signature-Input", sigInput)
			w.Header().Set("Signature", sig)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(respBody)
			return
		}
		w.WriteHeader(http.StatusInternalServerError)
	}))
	t.Cleanup(srv.Close)
	return srv
}

// newTestSentinelWithClient builds a sentinel wired to a real signed transport
// client pointed at srv, so report paths are exercised end-to-end (minus the
// backend response-signature, which the recorder doesn't produce).
func newTestSentinelWithClient(t *testing.T, srv *httptest.Server, allowScan bool) *Sentinel {
	t.Helper()
	// Report retry is exercised in the transport package. Run single-attempt here
	// so a delivery-failure recorder (unsigned 500) stays one report and adds no
	// real backoff delay to these scan/report-logic tests.
	t.Cleanup(transport.SetReportRetryForTest(1, time.Millisecond))
	privB64, pubB64, err := keystore.GenerateKeyPair()
	require.NoError(t, err)
	kf := &keystore.KeyFile{PrivateKey: privB64, PublicKey: pubB64, SigningPublicKey: pubB64}
	priv, err := kf.PrivateKeyBytes()
	require.NoError(t, err)
	serverPub := testBackendSigningKey().Public().(ed25519.PublicKey)

	s := newTestSentinel(allowScan)
	s.cfg.ServerURL = srv.URL
	s.client = transport.NewClient(srv.URL, "sentinel-test", "key-test", priv, serverPub, testBackendSigningKeyID, "1.2.3", slog.New(slog.NewTextHandler(io.Discard, nil)))
	return s
}

func newTestSentinel(allowScan bool) *Sentinel {
	return &Sentinel{
		logger: slog.Default(),
		cfg: &config.Config{
			ServerURL:           "https://example.com",
			AllowNetworkScan:    boolPtr(allowScan),
			AllowFilesystemScan: boolPtr(allowScan),
		},
	}
}

// TestEnrollOnce_ReplacesExistingKey guards the `--enroll-token` UX: an explicit
// token must (re-)register and overwrite any existing key, so re-pointing a host
// at a new enrollment is one command - never a silent no-op that keeps a stale
// (e.g. backend-deleted) identity polling with a 401.
func TestEnrollOnce_ReplacesExistingKey(t *testing.T) {
	var calls int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls++
		_ = json.NewEncoder(w).Encode(commonsentinel.RegisterResponse{
			SentinelID:   fmt.Sprintf("sentinel-%d", calls),
			KeyID:        fmt.Sprintf("key-%d", calls),
			KeyExpiresAt: time.Now().Add(24 * time.Hour),
		})
	}))
	defer srv.Close()

	dir := t.TempDir()
	cfg := &config.Config{
		ServerURL: srv.URL,
		KeyFile:   filepath.Join(dir, "sentinel-key.json"),
	}
	s := New(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)))
	ctx := context.Background()

	// First enrollment writes the key.
	require.NoError(t, s.EnrollOnce(ctx, "token-1"))
	kf, err := s.store.Load()
	require.NoError(t, err)
	assert.Equal(t, "sentinel-1", kf.SentinelID)

	// Re-enrolling with a new token MUST replace the existing identity.
	require.NoError(t, s.EnrollOnce(ctx, "token-2"))
	kf, err = s.store.Load()
	require.NoError(t, err)
	assert.Equal(t, "sentinel-2", kf.SentinelID, "re-enroll should overwrite the existing key")

	// An empty token is rejected, never treated as a silent reuse.
	assert.ErrorIs(t, s.EnrollOnce(ctx, ""), ErrTokenRequired)
}

// TestPollFailureEscalatesCredentialRejection covers the one poll failure an
// operator has to act on. A rejected identity never heals on its own, so it has
// to leave the WARN stream every poll shares and say what to do about it.
func TestPollFailureEscalatesCredentialRejection(t *testing.T) {
	var logs bytes.Buffer
	s := newTestSentinel(true)
	s.logger = slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug}))

	rejected := fmt.Errorf("get tasks: %w: unknown sentinel", transport.ErrCredentialsRejected)

	for range credentialAlertAfter - 1 {
		s.trackPollResult(rejected, "poll failed")
	}
	require.NotContains(t, logs.String(), "level=ERROR", "a couple of rejections may just be a rotation racing a restart")

	s.trackPollResult(rejected, "poll failed")
	firstAlert := logs.String()
	assert.Contains(t, firstAlert, "level=ERROR")
	assert.Contains(t, firstAlert, "unknown sentinel", "the server reason has to reach the operator")
	assert.Contains(t, firstAlert, "--enroll-token", "the alert is only useful if it carries the fix")

	// Between two alerts the loop stays quiet-ish rather than raising an error
	// every 30 seconds for as long as the host is broken.
	logs.Reset()
	for range credentialAlertRepeat - 1 {
		s.trackPollResult(rejected, "poll failed")
	}
	assert.NotContains(t, logs.String(), "level=ERROR")
	s.trackPollResult(rejected, "poll failed")
	assert.Contains(t, logs.String(), "level=ERROR", "a still-rejected sentinel must alert again periodically")

	// Only a poll that goes through clears the count. An unrelated failure in
	// between must not, or a host behind a flaky proxy would never reach the
	// threshold and would sit on the same repeated warning it does today.
	logs.Reset()
	s.trackPollResult(nil, "poll failed")
	for range credentialAlertAfter - 1 {
		s.trackPollResult(rejected, "poll failed")
		s.trackPollResult(errors.New("connection refused"), "poll failed")
	}
	assert.NotContains(t, logs.String(), "level=ERROR")
	s.trackPollResult(rejected, "poll failed")
	assert.Contains(t, logs.String(), "level=ERROR", "interleaved network errors must not starve the alert")
}

// TestApplyConfigCachesUnderLock verifies the freshest SentinelConfig
// is cached under the agent mutex and exposed to scan handlers.
func TestApplyConfigCachesUnderLock(t *testing.T) {
	s := newTestSentinel(true)

	cfg := transport.SentinelConfig{
		IPRanges:                   []string{"10.0.0.0/24"},
		Ports:                      []int{443, 8443},
		ScanNetworkIntervalSeconds: 3600,
		ScanEnabled:                true,
	}
	s.applyConfig(cfg)

	s.mu.RLock()
	defer s.mu.RUnlock()

	assert.True(t, s.hasConfig)
	assert.Equal(t, []string{"10.0.0.0/24"}, s.scanConfig.IPRanges)
	assert.Equal(t, []int{443, 8443}, s.scanConfig.Ports)
	assert.Equal(t, 3600, s.scanConfig.ScanNetworkIntervalSeconds)
}

// TestDispatchTaskUnknownTypeIsDropped verifies an unknown task type is
// silently dropped (no failure report - the backend already considers it
// queued; we just don't speak that dialect).
func TestDispatchTaskUnknownTypeIsDropped(t *testing.T) {
	s := newTestSentinel(true)

	task := transport.TaskResponse{
		ID:   "task-unknown",
		Type: "config_update", // legacy type - must be ignored
	}

	err := s.dispatchTask(context.Background(), task)
	assert.NoError(t, err)
}

// TestRunNetworkScanRejectsWhenDisabled verifies that with network scanning
// disabled locally, the task is refused WITHOUT contacting the backend.
// A locally-refused task gets no report: the backend deletes tasks on claim
// and does nothing with a "failed" report. newTestSentinel leaves a nil
// client, so any report attempt would panic - NotPanics proves none was made.
func TestRunNetworkScanRejectsWhenDisabled(t *testing.T) {
	s := newTestSentinel(false)

	task := transport.TaskResponse{
		ID:   "task-1",
		Type: commonsentinel.TaskTypeNetworkScan,
	}

	assert.NotPanics(t, func() {
		assert.NoError(t, s.runNetworkScan(context.Background(), task))
	})
}

// TestRunFilesystemScanRejectsWhenDisabled verifies the same for a
// filesystem_scan refused locally: no report is sent (nil client →
// NotPanics proves no backend call was made).
func TestRunFilesystemScanRejectsWhenDisabled(t *testing.T) {
	s := newTestSentinel(false)

	task := transport.TaskResponse{
		ID:   "task-fs",
		Type: commonsentinel.TaskTypeFilesystemScan,
	}

	assert.NotPanics(t, func() {
		assert.NoError(t, s.runFilesystemScan(context.Background(), task))
	})
}

// TestRunNetworkScanWithFqdnPayload verifies the payload {fqdn, ports} parses
// cleanly and reaches the FQDN branch. The scanning guard is pre-set so the
// scan coalesces, which makes triggerHostnameScan report Failed - we assert on
// that report rather than on a recovered panic.
func TestRunNetworkScanWithFqdnPayload(t *testing.T) {
	rec := &reportRecorder{}
	s := newTestSentinelWithClient(t, rec.server(t), true)
	s.applyConfig(transport.SentinelConfig{
		IPRanges:    []string{"10.0.0.0/24"},
		Ports:       []int{443},
		ScanEnabled: true,
	})

	// Pre-acquire the scanning guard so triggerHostnameScan coalesces.
	s.scanning.Store(true)

	payload, err := json.Marshal(map[string]any{
		"fqdn":  "example.com",
		"ports": []int{443, 8443},
	})
	require.NoError(t, err)

	task := transport.TaskResponse{
		ID:      "task-fqdn",
		Type:    commonsentinel.TaskTypeNetworkScan,
		Payload: payload,
	}

	require.NoError(t, s.runNetworkScan(context.Background(), task))
	require.Equal(t, []string{commonsentinel.ReportStatusFailed}, rec.statuses)
}

// TestRunNetworkScanFqdnEmptyPortsReportsFailed verifies that an FQDN task
// resolving to zero ports (no per-task ports, empty cached config) reports
// Failed instead of running an empty scan that acks Completed while consuming
// the scan guard.
func TestRunNetworkScanFqdnEmptyPortsReportsFailed(t *testing.T) {
	rec := &reportRecorder{}
	s := newTestSentinelWithClient(t, rec.server(t), true)
	s.applyConfig(transport.SentinelConfig{ScanEnabled: true}) // no ports

	payload, err := json.Marshal(map[string]any{"fqdn": "example.com"})
	require.NoError(t, err)

	task := transport.TaskResponse{
		ID:      "task-fqdn-noports",
		Type:    commonsentinel.TaskTypeNetworkScan,
		Payload: payload,
	}

	require.NoError(t, s.runNetworkScan(context.Background(), task))
	require.Equal(t, []string{commonsentinel.ReportStatusFailed}, rec.statuses)
	// The scan guard must NOT have been consumed by a phantom scan.
	assert.False(t, s.scanning.Load())
}

// TestRunNetworkScanWithDeepEnumPayload verifies that a payload carrying
// deep_enum=true parses cleanly and reaches the FQDN dispatch path
// (alongside the existing fqdn/ports fields). The actual enum call is
// covered at the scanner level; here we only assert the wire field
// flows from JSON through to the trigger function without a parse error.
func TestRunNetworkScanWithDeepEnumPayload(t *testing.T) {
	rec := &reportRecorder{}
	s := newTestSentinelWithClient(t, rec.server(t), true)
	s.applyConfig(transport.SentinelConfig{
		IPRanges:    []string{"10.0.0.0/24"},
		Ports:       []int{443},
		ScanEnabled: true,
	})

	// Pre-acquire the scanning guard so triggerHostnameScan coalesces.
	s.scanning.Store(true)

	payload, err := json.Marshal(map[string]any{
		"fqdn":      "example.com",
		"ports":     []int{443},
		"deep_enum": true,
	})
	require.NoError(t, err)

	task := transport.TaskResponse{
		ID:      "task-deep-enum",
		Type:    commonsentinel.TaskTypeNetworkScan,
		Payload: payload,
	}

	require.NoError(t, s.runNetworkScan(context.Background(), task))
	require.Equal(t, []string{commonsentinel.ReportStatusFailed}, rec.statuses)
}

// startTargetedScanTLSServer starts a real TLS 1.2-minimum listener on
// 127.0.0.1 (mirrors internal/scanner's startTLS12EnumServer - test helpers
// don't cross package boundaries, so this is a second, smaller copy) and
// returns its port. MinVersion 1.2 lets a real cipher enumeration against it
// find legacy suites instead of racing TLS 1.3-only rejection on every
// version probed.
func startTargetedScanTLSServer(t *testing.T) int {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "svc.internal"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}},
		MinVersion:   tls.VersionTLS12,
	})
	require.NoError(t, err)
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			_ = c.(*tls.Conn).Handshake()
			_ = c.Close()
		}
	}()
	_, portStr, err := net.SplitHostPort(ln.Addr().String())
	require.NoError(t, err)
	port, err := strconv.Atoi(portStr)
	require.NoError(t, err)
	return port
}

// TestRunNetworkScanWithTargetsPayload verifies that a payload carrying an
// explicit targets[] list is probed exactly (ip, port, sni) - bypassing the
// fqdn/CIDR branches entirely - with deep enum always on. This exercises the
// real scanner (unlike the other payload tests, which pre-acquire the
// scanning guard so the trigger short-circuits): s.scanner must be set, and
// the scan must actually run against a live listener to prove the
// (ip, port, sni) reached the wire and came back with enum evidence.
func TestRunNetworkScanWithTargetsPayload(t *testing.T) {
	port := startTargetedScanTLSServer(t)

	rec := &reportRecorder{accept: true}
	s := newTestSentinelWithClient(t, rec.server(t), true)
	s.scanner = scanner.New(slog.New(slog.NewTextHandler(io.Discard, nil)))

	payload, err := json.Marshal(map[string]any{
		"targets": []map[string]any{
			{"ip": "127.0.0.1", "port": port, "sni": "svc.internal"},
		},
	})
	require.NoError(t, err)

	task := transport.TaskResponse{
		ID:      "task-targets",
		Type:    commonsentinel.TaskTypeNetworkScan,
		Payload: payload,
	}

	require.NoError(t, s.runNetworkScan(context.Background(), task))

	var found *commonsentinel.SentinelNetworkObservation
	for i := range rec.reports {
		for j := range rec.reports[i].NetworkObservations {
			o := &rec.reports[i].NetworkObservations[j]
			if o.IP == "127.0.0.1" && o.Port == port {
				found = o
			}
		}
	}
	require.NotNil(t, found, "expected an observation for the explicit target")
	require.NotNil(t, found.TLS)
	assert.True(t, found.TLS.DeepEnumAttempted)
	assert.NotEmpty(t, found.TLS.SupportedProtocols)
}

// TestRunNetworkScanEmptyPayloadFullSweep verifies that an empty payload
// resolves to the full CIDR sweep using the cached SentinelConfig. The scanning
// guard is pre-set so the sweep coalesces and reports Failed.
func TestRunNetworkScanEmptyPayloadFullSweep(t *testing.T) {
	rec := &reportRecorder{}
	s := newTestSentinelWithClient(t, rec.server(t), true)
	s.applyConfig(transport.SentinelConfig{
		IPRanges:    []string{"10.0.0.0/24"},
		Ports:       []int{443},
		ScanEnabled: true,
	})

	// Pre-acquire the scanning guard so triggerScan coalesces.
	s.scanning.Store(true)

	task := transport.TaskResponse{
		ID:      "task-sweep",
		Type:    commonsentinel.TaskTypeNetworkScan,
		Payload: nil,
	}

	require.NoError(t, s.runNetworkScan(context.Background(), task))
	require.Equal(t, []string{commonsentinel.ReportStatusFailed}, rec.statuses)
}

// TestScanningGuard verifies that triggerScan respects the scanning
// atomic bool and short-circuits when a scan is already in flight.
func TestScanningGuard(t *testing.T) {
	s := newTestSentinel(true)
	s.scanning.Store(true)

	// With the guard set and no taskID, triggerScan returns early without
	// reporting - and without a real client. Should not panic.
	assert.NotPanics(t, func() {
		s.triggerScan(context.Background(), "", []string{"10.0.0.0/24"}, []int{443})
	})
}

// TestScanDisabledByConfig verifies that triggerScan refuses to run when
// network scanning is disabled by the local config flag.
func TestScanDisabledByConfig(t *testing.T) {
	s := newTestSentinel(false)

	assert.NotPanics(t, func() {
		s.triggerScan(context.Background(), "", []string{"10.0.0.0/24"}, []int{443})
	})
}

func TestBuildFilesystemReport(t *testing.T) {
	res := &filesystem.FSScanResult{
		Complete: true,
		Certificates: []commonsentinel.Certificate{
			{FingerprintSHA256: "fp1", DER: []byte("d1")},
			{FingerprintSHA256: "fp2", DER: []byte("d2")},
		},
		Observations: []commonsentinel.SentinelFilesystemObservation{
			{FingerprintSHA256: "fp1", FilePaths: []string{"/a.pem"}},
			{FingerprintSHA256: "fp2", FilePaths: []string{"/b.pem"}},
		},
	}
	r := buildFilesystemReport("task-1", res)
	if r.Status != commonsentinel.ReportStatusCompleted {
		t.Fatalf("status = %q, want completed", r.Status)
	}
	if !r.FilesystemScanComplete {
		t.Fatal("FilesystemScanComplete must be true")
	}
	if len(r.FilesystemFingerprints) != 2 || len(r.FilesystemObservations) != 2 {
		t.Fatalf("expected 2 fingerprints / 2 observations, got %d / %d",
			len(r.FilesystemFingerprints), len(r.FilesystemObservations))
	}
}

func TestBuildFilesystemReportEmpty(t *testing.T) {
	// A complete sweep that found nothing still yields a completed report
	// so the backend reconciles the machine to empty.
	r := buildFilesystemReport("task-1", &filesystem.FSScanResult{Complete: true})
	if r.Status != commonsentinel.ReportStatusCompleted || !r.FilesystemScanComplete {
		t.Fatalf("empty sweep report wrong: %+v", r)
	}
}

func TestLocalScanCompletionReport(t *testing.T) {
	keys := map[string]commonsentinel.LocalListenerKey{
		"b": {IP: "::1", Port: 8443},
		"a": {IP: "127.0.0.1", Port: 443},
	}
	report := localScanCompletionReport("task-local", keys, true)
	require.True(t, report.LocalScanComplete)
	require.Equal(t, []commonsentinel.LocalListenerKey{
		{IP: "127.0.0.1", Port: 443},
		{IP: "::1", Port: 8443},
	}, report.LocalListenerKeys)

	empty := localScanCompletionReport("task-empty", nil, true)
	require.True(t, empty.LocalScanComplete)
	require.Empty(t, empty.LocalListenerKeys)

	incomplete := localScanCompletionReport("task-failed", keys, false)
	require.False(t, incomplete.LocalScanComplete)
	require.Empty(t, incomplete.LocalListenerKeys)
}

func TestLocalScanBatchFailureDisablesReconciliation(t *testing.T) {
	rec := &reportRecorder{}
	s := newTestSentinelWithClient(t, rec.server(t), true)
	results := make(chan scanner.ProbeOutput, 1)
	results <- scanner.ProbeOutput{
		IP:    "127.0.0.1",
		Port:  443,
		Chain: [][]byte{{0x30, 0x01}},
	}
	close(results)

	s.collectAndPushNetwork(context.Background(), results, "task-local", &scanner.ScanMeta{
		ScanID: "scan-local", StartedAt: time.Now(),
	}, true, true)

	require.Len(t, rec.reports, 2)
	require.Equal(t, commonsentinel.ReportStatusPartial, rec.reports[0].Status)
	require.Equal(t, commonsentinel.ReportStatusCompleted, rec.reports[1].Status)
	require.False(t, rec.reports[1].LocalScanComplete,
		"a failed observation batch must never authorize deletion")
	require.Empty(t, rec.reports[1].LocalListenerKeys)
}

func TestLocalScanAcceptedBatchAuthorizesReconciliation(t *testing.T) {
	rec := &reportRecorder{accept: true}
	s := newTestSentinelWithClient(t, rec.server(t), true)
	results := make(chan scanner.ProbeOutput, 1)
	results <- scanner.ProbeOutput{
		IP:    "127.0.0.1",
		Port:  443,
		Chain: [][]byte{{0x30, 0x01}},
	}
	close(results)

	s.collectAndPushNetwork(context.Background(), results, "task-local", &scanner.ScanMeta{
		ScanID: "scan-local", StartedAt: time.Now(),
	}, true, true)

	require.Len(t, rec.reports, 2)
	require.Equal(t, commonsentinel.ReportStatusPartial, rec.reports[0].Status)
	require.True(t, rec.reports[1].LocalScanComplete)
	require.Equal(t, []commonsentinel.LocalListenerKey{{IP: "127.0.0.1", Port: 443}},
		rec.reports[1].LocalListenerKeys)
}

func TestLocalScanEmptySweepAuthorizesEmptyReconciliation(t *testing.T) {
	rec := &reportRecorder{accept: true}
	s := newTestSentinelWithClient(t, rec.server(t), true)
	results := make(chan scanner.ProbeOutput)
	close(results)

	s.collectAndPushNetwork(context.Background(), results, "task-local-empty", &scanner.ScanMeta{
		ScanID: "scan-local-empty", StartedAt: time.Now(),
	}, true, true)

	require.Len(t, rec.reports, 1)
	require.Equal(t, commonsentinel.ReportStatusCompleted, rec.reports[0].Status)
	require.True(t, rec.reports[0].LocalScanComplete)
	require.Empty(t, rec.reports[0].LocalListenerKeys)
}

func TestLocalScanIncompleteEnumerationDisablesReconciliation(t *testing.T) {
	rec := &reportRecorder{accept: true}
	s := newTestSentinelWithClient(t, rec.server(t), true)
	results := make(chan scanner.ProbeOutput)
	close(results)

	s.collectAndPushNetwork(context.Background(), results, "task-local-incomplete", &scanner.ScanMeta{
		ScanID: "scan-local-incomplete", StartedAt: time.Now(),
	}, true, false)

	require.Len(t, rec.reports, 1)
	require.Equal(t, commonsentinel.ReportStatusCompleted, rec.reports[0].Status)
	require.False(t, rec.reports[0].LocalScanComplete)
	require.Empty(t, rec.reports[0].LocalListenerKeys)
}

func TestBuildKubernetesReport(t *testing.T) {
	res := &kubernetes.SweepResult{
		Certificates: []commonsentinel.Certificate{{FingerprintSHA256: strings.Repeat("ab", 32), DER: []byte{0x30}}},
		Observations: []commonsentinel.SentinelKubernetesObservation{{
			Cluster: "prod", Namespace: "default", SecretName: "web-tls",
			SourceKind: "secret", DataKey: "tls.crt",
			ObservedChainFingerprints: []string{strings.Repeat("ab", 32)},
		}},
		Sweeps: []commonsentinel.KubernetesSweepResult{{Cluster: "prod", Complete: true, ObservedKeys: []string{"secret/default/web-tls/tls.crt"}}},
	}
	r := buildKubernetesReport("task-1", res)
	assert.Equal(t, "task-1", r.TaskID)
	assert.Equal(t, commonsentinel.ReportStatusCompleted, r.Status)
	assert.Len(t, r.KubernetesObservations, 1)
	assert.Len(t, r.KubernetesSweeps, 1)
	assert.Len(t, r.Certificates, 1)
	// The k8s discriminator rides ONLY on kubernetes reports; the backend
	// keys the per-sentinel cluster status on it.
	if assert.NotNil(t, r.KubernetesClustersConfigured) {
		assert.Equal(t, 1, *r.KubernetesClustersConfigured)
	}
}

// TestKubernetesScanRefusedLocallyProducesNoReport mirrors the network/fs
// refuse pattern: with the kill switch off, dispatchTask returns nil and the
// fake backend receives no /report call at all (the task was already deleted
// from the pool on claim, so a "failed" report is a no-op there).
func TestKubernetesScanRefusedLocallyProducesNoReport(t *testing.T) {
	rec := &reportRecorder{}
	s := newTestSentinelWithClient(t, rec.server(t), true)
	s.cfg.AllowKubernetesScan = boolPtr(false)

	task := transport.TaskResponse{
		ID:   "task-k8s-refused",
		Type: commonsentinel.TaskTypeKubernetesScan,
	}

	require.NoError(t, s.dispatchTask(context.Background(), task))
	assert.Empty(t, rec.statuses, "a locally-refused kubernetes_scan must send no report")
}

// TestKubernetesScanWithoutClustersReportsCompleted verifies that when the
// backend switch is on but this host has no clusters configured, the sweep is
// acked with a single bare completed report (no observations, no sweeps).
func TestKubernetesScanWithoutClustersReportsCompleted(t *testing.T) {
	rec := &reportRecorder{}
	s := newTestSentinelWithClient(t, rec.server(t), true)
	s.cfg.AllowKubernetesScan = boolPtr(true)
	// No KubernetesClusters configured on this host.

	task := transport.TaskResponse{
		ID:   "task-k8s-empty",
		Type: commonsentinel.TaskTypeKubernetesScan,
	}

	require.NoError(t, s.dispatchTask(context.Background(), task))
	require.Equal(t, []string{commonsentinel.ReportStatusCompleted}, rec.statuses)
}

func TestKubernetesScanReportsExtractionTruncation(t *testing.T) {
	for _, count := range []int{16, 17} {
		t.Run(strconv.Itoa(count), func(t *testing.T) {
			var chain []byte
			api := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/api/v1/secrets" {
					w.WriteHeader(http.StatusNotFound)
					return
				}
				_ = json.NewEncoder(w).Encode(map[string]any{"items": []any{map[string]any{
					"metadata": map[string]string{"namespace": "default", "name": "web-tls"},
					"type":     "kubernetes.io/tls",
					"data":     map[string][]byte{"tls.crt": chain, "tls.key": []byte("never reported")},
				}}})
			}))
			defer api.Close()
			certificate := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: api.Certificate().Raw})
			chain = bytes.Repeat(certificate, count)
			dir := t.TempDir()
			caFile, tokenFile := filepath.Join(dir, "ca.pem"), filepath.Join(dir, "token")
			require.NoError(t, os.WriteFile(caFile, certificate, 0o600))
			require.NoError(t, os.WriteFile(tokenFile, []byte("test-token"), 0o600))

			rec := &reportRecorder{accept: true}
			s := newTestSentinelWithClient(t, rec.server(t), true)
			s.cfg.AllowKubernetesScan = boolPtr(true)
			s.cfg.KubernetesClusters = []config.KubernetesCluster{{
				Name: "cluster", Server: api.URL, CAFile: caFile, TokenFile: tokenFile,
			}}
			s.kubeScanner = kubernetes.NewScanner(s.logger)
			require.NoError(t, s.runKubernetesScan(context.Background(), transport.TaskResponse{ID: "task-kubernetes", Type: commonsentinel.TaskTypeKubernetesScan}))

			require.Len(t, rec.reports, 1)
			report := rec.reports[0]
			assert.Equal(t, commonsentinel.ReportStatusCompleted, report.Status)
			require.Len(t, report.KubernetesSweeps, 1)
			sweep := report.KubernetesSweeps[0]
			assert.Equal(t, count == 16, sweep.Complete)
			if count > 16 {
				assert.Equal(t, commonsentinel.KubernetesReasonTruncated, sweep.Reason)
			} else {
				assert.Empty(t, sweep.Reason)
			}
			assert.Equal(t, []string{"secret/default/web-tls/tls.crt"}, sweep.ObservedKeys)
			require.Len(t, report.KubernetesObservations, 1)
			assert.Len(t, report.KubernetesObservations[0].ObservedChainFingerprints, 16)
			require.Len(t, report.Certificates, 1)
			assert.Equal(t, api.Certificate().Raw, report.Certificates[0].DER)
		})
	}
}

// TestRun_ServiceModeSelfEnrollsOnceThenReuses guards the idempotent
// service-mode self-enroll path: a token from config/env must register ONCE
// when no key exists, and must NOT re-register on subsequent startups (the
// existing key takes precedence over the token).
func TestRun_ServiceModeSelfEnrollsOnceThenReuses(t *testing.T) {
	var calls int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls++
		_ = json.NewEncoder(w).Encode(commonsentinel.RegisterResponse{
			SentinelID:   fmt.Sprintf("sentinel-%d", calls),
			KeyID:        fmt.Sprintf("key-%d", calls),
			KeyExpiresAt: time.Now().Add(24 * time.Hour),
		})
	}))
	defer srv.Close()

	dir := t.TempDir()
	cfg := &config.Config{
		ServerURL: srv.URL,
		KeyFile:   filepath.Join(dir, "sentinel-key.json"),
	}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	ctx := context.Background()

	// No key + token -> one /register call, key persisted.
	s := New(cfg, logger)
	kf, err := s.ensureRegistered(ctx, "service-token")
	require.NoError(t, err)
	assert.Equal(t, 1, calls, "first boot must register exactly once")
	assert.Equal(t, "sentinel-1", kf.SentinelID)

	// Second startup with same store path + token → key present, zero further /register calls.
	s2 := New(cfg, logger)
	kf2, err := s2.ensureRegistered(ctx, "service-token")
	require.NoError(t, err)
	assert.Equal(t, 1, calls, "already-enrolled host must NOT re-register")
	assert.Equal(t, "sentinel-1", kf2.SentinelID, "identity must be reused")
}

// TestNetworkScanHeartbeatDuringSilentSweep proves that a scan which produces
// no observations for longer than the batch interval still refreshes presence:
// the batch timer sends a bare partial report (heartbeat) instead of staying
// silent. Uses a short injected batchTimeout as simulated time.
func TestNetworkScanHeartbeatDuringSilentSweep(t *testing.T) {
	rec := &reportRecorder{accept: true}
	firstHeartbeat := make(chan struct{})
	var once sync.Once
	rec.onReport = func(rr transport.ReportRequest) {
		if rr.Status == commonsentinel.ReportStatusPartial &&
			len(rr.NetworkObservations) == 0 && len(rr.Certificates) == 0 {
			once.Do(func() { close(firstHeartbeat) })
		}
	}
	srv := rec.server(t)
	s := newTestSentinelWithClient(t, srv, true)
	s.batchTimeout = 20 * time.Millisecond

	ch := make(chan scanner.ProbeOutput)
	go func() {
		<-firstHeartbeat // end the sweep only once presence has been refreshed
		close(ch)
	}()

	meta := &scanner.ScanMeta{ScanID: "scan-heartbeat", StartedAt: time.Now()}
	s.collectAndPushNetwork(context.Background(), ch, "task-heartbeat", meta, false, false)

	var heartbeats, completed int
	for _, rr := range rec.reports {
		switch rr.Status {
		case commonsentinel.ReportStatusPartial:
			if len(rr.NetworkObservations) == 0 && len(rr.Certificates) == 0 {
				heartbeats++
			}
		case commonsentinel.ReportStatusCompleted:
			completed++
		}
	}
	assert.GreaterOrEqual(t, heartbeats, 1, "a silent sweep must emit at least one presence heartbeat")
	assert.Equal(t, 1, completed, "the scan still ends with exactly one completion report")
}
