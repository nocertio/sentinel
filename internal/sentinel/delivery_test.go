package sentinel

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	api "nocert.io/common/pkg/api/sentinel"
	"nocert.io/common/pkg/httpsig"
	"nocert.io/common/pkg/tlsprobe"
	"nocert.io/sentinel/internal/scanner"
	"nocert.io/sentinel/internal/transport"
)

// Use the real signed HTTP client, including its four attempts, with short
// delays. No test contacts a scan target or backend outside this process.
func deliverySentinel(t *testing.T, handler http.HandlerFunc) *Sentinel {
	t.Helper()
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x35}, ed25519.SeedSize))
	var mu sync.Mutex
	nonces := map[string]bool{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Error(err)
			w.WriteHeader(400)
			return
		}
		if r.Header.Get("Content-Digest") != httpsig.ContentDigest(body) {
			t.Error("invalid request digest")
		}
		if err := httpsig.VerifyRequest(r, key.Public().(ed25519.PublicKey), "key", nil); err != nil {
			t.Error(err)
		}
		details, err := httpsig.RequestDetails(r)
		if err != nil {
			t.Error(err)
			w.WriteHeader(400)
			return
		}
		mu.Lock()
		if nonces[details.Nonce] {
			t.Error("retry reused a signature nonce")
		}
		nonces[details.Nonce] = true
		mu.Unlock()
		r.Body = io.NopCloser(bytes.NewReader(body))
		handler(w, r)
	}))
	t.Cleanup(server.Close)
	t.Cleanup(transport.SetReportRetryForTest(4, time.Millisecond))
	s := newTestSentinel(true)
	s.logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	s.cfg.PollingInterval = 10 * time.Millisecond
	s.client = transport.NewClient(server.URL, "agent", "key", key, testBackendSigningKey().Public().(ed25519.PublicKey), testBackendSigningKeyID, "test", s.logger)
	return s
}

func deliveryReply(t *testing.T, w http.ResponseWriter, r *http.Request, value any) {
	t.Helper()
	body, err := json.Marshal(value)
	if err != nil {
		t.Error(err)
		w.WriteHeader(500)
		return
	}
	details, err := httpsig.RequestDetails(r)
	if err != nil {
		t.Error(err)
		w.WriteHeader(400)
		return
	}
	digest, input, signature := httpsig.SignResponse(200, body, details.Nonce, testBackendSigningKey(), testBackendSigningKeyID)
	w.Header().Set("Content-Digest", digest)
	w.Header().Set("Signature-Input", input)
	w.Header().Set("Signature", signature)
	_, _ = w.Write(body)
}

func TestTargetedDeliveryRetainsBatchesAndCompletion(t *testing.T) {
	var mu sync.Mutex
	var reports []transport.ReportRequest
	var firstBody []byte
	partial, complete := 0, 0
	s := deliverySentinel(t, func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		body, _ := io.ReadAll(r.Body)
		var report transport.ReportRequest
		if err := json.Unmarshal(body, &report); err != nil {
			t.Error(err)
		}
		reports = append(reports, report)
		if report.Status == api.ReportStatusPartial {
			partial++
			if partial == 1 {
				firstBody = body
			}
			if partial <= 5 && !bytes.Equal(firstBody, body) {
				t.Error("retry changed the pending batch")
			}
			if partial <= 4 {
				w.WriteHeader(503)
				return
			}
		} else {
			complete++
			if partial != 6 {
				t.Error("completion preceded accepted data batches")
			}
			if complete <= 4 {
				w.WriteHeader(503)
				return
			}
		}
		deliveryReply(t, w, r, map[string]bool{"accepted": true})
	})
	outputs := make(chan scanner.ProbeOutput, 51)
	for i := range 51 {
		outputs <- scanner.ProbeOutput{IP: "192.0.2.1", Port: 443 + i, Chain: [][]byte{{0x30, byte(i)}, {0x30, 0xff}}}
	}
	close(outputs)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	require.True(t, s.collectAndPushNetwork(ctx, outputs, "targeted", &scanner.ScanMeta{StartedAt: time.Now()}, false, false))
	mu.Lock()
	defer mu.Unlock()
	require.Equal(t, 6, partial)
	require.Equal(t, 5, complete)
	require.Len(t, reports[4].NetworkObservations, 50)
	require.Len(t, reports[5].NetworkObservations, 1)
	for _, report := range []transport.ReportRequest{reports[4], reports[5]} {
		certs := map[string]bool{}
		for _, c := range report.Certificates {
			require.False(t, certs[c.FingerprintSHA256])
			certs[c.FingerprintSHA256] = true
		}
		for _, o := range report.NetworkObservations {
			for _, fp := range o.ObservedChainFingerprints {
				require.True(t, certs[fp], "retried batch must be self-contained")
			}
		}
	}
}

func TestTargetedDeliveryDefersTasksWithoutRescanning(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	waiting, release, finished := make(chan struct{}), make(chan struct{}), make(chan struct{}, 1)
	defer func() {
		select {
		case <-release:
		default:
			close(release)
		}
	}()
	var polls, attempts, firstProbes, nextProbes atomic.Int32
	first, _ := json.Marshal(api.NetworkScanPayload{Fqdn: "first.invalid", Ports: []int{443}})
	next, _ := json.Marshal(api.NetworkScanPayload{Targets: []api.TargetSpec{{IP: "192.0.2.2", Port: 443}}})
	s := deliverySentinel(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			response := transport.TasksResponse{Config: transport.SentinelConfig{GentleScan: true}}
			if polls.Add(1) == 1 {
				response.Tasks = []transport.TaskResponse{
					{ID: "first", Type: api.TaskTypeNetworkScan, Payload: first},
					{ID: "next", Type: api.TaskTypeNetworkScan, Payload: next},
				}
			}
			deliveryReply(t, w, r, response)
			return
		}
		var report transport.ReportRequest
		if err := json.NewDecoder(r.Body).Decode(&report); err != nil {
			t.Error(err)
		}
		if report.TaskID == "first" && report.Status == api.ReportStatusPartial {
			n := attempts.Add(1)
			if n <= 4 {
				w.WriteHeader(503)
				return
			}
			if n == 5 {
				close(waiting)
				select {
				case <-release:
				case <-ctx.Done():
					return
				}
			}
		}
		deliveryReply(t, w, r, map[string]bool{"accepted": true})
		if report.TaskID == "next" && report.Status == api.ReportStatusCompleted {
			finished <- struct{}{}
		}
	})
	s.scanner = scanner.NewWithProber(s.logger, sweepProber(func(_ context.Context, host string, _ int) (*tlsprobe.Result, error) {
		if host == "first.invalid" {
			firstProbes.Add(1)
		} else {
			nextProbes.Add(1)
		}
		return &tlsprobe.Result{PeerIP: "192.0.2.1", RawChain: [][]byte{{0x30, 0x00}}}, nil
	}))
	done := make(chan struct{})
	go func() { defer close(done); _ = s.pollLoop(ctx) }()
	defer func() { cancel(); <-done }()
	select {
	case <-waiting:
	case <-ctx.Done():
		t.Fatal("pending batch was not retried")
	}
	require.Equal(t, int32(1), polls.Load(), "do not claim more tasks while a report is pending")
	require.Equal(t, int32(1), firstProbes.Load())
	require.Zero(t, nextProbes.Load(), "already-received task must wait")
	close(release)
	select {
	case <-finished:
	case <-ctx.Done():
		t.Fatal("queued task did not resume")
	}
	require.Equal(t, int32(1), firstProbes.Load(), "delivery retry must not probe again")
	require.Equal(t, int32(1), nextProbes.Load())
}

func TestTargetedDeliveryStopsOnPermanentFailure(t *testing.T) {
	for _, status := range []int{400, 401, 403, 413, 200} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			var calls atomic.Int32
			s := deliverySentinel(t, func(w http.ResponseWriter, _ *http.Request) {
				calls.Add(1)
				w.WriteHeader(status) // A success without a signature must also stop retries.
			})
			outputs := make(chan scanner.ProbeOutput, 1)
			outputs <- scanner.ProbeOutput{IP: "192.0.2.1", Port: 443, Chain: [][]byte{{0x30, 0x00}}}
			close(outputs)
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			require.False(t, s.collectAndPushNetwork(ctx, outputs, "targeted", &scanner.ScanMeta{}, false, false))
			require.NoError(t, ctx.Err())
			require.Equal(t, int32(1), calls.Load(), "no retry or completion after a permanent refusal")
		})
	}
}

func TestTargetedDeliveryCancellationDrainsScanner(t *testing.T) {
	for _, hostname := range []bool{false, true} {
		t.Run(map[bool]string{true: "hostname", false: "targets"}[hostname], func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			waiting := make(chan struct{}, 1)
			probing := make(chan struct{})
			var calls, active, completed atomic.Int32
			s := deliverySentinel(t, func(w http.ResponseWriter, r *http.Request) {
				var report transport.ReportRequest
				if err := json.NewDecoder(r.Body).Decode(&report); err != nil {
					t.Error(err)
				}
				if report.Status == api.ReportStatusCompleted {
					completed.Add(1)
				}
				if len(report.NetworkObservations) == 0 {
					deliveryReply(t, w, r, map[string]bool{"accepted": true})
					return
				}
				calls.Add(1)
				w.Header().Set("Retry-After", "3600")
				w.WriteHeader(503)
				waiting <- struct{}{}
			})
			s.batchTimeout = 30 * time.Millisecond
			s.scanner = scanner.NewWithProber(s.logger, sweepProber(func(ctx context.Context, _ string, port int) (*tlsprobe.Result, error) {
				active.Add(1)
				defer active.Add(-1)
				if port != 443 {
					close(probing)
					<-ctx.Done()
					return nil, ctx.Err()
				}
				return &tlsprobe.Result{PeerIP: "192.0.2.1", RawChain: [][]byte{{0x30, 0x00}}}, nil
			}))
			s.scanner.SetGentle(true)
			done := make(chan struct{})
			go func() {
				defer close(done)
				if hostname {
					s.triggerHostnameScan(ctx, "task", "fixture.invalid", []int{443, 444}, false)
				} else {
					s.triggerTargetedScan(ctx, "task", []api.TargetSpec{{IP: "192.0.2.1", Port: 443}, {IP: "192.0.2.1", Port: 444}})
				}
			}()
			select {
			case <-waiting:
			case <-ctx.Done():
				t.Error("report was not attempted")
			}
			select {
			case <-probing:
			case <-ctx.Done():
				t.Error("second probe did not start")
			}
			cancel()
			select {
			case <-done:
			case <-time.After(time.Second):
				t.Fatal("scanner did not stop")
			}
			require.Equal(t, int32(1), calls.Load())
			require.Zero(t, completed.Load())
			require.Zero(t, active.Load())
			require.False(t, s.scanning.Load())
		})
	}
}
