package sentinel

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	commonsentinel "nocert.io/common/pkg/api/sentinel"
	"nocert.io/common/pkg/httpsig"
	"nocert.io/common/pkg/tlsprobe"
	"nocert.io/sentinel/internal/scanner"
	"nocert.io/sentinel/internal/transport"
)

type sweepProber func(context.Context, string, int) (*tlsprobe.Result, error)

func (p sweepProber) Probe(ctx context.Context, host string, port int, _ time.Duration, _ string) (*tlsprobe.Result, error) {
	return p(ctx, host, port)
}

func sweepConfig() transport.SentinelConfig {
	return transport.SentinelConfig{IPRanges: []string{"192.0.2.0/26"}, Ports: []int{443}, ScanEnabled: true}
}

func queueTestSweep(t *testing.T, s *Sentinel, id string) {
	t.Helper()
	require.NoError(t, s.runNetworkScan(context.Background(), transport.TaskResponse{ID: id, Type: commonsentinel.TaskTypeNetworkScan}))
	require.NotNil(t, s.sweep)
}

func TestSweepResumeCoalesceAndComplete(t *testing.T) {
	rec := &reportRecorder{accept: true}
	srv := rec.server(t)
	path := filepath.Join(t.TempDir(), "key.json")
	var mu sync.Mutex
	seen := map[string]int{}
	prober := sweepProber(func(_ context.Context, host string, _ int) (*tlsprobe.Result, error) {
		mu.Lock()
		seen[host]++
		mu.Unlock()
		return &tlsprobe.Result{PeerIP: host, RawChain: [][]byte{{0x30, 0x00}}}, nil
	})
	makeSentinel := func() *Sentinel {
		s := newTestSentinelWithClient(t, srv, true)
		s.cfg.KeyFile = path
		s.scanner = scanner.NewWithProber(s.logger, prober)
		s.applyConfig(sweepConfig())
		return s
	}
	s := makeSentinel()
	queueTestSweep(t, s, "first")
	s.runSweepBatch(context.Background())
	require.Equal(t, 50, s.sweep.checkpoint.Next)
	require.NotContains(t, rec.statuses, commonsentinel.ReportStatusCompleted)
	queueTestSweep(t, s, "duplicate")
	require.Equal(t, 50, s.sweep.checkpoint.Next)
	require.Equal(t, "first", s.sweep.taskID)
	// Restart alone does not authorize a scan. A fresh backend task resumes it.
	resumed := makeSentinel()
	require.Nil(t, resumed.sweep)
	queueTestSweep(t, resumed, "after-restart")
	require.Equal(t, 50, resumed.sweep.checkpoint.Next)
	resumed.runSweepBatch(context.Background())
	require.Nil(t, resumed.sweep)
	require.Equal(t, commonsentinel.ReportStatusCompleted, rec.statuses[len(rec.statuses)-1])
	require.Len(t, seen, 62)
	for host, count := range seen {
		require.Equal(t, 1, count, host)
	}
	queueTestSweep(t, resumed, "next-cycle")
	require.Zero(t, resumed.sweep.checkpoint.Next)
}

func TestSweepFailedReportDoesNotAdvance(t *testing.T) {
	rec := &reportRecorder{}
	s := newTestSentinelWithClient(t, rec.server(t), true)
	s.cfg.KeyFile = filepath.Join(t.TempDir(), "key.json")
	cfg := sweepConfig()
	cfg.IPRanges = []string{"192.0.2.1/32"}
	s.applyConfig(cfg)
	s.scanner = scanner.NewWithProber(s.logger, sweepProber(func(_ context.Context, host string, _ int) (*tlsprobe.Result, error) {
		return &tlsprobe.Result{PeerIP: host, RawChain: [][]byte{{0x30, 0x00}}}, nil
	}))
	queueTestSweep(t, s, "retry")
	s.runSweepBatch(context.Background())
	require.Zero(t, s.sweep.checkpoint.Next)
	require.True(t, s.sweep.retryAfter.After(time.Now()))
	require.NotContains(t, rec.statuses, commonsentinel.ReportStatusCompleted)
	require.Zero(t, s.loadSweepCheckpoint(s.sweep.scope).Next)
	rec.accept = true
	s.runSweepBatch(context.Background())
	require.Nil(t, s.sweep)
	require.Equal(t, commonsentinel.ReportStatusCompleted, rec.statuses[len(rec.statuses)-1])
}

func TestSweepCancellationDrainsWorkersWithoutAdvancing(t *testing.T) {
	s := newTestSentinel(true)
	s.applyConfig(sweepConfig())
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var active atomic.Int32
	s.scanner = scanner.NewWithProber(s.logger, sweepProber(func(ctx context.Context, _ string, _ int) (*tlsprobe.Result, error) {
		active.Add(1)
		defer active.Add(-1)
		cancel()
		<-ctx.Done()
		return nil, ctx.Err()
	}))
	queueTestSweep(t, s, "cancel")
	s.runSweepBatch(ctx)
	require.Zero(t, s.sweep.checkpoint.Next)
	require.Zero(t, active.Load())
	require.False(t, s.scanning.Load())
}

func TestSweepConfigChangesAndLocalRefusal(t *testing.T) {
	s := newTestSentinel(true)
	s.cfg.KeyFile = filepath.Join(t.TempDir(), "key.json")
	cfg := sweepConfig()
	s.applyConfig(cfg)
	queueTestSweep(t, s, "first")
	s.sweep.checkpoint.Next = 12
	s.saveSweepCheckpoint(s.sweep.checkpoint)
	cfg.GentleScan = true
	s.applyConfig(cfg)
	require.Equal(t, 12, s.sweep.checkpoint.Next, "profile change must preserve progress")
	cfg.Ports = []int{8443}
	s.applyConfig(cfg)
	require.Nil(t, s.sweep, "scope change must wait for a fresh task")
	s.applyConfig(sweepConfig())
	queueTestSweep(t, s, "changed-back")
	require.Zero(t, s.sweep.checkpoint.Next)
	disabled := newTestSentinel(false)
	disabled.applyConfig(sweepConfig())
	require.NoError(t, disabled.runNetworkScan(context.Background(), transport.TaskResponse{ID: "refused"}))
	require.Nil(t, disabled.sweep)
}

func TestSweepCheckpointValidationAndAtomicReplacement(t *testing.T) {
	s := newTestSentinel(true)
	s.cfg.KeyFile = filepath.Join(t.TempDir(), "key.json")
	scope, err := scanner.NewScope([]string{"192.0.2.0/26"}, []int{443})
	require.NoError(t, err)
	cp := s.loadSweepCheckpoint(scope)
	cp.Next = 12
	require.NoError(t, writeSweepCheckpoint(s.checkpointPath(), cp))
	require.Equal(t, 12, s.loadSweepCheckpoint(scope).Next)
	stat, err := os.Stat(s.checkpointPath())
	require.NoError(t, err)
	if runtime.GOOS != "windows" {
		require.Equal(t, os.FileMode(0600), stat.Mode().Perm())
	}
	s.sentinelID = "new-identity"
	require.Zero(t, s.loadSweepCheckpoint(scope).Next)
	s.sentinelID = ""
	for _, data := range []string{
		`{`, strings.Repeat("x", 1025),
		`{"scope":"other","next":12}`,
		`{"scope":"` + cp.Scope + `","next":-1}`,
		`{"scope":"` + cp.Scope + `","next":62}`,
		`{"scope":"` + cp.Scope + `","next":99999999}`,
	} {
		require.NoError(t, os.WriteFile(s.checkpointPath(), []byte(data), 0600))
		require.Zero(t, s.loadSweepCheckpoint(scope).Next)
	}
	if runtime.GOOS != "windows" {
		target := filepath.Join(t.TempDir(), "unrelated")
		require.NoError(t, os.WriteFile(target, []byte("untouched"), 0600))
		require.NoError(t, os.Remove(s.checkpointPath()))
		require.NoError(t, os.Symlink(target, s.checkpointPath()))
		require.NoError(t, writeSweepCheckpoint(s.checkpointPath(), cp))
		data, err := os.ReadFile(target)
		require.NoError(t, err)
		require.Equal(t, "untouched", string(data))
	}
	require.NoError(t, os.Remove(s.checkpointPath()))
	require.NoError(t, os.Mkdir(s.checkpointPath(), 0700))
	require.Error(t, writeSweepCheckpoint(s.checkpointPath(), cp))
	entries, err := filepath.Glob(filepath.Join(filepath.Dir(s.checkpointPath()), ".scan-progress-*.tmp"))
	require.NoError(t, err)
	require.Empty(t, entries)
}

// Loopback integration: real TLS collection, signed HTTP reports and durable
// progress. No industrial endpoint or external service is contacted.
func TestSweepIntegrationTLSAndReports(t *testing.T) {
	port := startTargetedScanTLSServer(t)
	rec := &reportRecorder{accept: true}
	s := newTestSentinelWithClient(t, rec.server(t), true)
	s.cfg.KeyFile = filepath.Join(t.TempDir(), "key.json")
	s.applyConfig(transport.SentinelConfig{IPRanges: []string{"127.0.0.1/32", "127.0.0.1/32"}, Ports: []int{port, port}})
	queueTestSweep(t, s, "tls-sweep")
	s.runSweepBatch(context.Background())
	require.Nil(t, s.sweep)
	require.Equal(t, []string{commonsentinel.ReportStatusPartial, commonsentinel.ReportStatusCompleted}, rec.statuses)
	require.Len(t, rec.reports[0].Certificates, 1)
	require.Len(t, rec.reports[0].NetworkObservations, 1)
	require.Equal(t, port, rec.reports[0].NetworkObservations[0].Port)
	require.Equal(t, scanner.Fingerprint(rec.reports[0].Certificates[0].DER), rec.reports[0].NetworkObservations[0].ObservedChainFingerprints[0])
}

func TestSweepPollsAndDispatchesBetweenSilentBatches(t *testing.T) {
	var probes atomic.Int32
	var polls atomic.Int32
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	cfg := sweepConfig()
	var observedAtPoll int32
	targetedDone := make(chan struct{}, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var response any = map[string]bool{"accepted": true}
		if r.Method == http.MethodGet {
			n := polls.Add(1)
			resp := transport.TasksResponse{Config: cfg}
			switch n {
			case 1:
				resp.Tasks = []transport.TaskResponse{{ID: "sweep", Type: commonsentinel.TaskTypeNetworkScan}}
			case 2:
				observedAtPoll = probes.Load()
				// A fresh profile is applied before a targeted onboarding scan. Empty
				// ports in the payload inherit the existing configuration.
				resp.Config.GentleScan = true
				payload, _ := json.Marshal(commonsentinel.NetworkScanPayload{Fqdn: "onboarding.example"})
				resp.Tasks = []transport.TaskResponse{{ID: "targeted", Type: commonsentinel.TaskTypeNetworkScan, Payload: payload}}
			}
			response = resp
		} else {
			data, _ := io.ReadAll(r.Body)
			var report transport.ReportRequest
			_ = json.Unmarshal(data, &report)
			if report.TaskID == "targeted" && report.Status == commonsentinel.ReportStatusCompleted {
				targetedDone <- struct{}{}
			}
		}
		body, _ := json.Marshal(response)
		details, err := httpsig.RequestDetails(r)
		if err != nil {
			t.Error(err)
			w.WriteHeader(400)
			return
		}
		digest, input, sig := httpsig.SignResponse(200, body, details.Nonce, testBackendSigningKey(), testBackendSigningKeyID)
		w.Header().Set("Content-Digest", digest)
		w.Header().Set("Signature-Input", input)
		w.Header().Set("Signature", sig)
		_, _ = w.Write(body)
	}))
	defer srv.Close()
	s := newTestSentinelWithClient(t, srv, true)
	s.cfg.PollingInterval = 50 * time.Millisecond
	s.scanner = scanner.NewWithProber(s.logger, sweepProber(func(_ context.Context, host string, _ int) (*tlsprobe.Result, error) {
		if host != "onboarding.example" {
			probes.Add(1)
		}
		return nil, errors.New("no TLS")
	}))
	done := make(chan struct{})
	go func() { defer close(done); _ = s.pollLoop(ctx) }()
	select {
	case <-targetedDone:
		cancel()
	case <-ctx.Done():
		t.Error("targeted task was blocked by the sweep")
	}
	<-done
	require.GreaterOrEqual(t, polls.Load(), int32(2))
	require.Equal(t, int32(50), observedAtPoll, "poll must run between batches, not after all 62 hosts")
	require.True(t, s.scanConfig.GentleScan)
}

func TestSweepCompletionRetryDoesNotRepeatProbes(t *testing.T) {
	var probes atomic.Int32
	rec := &reportRecorder{}
	s := newTestSentinelWithClient(t, rec.server(t), true)
	cfg := sweepConfig()
	cfg.IPRanges = []string{"192.0.2.1/32"}
	s.applyConfig(cfg)
	s.scanner = scanner.NewWithProber(s.logger, sweepProber(func(context.Context, string, int) (*tlsprobe.Result, error) {
		probes.Add(1)
		return nil, errors.New("no TLS")
	}))
	queueTestSweep(t, s, "completion-retry")
	s.runSweepBatch(context.Background())
	require.Equal(t, 1, s.sweep.checkpoint.Next)
	require.Equal(t, int32(1), probes.Load())
	rec.accept = true
	s.runSweepBatch(context.Background())
	require.Nil(t, s.sweep)
	require.Equal(t, int32(1), probes.Load())
}
