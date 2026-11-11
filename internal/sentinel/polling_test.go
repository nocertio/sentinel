package sentinel

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"nocert.io/common/pkg/httpsig"
	"nocert.io/sentinel/internal/transport"
)

func TestRequestDelay(t *testing.T) {
	transient := errors.New("temporary failure")
	for _, tc := range []struct {
		name      string
		interval  time.Duration
		failures  int
		err       error
		low, high time.Duration
	}{
		{"normal", 30 * time.Second, 0, nil, 27 * time.Second, 33 * time.Second},
		{"recovery", 30 * time.Second, 64, nil, 27 * time.Second, 33 * time.Second},
		{"first failure", 30 * time.Second, 1, transient, 30 * time.Second, time.Minute},
		{"second failure", 30 * time.Second, 2, transient, time.Minute, 2 * time.Minute},
		{"long outage", 30 * time.Second, 64, transient, 150 * time.Second, 5 * time.Minute},
		{"configured slow polling", 10 * time.Minute, 64, transient, 10 * time.Minute, 10 * time.Minute},
		{"retry after", 30 * time.Second, 1, fmt.Errorf("poll: %w", &transport.HTTPError{StatusCode: 503, RetryAfter: 120 * time.Second}), 120 * time.Second, 121 * time.Second},
		{"longer own backoff", 30 * time.Second, 64, &transport.HTTPError{StatusCode: 429, RetryAfter: time.Second}, 150 * time.Second, 5 * time.Minute},
		{"maximum interval", time.Duration(math.MaxInt64), 0, nil, time.Duration(math.MaxInt64) - time.Duration(math.MaxInt64)/10, time.Duration(math.MaxInt64)},
		{"maximum failed interval", time.Duration(math.MaxInt64), 64, transient, time.Duration(math.MaxInt64), time.Duration(math.MaxInt64)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for range 50 {
				delay := requestDelay(tc.interval, tc.failures, tc.err)
				require.GreaterOrEqual(t, delay, tc.low)
				require.LessOrEqual(t, delay, tc.high)
			}
		})
	}
}

// Real loopback HTTP verifies that guidance survives transport errors all the
// way to polling, and that every attempt carries a fresh valid signature.
func TestPollingRecoversFromRateLimitAndUnavailable(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	agentKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x41}, ed25519.SeedSize))
	var calls atomic.Int32
	var arrivals []time.Time
	nonces := map[string]bool{}
	ready := make(chan struct{}, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := httpsig.VerifyRequest(r, agentKey.Public().(ed25519.PublicKey), "agent-key", nil); err != nil {
			t.Error(err)
			w.WriteHeader(401)
			return
		}
		details, err := httpsig.RequestDetails(r)
		if err != nil {
			t.Error(err)
			w.WriteHeader(400)
			return
		}
		if nonces[details.Nonce] {
			t.Error("reused polling nonce")
		}
		nonces[details.Nonce] = true
		arrivals = append(arrivals, time.Now())
		n := calls.Add(1)
		if n == 1 {
			conn, _, err := w.(http.Hijacker).Hijack()
			if err != nil {
				t.Error(err)
				return
			}
			_ = conn.Close()
			return
		}
		if n <= 3 {
			w.Header().Set("Retry-After", "1")
			if n == 2 {
				w.WriteHeader(429)
			} else {
				w.WriteHeader(503)
			}
			_, _ = w.Write([]byte("untrusted proxy diagnostics"))
			return
		}
		body, _ := json.Marshal(transport.TasksResponse{Config: transport.SentinelConfig{Ports: []int{443}}, Tasks: []transport.TaskResponse{}})
		digest, input, sig := httpsig.SignResponse(200, body, details.Nonce, testBackendSigningKey(), testBackendSigningKeyID)
		w.Header().Set("Content-Digest", digest)
		w.Header().Set("Signature-Input", input)
		w.Header().Set("Signature", sig)
		_, _ = w.Write(body)
		if n == 5 {
			ready <- struct{}{}
		}
	}))
	defer srv.Close()
	s := newTestSentinel(true)
	s.cfg.PollingInterval = 20 * time.Millisecond
	s.client = transport.NewClient(srv.URL, "agent", "agent-key", agentKey, testBackendSigningKey().Public().(ed25519.PublicKey), testBackendSigningKeyID, "test", s.logger)
	done := make(chan error, 1)
	go func() { done <- s.pollLoop(ctx) }()
	select {
	case <-ready:
		cancel()
	case <-ctx.Done():
		t.Error("polling did not recover")
	}
	require.NoError(t, <-done)
	require.Equal(t, int32(5), calls.Load())
	require.GreaterOrEqual(t, arrivals[2].Sub(arrivals[1]), time.Second)
	require.GreaterOrEqual(t, arrivals[3].Sub(arrivals[2]), time.Second)
	require.Equal(t, []int{443}, s.scanConfig.Ports)
	require.Zero(t, s.credentialFailures, "temporary outages are not credential rejections")
}

func TestPollingCancellationDuringRetryAfter(t *testing.T) {
	first := make(chan struct{}, 1)
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		w.Header().Set("Retry-After", "120")
		w.WriteHeader(503)
		first <- struct{}{}
	}))
	defer srv.Close()
	s := newTestSentinelWithClient(t, srv, true)
	s.cfg.PollingInterval = time.Millisecond
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- s.pollLoop(ctx) }()
	select {
	case <-first:
	case <-time.After(5 * time.Second):
		t.Fatal("initial poll was not sent")
	}
	cancel()
	select {
	case err := <-done:
		require.NoError(t, err)
	case <-time.After(time.Second):
		t.Fatal("shutdown waited for Retry-After")
	}
	require.Equal(t, int32(1), calls.Load())
}

func TestRegistrationRetriesStatusNotText(t *testing.T) {
	old := registrationRetryInterval
	registrationRetryInterval = time.Millisecond
	t.Cleanup(func() { registrationRetryInterval = old })
	for _, tc := range []struct {
		name      string
		statuses  []int
		wantCalls int
		wantError bool
	}{
		{"temporary", []int{429, 503, 200}, 3, false},
		{"bad token", []int{401}, 1, true},
		{"forbidden", []int{403}, 1, true},
		{"bad request", []int{400}, 1, true},
		{"persistent outage", []int{503}, maxRegisterRetries, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var calls atomic.Int32
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Header.Get("Authorization") != "Bearer test-token" {
					t.Error("missing enrollment token")
				}
				n := int(calls.Add(1)) - 1
				status := tc.statuses[min(n, len(tc.statuses)-1)]
				w.WriteHeader(status)
				if status == 200 {
					_, _ = w.Write([]byte(`{"sentinel_id":"registered"}`))
				} else {
					_, _ = w.Write([]byte("untrusted text: status 400, status 503"))
				}
			}))
			defer srv.Close()
			s := newTestSentinel(true)
			s.cfg.ServerURL = srv.URL
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			result, err := s.doRegister(ctx, "test-token", "test-public-key")
			if tc.wantError {
				require.Error(t, err)
				require.NotContains(t, err.Error(), "untrusted text")
			} else {
				require.NoError(t, err)
				require.Equal(t, "registered", result.SentinelID)
			}
			require.Equal(t, int32(tc.wantCalls), calls.Load())
		})
	}
}

func TestPollingWaitStartsAfterSlowFailure(t *testing.T) {
	const interval = 40 * time.Millisecond
	var calls atomic.Int32
	gaps := make(chan time.Duration, 1)
	var failedAt time.Time
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if calls.Add(1) == 1 {
			time.Sleep(3 * interval)
			failedAt = time.Now()
		} else {
			gaps <- time.Since(failedAt)
		}
		w.WriteHeader(503)
	}))
	defer srv.Close()
	s := newTestSentinelWithClient(t, srv, true)
	s.cfg.PollingInterval = interval
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- s.pollLoop(ctx) }()
	select {
	case gap := <-gaps:
		require.GreaterOrEqual(t, gap, interval)
	case <-time.After(5 * time.Second):
		t.Error("no retry after slow failure")
	}
	cancel()
	require.NoError(t, <-done)
}
