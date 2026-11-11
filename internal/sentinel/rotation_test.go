package sentinel

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/stretchr/testify/require"
	"nocert.io/common/pkg/httpsig"
	"nocert.io/sentinel/internal/config"
	"nocert.io/sentinel/internal/keystore"
	"nocert.io/sentinel/internal/transport"
)

type rotationBackend struct {
	mu       sync.Mutex
	held     map[string]ed25519.PublicKey
	steps    []string
	arrivals []time.Time
	nonces   map[string]bool
	requests []string
}

func rotationAgent(t *testing.T, steps ...string) (*Sentinel, *keystore.KeyFile, *rotationBackend) {
	t.Helper()
	priv, pub, err := keystore.GenerateKeyPair()
	require.NoError(t, err)
	kf := &keystore.KeyFile{
		SentinelID: "fixture-agent", KeyID: "held-key", PrivateKey: priv, PublicKey: pub,
		KeyExpiresAt:     time.Now().Add(30 * time.Second).UTC(),
		SigningPublicKey: base64.StdEncoding.EncodeToString(testBackendSigningKey().Public().(ed25519.PublicKey)),
		SigningKeyID:     testBackendSigningKeyID,
	}
	key, err := kf.PrivateKeyBytes()
	require.NoError(t, err)
	b := &rotationBackend{held: map[string]ed25519.PublicKey{kf.KeyID: key.Public().(ed25519.PublicKey)}, steps: steps, nonces: map[string]bool{}}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b.mu.Lock()
		defer b.mu.Unlock()
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Error(err)
			w.WriteHeader(400)
			return
		}
		details, err := httpsig.RequestDetails(r)
		if err != nil || b.held[details.KeyID] == nil {
			t.Error("request did not use a held key")
			w.WriteHeader(401)
			return
		}
		if err := httpsig.VerifyRequest(r, b.held[details.KeyID], details.KeyID, nil); err != nil || r.Header.Get("Content-Digest") != httpsig.ContentDigest(body) {
			t.Error("invalid signed rotation request")
			w.WriteHeader(401)
			return
		}
		if b.nonces[details.Nonce] {
			t.Error("rotation reused a nonce")
		}
		b.nonces[details.Nonce] = true
		b.requests = append(b.requests, details.KeyID)
		b.arrivals = append(b.arrivals, time.Now())
		step := "ok"
		if len(b.steps) > 0 {
			step, b.steps = b.steps[0], b.steps[1:]
		}
		switch step {
		case "503", "429", "403":
			status := map[string]int{"503": 503, "429": 429, "403": 403}[step]
			if step == "429" {
				w.Header().Set("Retry-After", "1")
			}
			w.WriteHeader(status)
			_, _ = io.WriteString(w, "untrusted proxy diagnostic\n"+strings.Repeat("x", 4096))
			return
		}
		var payload transport.RotateRequest
		if err := json.Unmarshal(body, &payload); err != nil {
			t.Error(err)
			w.WriteHeader(400)
			return
		}
		publicKey, err := base64.StdEncoding.DecodeString(payload.NewPublicKey)
		if err != nil || len(publicKey) != ed25519.PublicKeySize {
			t.Error("invalid new public key")
			w.WriteHeader(400)
			return
		}
		keyID := fmt.Sprintf("rotated-%d", len(b.arrivals))
		// Preserve the authenticated key, as the backend does during grace.
		b.held = map[string]ed25519.PublicKey{details.KeyID: b.held[details.KeyID], keyID: publicKey}
		if step == "lost" {
			conn, _, err := w.(http.Hijacker).Hijack()
			if err != nil {
				t.Error(err)
				return
			}
			_ = conn.Close()
			return
		}
		reply, _ := json.Marshal(transport.RotateResponse{KeyID: keyID, KeyExpiresAt: time.Now().Add(30 * 24 * time.Hour)})
		digest, input, signature := httpsig.SignResponse(200, reply, details.Nonce, testBackendSigningKey(), testBackendSigningKeyID)
		w.Header().Set("Content-Digest", digest)
		w.Header().Set("Signature-Input", input)
		w.Header().Set("Signature", signature)
		if step == "invalid signature" {
			w.Header().Set("Signature", "invalid")
		}
		_, _ = w.Write(reply)
	}))
	t.Cleanup(srv.Close)
	s := New(&config.Config{ServerURL: srv.URL, KeyFile: filepath.Join(t.TempDir(), "key.json"), KeyRotationCheckInterval: 6 * time.Hour, KeyRotationMargin: 5 * 24 * time.Hour}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	require.NoError(t, s.store.Save(kf))
	s.client = transport.NewClient(srv.URL, kf.SentinelID, kf.KeyID, key, testBackendSigningKey().Public().(ed25519.PublicKey), testBackendSigningKeyID, "test", s.logger)
	return s, kf, b
}

type rotationLogs struct {
	mu           sync.Mutex
	bytes        bytes.Buffer
	success      chan struct{}
	warningTimes []time.Time
}

func (l *rotationLogs) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	n, err := l.bytes.Write(p)
	if bytes.Contains(p, []byte("key rotation failed")) {
		l.warningTimes = append(l.warningTimes, time.Now())
	}
	if bytes.Contains(p, []byte("key rotation successful")) {
		select {
		case l.success <- struct{}{}:
		default:
		}
	}
	return n, err
}

func TestKeyRotationAtStartupAndAfterTemporaryFailure(t *testing.T) {
	for _, steps := range [][]string{{}, {"503", "429", "lost", "lost"}} {
		t.Run(fmt.Sprint(steps), func(t *testing.T) {
			s, original, b := rotationAgent(t, steps...)
			if len(steps) != 0 {
				s.cfg.KeyRotationCheckInterval = 10 * time.Millisecond
			}
			logs := &rotationLogs{success: make(chan struct{}, 1)}
			s.logger = slog.New(slog.NewTextHandler(logs, nil))
			ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
			defer cancel()
			done := make(chan error, 1)
			go func() { done <- s.keyRotationLoop(ctx) }()
			select {
			case <-logs.success:
			case <-ctx.Done():
				t.Error("rotation did not finish before the deadline")
			}
			cancel()
			require.NoError(t, <-done)
			saved, err := s.store.Load()
			require.NoError(t, err)
			require.NotEqual(t, original.KeyID, saved.KeyID)
			require.NotEqual(t, original.PrivateKey, saved.PrivateKey)
			require.Equal(t, original.SentinelID, saved.SentinelID)
			require.Equal(t, original.SigningPublicKey, saved.SigningPublicKey)
			// A new request must use the identity that survived on disk.
			_, err = s.client.RotateKey(t.Context(), saved.PublicKey)
			require.NoError(t, err)
			b.mu.Lock()
			defer b.mu.Unlock()
			require.Equal(t, saved.KeyID, b.requests[len(b.requests)-1])
			if len(steps) != 0 {
				require.GreaterOrEqual(t, b.arrivals[2].Sub(b.arrivals[1]), time.Second)
			}
			logs.mu.Lock()
			defer logs.mu.Unlock()
			require.NotContains(t, logs.bytes.String(), "untrusted proxy diagnostic")
			require.NotContains(t, logs.bytes.String(), original.PrivateKey)
			require.LessOrEqual(t, strings.Count(logs.bytes.String(), "key rotation failed"), 1)
		})
	}
}

func TestRotationSaveFailureKeepsHeldIdentity(t *testing.T) {
	s, kf, b := rotationAgent(t)
	original := *kf
	store := s.store
	blocker := filepath.Join(t.TempDir(), "file")
	require.NoError(t, os.WriteFile(blocker, []byte("fixture"), 0600))
	s.store = keystore.NewStore(filepath.Join(blocker, "key.json"))
	retry, err := s.rotateKey(t.Context(), kf)
	require.Error(t, err)
	require.True(t, retry)
	require.Equal(t, original, *kf)
	saved, err := store.Load()
	require.NoError(t, err)
	require.Equal(t, original, *saved)
	s.store = store
	retry, err = s.rotateKey(t.Context(), kf)
	require.NoError(t, err)
	require.False(t, retry)
	require.NotEqual(t, original.KeyID, kf.KeyID)
	b.mu.Lock()
	defer b.mu.Unlock()
	require.Equal(t, []string{original.KeyID, original.KeyID}, b.requests)
}

func TestRejectedRotationKeepsIdentity(t *testing.T) {
	for _, step := range []string{"403", "invalid signature"} {
		t.Run(step, func(t *testing.T) {
			s, kf, _ := rotationAgent(t, step)
			original := *kf
			retry, err := s.rotateKey(t.Context(), kf)
			require.Error(t, err)
			require.False(t, retry)
			require.Equal(t, original, *kf)
			saved, err := s.store.Load()
			require.NoError(t, err)
			require.Equal(t, original, *saved)
		})
	}
}

func TestRotationCheckSchedule(t *testing.T) {
	for _, tc := range []struct {
		name                          string
		agents                        int
		interval, validity, low, high time.Duration
	}{
		{"fleet", 1000, 6 * time.Hour, 30 * 24 * time.Hour, 324 * time.Minute, 396 * time.Minute},
		{"before expiry", 1, 24 * time.Hour, 8 * time.Hour, 108 * time.Minute, 132 * time.Minute},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "key.json")
			synctest.Test(t, func(t *testing.T) {
				store := keystore.NewStore(path)
				require.NoError(t, store.Save(&keystore.KeyFile{KeyExpiresAt: time.Now().Add(tc.validity)}))
				logs := &rotationLogs{}
				ctx, cancel := context.WithCancel(t.Context())
				defer cancel()
				done := make(chan error, tc.agents)
				for range tc.agents {
					s := &Sentinel{cfg: &config.Config{KeyRotationCheckInterval: tc.interval, KeyRotationMargin: time.Hour}, store: store, logger: slog.New(slog.NewTextHandler(logs, nil))}
					go func() { done <- s.keyRotationLoop(ctx) }()
				}
				synctest.Wait()
				// One warning records each loop's next check without a network request.
				require.NoError(t, os.Remove(path))
				start := time.Now()
				time.Sleep(tc.high)
				synctest.Wait()
				cancel()
				for range tc.agents {
					require.NoError(t, <-done)
				}
				require.Len(t, logs.warningTimes, tc.agents)
				seen := map[time.Duration]bool{}
				for _, at := range logs.warningTimes {
					delay := at.Sub(start)
					require.GreaterOrEqual(t, delay, tc.low)
					require.LessOrEqual(t, delay, tc.high)
					seen[delay] = true
				}
				if tc.agents > 1 {
					require.Greater(t, len(seen), 1)
				}
			})
		})
	}
}

func TestRotationStartupDelay(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		for _, remaining := range []time.Duration{-time.Hour, 0, time.Second, time.Minute} {
			require.Zero(t, rotationStartupDelay(6*time.Hour, time.Now().Add(remaining)))
		}
		seen := map[time.Duration]bool{}
		for range 1000 {
			d := rotationStartupDelay(6*time.Hour, time.Now().Add(time.Hour))
			require.GreaterOrEqual(t, d, time.Duration(0))
			require.LessOrEqual(t, d, time.Minute)
			seen[d] = true
		}
		require.Greater(t, len(seen), 1)
		ctx, cancel := context.WithCancel(t.Context())
		time.AfterFunc(time.Second, cancel)
		start := time.Now()
		require.False(t, waitForRotation(ctx, 6*time.Hour))
		require.Equal(t, time.Second, time.Since(start))
	})
}
