package sentinel

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"nocert.io/sentinel/internal/config"
	"nocert.io/sentinel/internal/keystore"
	"nocert.io/sentinel/internal/transport"
)

func TestEnrollmentMachineIdentity(t *testing.T) {
	for _, tc := range []struct {
		name, storedID, currentID, token string
		status, calls                    int
		wantError, wantNew               bool
	}{
		{name: "same machine", storedID: "original", currentID: "original"},
		{name: "same machine with token", storedID: "original", currentID: "original", token: "test-token"},
		{name: "legacy key", currentID: "original"},
		{name: "host ID unavailable", storedID: "original"},
		{name: "clone with token", storedID: "original", currentID: "clone", token: "test-token", status: 200, calls: 1, wantNew: true},
		{name: "clone without token", storedID: "original", currentID: "clone", wantError: true},
		{name: "clone refused", storedID: "original", currentID: "clone", token: "test-token", status: 401, calls: 1, wantError: true},
		{name: "clone interrupted during outage", storedID: "original", currentID: "clone", token: "test-token", status: 503, calls: 1, wantError: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			var calls atomic.Int32
			var submittedKey string
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				if r.Header.Get("Authorization") != "Bearer test-token" {
					t.Error("missing enrollment token")
				}
				var request transport.RegisterRequest
				if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
					t.Error(err)
				}
				submittedKey = request.PublicKey
				w.WriteHeader(tc.status)
				_ = json.NewEncoder(w).Encode(transport.RegisterResponse{
					SentinelID: "new-sentinel", KeyID: "new-key", KeyExpiresAt: time.Now().Add(30 * 24 * time.Hour),
				})
				if tc.status == http.StatusServiceUnavailable {
					cancel()
				}
			}))
			defer server.Close()
			cfg := &config.Config{ServerURL: server.URL, KeyFile: filepath.Join(t.TempDir(), "key.json")}
			s := New(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)))
			s.machineID = tc.currentID
			private, public, err := keystore.GenerateKeyPair()
			require.NoError(t, err)
			old := &keystore.KeyFile{SentinelID: "original-sentinel", KeyID: "original-key", PrivateKey: private, PublicKey: public, MachineID: tc.storedID}
			require.NoError(t, s.store.Save(old))
			before, err := os.ReadFile(cfg.KeyFile)
			require.NoError(t, err)
			got, err := s.ensureRegistered(ctx, tc.token)
			if tc.wantError {
				require.Error(t, err)
				require.Nil(t, got, "a cloned identity must not be used after a failed enrollment")
				require.Empty(t, cfg.SentinelID)
			} else {
				require.NoError(t, err)
			}
			require.Equal(t, int32(tc.calls), calls.Load())
			if tc.wantNew {
				require.Equal(t, "new-sentinel", got.SentinelID)
				require.Equal(t, tc.currentID, got.MachineID)
				require.Equal(t, submittedKey, got.PublicKey)
				require.NotEqual(t, old.PublicKey, got.PublicKey)
				require.NotEqual(t, old.PrivateKey, got.PrivateKey)
				stored, err := s.store.Load()
				require.NoError(t, err)
				require.Equal(t, got, stored)
			} else {
				after, err := os.ReadFile(cfg.KeyFile)
				require.NoError(t, err)
				require.Equal(t, before, after, "existing identity must survive failure unchanged")
				if !tc.wantError {
					require.Equal(t, old, got)
				}
			}
		})
	}
}

func TestCleanClonesWithSameMachineID(t *testing.T) {
	_, signingKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer injected-token" || r.URL.Path != "/api/v1/sentinels/register" {
			t.Error("invalid enrollment request")
			w.WriteHeader(401)
			return
		}
		id := calls.Add(1)
		_ = json.NewEncoder(w).Encode(transport.RegisterResponse{
			SentinelID: fmt.Sprintf("clone-%d", id), KeyID: fmt.Sprintf("key-%d", id),
			KeyExpiresAt:     time.Now().Add(30 * 24 * time.Hour),
			SigningPublicKey: base64.StdEncoding.EncodeToString(signingKey.Public().(ed25519.PublicKey)), SigningKeyID: "server-1",
		})
	}))
	defer server.Close()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	var configs [2]*config.Config
	var keys [2]*keystore.KeyFile
	var errs [2]error
	var wg sync.WaitGroup
	for i := range configs {
		configs[i] = &config.Config{ServerURL: server.URL, KeyFile: filepath.Join(t.TempDir(), "sentinel-key.json")}
		s := New(configs[i], logger)
		_, err := s.ensureRegistered(t.Context(), "")
		require.ErrorIs(t, err, ErrTokenRequired)
		require.False(t, s.store.Exists(), "the template must stay unenrolled until a token is injected")
	}
	require.Zero(t, calls.Load())
	for i := range configs {
		wg.Go(func() {
			s := New(configs[i], logger)
			s.machineID = "copied-machine-id"
			keys[i], errs[i] = s.ensureRegistered(t.Context(), "injected-token")
		})
	}
	wg.Wait()
	for _, err := range errs {
		require.NoError(t, err)
	}
	require.NotEqual(t, keys[0].SentinelID, keys[1].SentinelID)
	require.NotEqual(t, keys[0].PublicKey, keys[1].PublicKey)
	require.NotEqual(t, keys[0].PrivateKey, keys[1].PrivateKey)
	for i, cfg := range configs {
		s := New(cfg, logger)
		s.machineID = "copied-machine-id"
		reused, err := s.ensureRegistered(t.Context(), "")
		require.NoError(t, err)
		require.Equal(t, keys[i], reused)
		info, err := os.Stat(cfg.KeyFile)
		require.NoError(t, err)
		require.Equal(t, os.FileMode(0600), info.Mode().Perm())
	}
	require.Equal(t, int32(2), calls.Load(), "restarts must preserve each clone's identity")
}
