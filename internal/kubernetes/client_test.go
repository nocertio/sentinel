package kubernetes

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newTestClient wires a clusterClient at a httptest TLS server, trusting its cert.
func newTestClient(t *testing.T, srv *httptest.Server) *clusterClient {
	t.Helper()
	c, err := newClusterClientForTest(srv.URL, srv.Client(), "test-token")
	require.NoError(t, err)
	return c
}

func TestListTLSSecretsPaginatedWithFieldSelector(t *testing.T) {
	var gotSelectors []string
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "Bearer test-token", r.Header.Get("Authorization"))
		assert.Equal(t, "/api/v1/secrets", r.URL.Path)
		gotSelectors = append(gotSelectors, r.URL.Query().Get("fieldSelector"))
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Query().Get("continue") == "" {
			_ = json.NewEncoder(w).Encode(map[string]any{
				"metadata": map[string]any{"continue": "page2"},
				"items": []map[string]any{{
					"metadata": map[string]any{"namespace": "default", "name": "a-tls"},
					"type":     "kubernetes.io/tls",
					"data":     map[string]string{"tls.crt": "QQ=="},
				}},
			})
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"metadata": map[string]any{},
			"items": []map[string]any{{
				"metadata": map[string]any{"namespace": "web", "name": "b-tls"},
				"type":     "kubernetes.io/tls",
				"data":     map[string]string{"tls.crt": "Qg=="},
			}},
		})
	}))
	defer srv.Close()

	secrets, complete, err := collectSecrets(newTestClient(t, srv), "")
	require.NoError(t, err)
	assert.True(t, complete)
	require.Len(t, secrets, 2)
	assert.Equal(t, "a-tls", secrets[0].Metadata.Name)
	assert.Equal(t, []byte("B"), secrets[1].Data["tls.crt"])
	for _, fs := range gotSelectors {
		assert.Equal(t, "type=kubernetes.io/tls", fs)
	}
}

// TestListTLSSecretsBoundsInfinitePagination pins the OOM/stall guard: an API
// server that hands out a fresh continue token forever must not loop or grow
// memory without bound. The list stops at maxSecretsPerList and reports
// complete=false so the caller never reconciles on the truncated view.
func TestListTLSSecretsBoundsInfinitePagination(t *testing.T) {
	var calls int
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		items := make([]map[string]any, listPageSize)
		for i := range items {
			items[i] = map[string]any{
				"metadata": map[string]any{"namespace": "default", "name": fmt.Sprintf("s-%d-%d", calls, i)},
				"type":     "kubernetes.io/tls",
				"data":     map[string]string{"tls.crt": "QQ=="},
			}
		}
		w.Header().Set("Content-Type", "application/json")
		// Always hand out a fresh continue token: an unbounded page stream.
		_ = json.NewEncoder(w).Encode(map[string]any{
			"metadata": map[string]any{"continue": fmt.Sprintf("page-%d", calls)},
			"items":    items,
		})
	}))
	defer srv.Close()

	secrets, complete, err := collectSecrets(newTestClient(t, srv), "")
	require.NoError(t, err)
	assert.False(t, complete, "a truncated list must never authorize reconciliation")
	assert.Len(t, secrets, maxSecretsPerList)
	assert.LessOrEqual(t, calls, maxSecretsPerList/listPageSize+1, "pagination must terminate at the cap")
}

func TestListTLSSecretsNamespaceScopedPath(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/api/v1/namespaces/web/secrets", r.URL.Path)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"metadata": map[string]any{}, "items": []any{}})
	}))
	defer srv.Close()
	_, complete, err := collectSecrets(newTestClient(t, srv), "web")
	require.NoError(t, err)
	assert.True(t, complete)
}

// collectSecrets drains listTLSSecrets into a slice for assertions.
func collectSecrets(c *clusterClient, namespace string) ([]secret, bool, error) {
	var out []secret
	complete, err := c.listTLSSecrets(context.Background(), namespace, func(s *secret) bool {
		out = append(out, *s)
		return true
	})
	return out, complete, err
}

func TestGetSecretDistinguishesNotFoundFromForbidden(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v1/namespaces/istio-system/secrets/cacerts" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.WriteHeader(http.StatusForbidden)
	}))
	defer srv.Close()
	c := newTestClient(t, srv)
	_, found, err := c.getSecret(context.Background(), "istio-system", "cacerts")
	require.NoError(t, err)
	assert.False(t, found)
	_, found, err = c.getSecret(context.Background(), "linkerd", "linkerd-identity-issuer")
	var se *statusError
	require.ErrorAs(t, err, &se)
	assert.Equal(t, http.StatusForbidden, se.code)
	assert.False(t, found)
}

func TestListRestartsOnceOn410Gone(t *testing.T) {
	calls := 0
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		w.Header().Set("Content-Type", "application/json")
		if calls == 2 { // second page of first attempt: expired continue token
			w.WriteHeader(http.StatusGone)
			return
		}
		if calls == 1 {
			_ = json.NewEncoder(w).Encode(map[string]any{"metadata": map[string]any{"continue": "expired"}, "items": []any{}})
			return
		}
		// restarted list completes in one page
		_ = json.NewEncoder(w).Encode(map[string]any{"metadata": map[string]any{}, "items": []any{}})
	}))
	defer srv.Close()
	_, complete, err := collectSecrets(newTestClient(t, srv), "")
	require.NoError(t, err)
	assert.True(t, complete)
	assert.Equal(t, 3, calls)
}

// TestNewFromRESTConfigDoesNotFollowRedirects exercises the PROD constructor
// (newFromRESTConfig, trusting only the test server's CA) rather than the
// test-only shortcut, and pins the anti-replay guard: a 302 is NOT followed, so
// the Bearer token is never resent to the redirect target. The API server never
// legitimately 302s a GET, so the redirect surfaces as a statusError and the
// client issues exactly one request.
func TestNewFromRESTConfigDoesNotFollowRedirects(t *testing.T) {
	var calls int
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		w.Header().Set("Location", "https://evil.example/steal")
		w.WriteHeader(http.StatusFound)
	}))
	defer srv.Close()

	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw})
	c, err := newFromRESTConfig(&restConfig{server: srv.URL, caPEM: caPEM, token: "test-token"})
	require.NoError(t, err)

	err = c.getJSON(context.Background(), "/api/v1/secrets", &secretList{})
	var se *statusError
	require.ErrorAs(t, err, &se)
	assert.Equal(t, http.StatusFound, se.code)
	assert.Equal(t, 1, calls, "client must not follow the redirect (Bearer replay guard)")
}

// TestListTLSSecretsStreamsPerPage proves the connector processes each page as
// it arrives rather than buffering the whole list: the page-1 Secret is handed
// to visit BEFORE page 2 is ever requested. listTLSSecrets is synchronous, so
// the handler and the visitor interleave in one goroutine without a data race.
func TestListTLSSecretsStreamsPerPage(t *testing.T) {
	page2Requested := false
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Query().Get("continue") == "" {
			_ = json.NewEncoder(w).Encode(map[string]any{
				"metadata": map[string]any{"continue": "p2"},
				"items": []map[string]any{{
					"metadata": map[string]any{"namespace": "default", "name": "p1-tls"},
					"type":     "kubernetes.io/tls",
					"data":     map[string]string{"tls.crt": "QQ=="},
				}},
			})
			return
		}
		page2Requested = true
		_ = json.NewEncoder(w).Encode(map[string]any{
			"metadata": map[string]any{},
			"items": []map[string]any{{
				"metadata": map[string]any{"namespace": "default", "name": "p2-tls"},
				"type":     "kubernetes.io/tls",
				"data":     map[string]string{"tls.crt": "Qg=="},
			}},
		})
	}))
	defer srv.Close()

	var order []string
	complete, err := newTestClient(t, srv).listTLSSecrets(context.Background(), "", func(s *secret) bool {
		if s.Metadata.Name == "p1-tls" && page2Requested {
			t.Error("page 2 was fetched before the page-1 Secret was processed (not streaming)")
		}
		order = append(order, s.Metadata.Name)
		return true
	})
	require.NoError(t, err)
	assert.True(t, complete)
	assert.Equal(t, []string{"p1-tls", "p2-tls"}, order)
}
