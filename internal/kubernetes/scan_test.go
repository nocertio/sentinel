package kubernetes

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type fakeAPI struct {
	secrets    []secret
	configMaps map[string]configMap // "ns/name"
	complete   bool
}

func TestSweepForbiddenMeshReadIsIncomplete(t *testing.T) {
	for _, kind := range []string{"secrets", "configmaps"} {
		t.Run(kind, func(t *testing.T) {
			srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/api/v1/secrets" {
					_, _ = w.Write([]byte(`{"items":[],"metadata":{}}`))
				} else if strings.Contains(r.URL.Path, "/"+kind+"/") {
					w.WriteHeader(http.StatusForbidden)
				} else {
					w.WriteHeader(http.StatusNotFound)
				}
			}))
			defer srv.Close()
			orig := newClusterAPI
			newClusterAPI = func(ClusterSpec) (clusterAPI, error) { return newTestClient(t, srv), nil }
			t.Cleanup(func() { newClusterAPI = orig })
			res := NewScanner(slog.Default()).Sweep(context.Background(), []ClusterSpec{{Name: "test"}}, SweepOptions{})
			require.Len(t, res.Sweeps, 1)
			require.False(t, res.Sweeps[0].Complete)
			require.Equal(t, "forbidden", res.Sweeps[0].Reason)
		})
	}
}

func (f *fakeAPI) listTLSSecrets(_ context.Context, namespace string, visit func(*secret) bool) (bool, error) {
	for i := range f.secrets {
		if namespace != "" && f.secrets[i].Metadata.Namespace != namespace {
			continue
		}
		if !visit(&f.secrets[i]) {
			return false, nil
		}
	}
	return f.complete, nil
}

func (f *fakeAPI) getSecret(_ context.Context, ns, name string) (*secret, bool, error) {
	for _, s := range f.secrets {
		if s.Metadata.Namespace == ns && s.Metadata.Name == name {
			return &s, true, nil
		}
	}
	return nil, false, nil
}

func (f *fakeAPI) getConfigMap(_ context.Context, ns, name string) (*configMap, bool, error) {
	cm, ok := f.configMaps[ns+"/"+name]
	if !ok {
		return nil, false, nil
	}
	return &cm, true, nil
}

func withFakeAPI(t *testing.T, f *fakeAPI) {
	t.Helper()
	orig := newClusterAPI
	newClusterAPI = func(ClusterSpec) (clusterAPI, error) { return f, nil }
	t.Cleanup(func() { newClusterAPI = orig })
}

// fpOf is the fingerprint of the shaped cert a given label extracts to,
// matching pemCert(label) -> shapedCert(label).
func fpOf(label string) string {
	sum := sha256.Sum256(shapedCert(label))
	return hex.EncodeToString(sum[:])
}

func TestSweepAggregatesAndDeduplicates(t *testing.T) {
	withFakeAPI(t, &fakeAPI{complete: true, secrets: []secret{
		{Metadata: objectMeta{Namespace: "default", Name: "web-tls", Annotations: map[string]string{
			"cert-manager.io/certificate-name": "web",
		}}, Type: tlsSecretType, Data: map[string][]byte{"tls.crt": pemCert("LEAF"), "tls.key": []byte("SECRET")}},
		// Same cert duplicated in another namespace: one Certificate, two observations.
		{Metadata: objectMeta{Namespace: "web", Name: "copy-tls"}, Type: tlsSecretType,
			Data: map[string][]byte{"tls.crt": pemCert("LEAF")}},
	}})

	res := NewScanner(slog.Default()).Sweep(context.Background(),
		[]ClusterSpec{{Name: "prod"}}, SweepOptions{})

	require.Len(t, res.Certificates, 1)
	assert.Equal(t, fpOf("LEAF"), res.Certificates[0].FingerprintSHA256)
	require.Len(t, res.Observations, 2)
	byNS := map[string]int{}
	for _, o := range res.Observations {
		byNS[o.Namespace]++
		assert.Equal(t, "prod", o.Cluster)
		assert.Equal(t, "secret", o.SourceKind)
		assert.Equal(t, "tls.crt", o.DataKey)
	}
	assert.Equal(t, map[string]int{"default": 1, "web": 1}, byNS)
	for _, o := range res.Observations {
		if o.Namespace == "default" {
			assert.Equal(t, "cert-manager", o.ManagedBy)
		}
	}
	require.Len(t, res.Sweeps, 1)
	assert.True(t, res.Sweeps[0].Complete)
	assert.ElementsMatch(t, []string{
		"secret/default/web-tls/tls.crt",
		"secret/web/copy-tls/tls.crt",
	}, res.Sweeps[0].ObservedKeys)
}

func TestSweepReadsWellKnownMeshTargets(t *testing.T) {
	withFakeAPI(t, &fakeAPI{complete: true,
		secrets: []secret{{
			Metadata: objectMeta{Namespace: "istio-system", Name: "cacerts"},
			Type:     "Opaque",
			Data: map[string][]byte{
				"ca-cert.pem": pemCert("ISTIOCA"),
				"ca-key.pem":  []byte("PRIVATE"),
			},
		}},
		configMaps: map[string]configMap{"linkerd/linkerd-identity-trust-roots": {
			Metadata: objectMeta{Namespace: "linkerd", Name: "linkerd-identity-trust-roots"},
			Data:     map[string]string{"ca-bundle.crt": string(pemCert("ANCHOR"))},
		}},
	})

	res := NewScanner(slog.Default()).Sweep(context.Background(),
		[]ClusterSpec{{Name: "prod"}}, SweepOptions{})

	keys := res.Sweeps[0].ObservedKeys
	assert.Contains(t, keys, "secret/istio-system/cacerts/ca-cert.pem")
	assert.Contains(t, keys, "configmap/linkerd/linkerd-identity-trust-roots/ca-bundle.crt")
	for _, c := range res.Certificates {
		assert.NotContains(t, string(c.DER), "PRIVATE")
	}
}

func TestSweepDeduplicatesMeshTargetAlsoTLSTyped(t *testing.T) {
	// linkerd-identity-issuer is on the mesh allowlist AND, in the tls-typed
	// install scheme, shows up in the kubernetes.io/tls list too. It must be
	// collected once: one observation and one ObservedKeys entry per location.
	withFakeAPI(t, &fakeAPI{complete: true, secrets: []secret{{
		Metadata: objectMeta{Namespace: "linkerd", Name: "linkerd-identity-issuer"},
		Type:     tlsSecretType,
		Data:     map[string][]byte{"tls.crt": pemCert("ISSUER"), "tls.key": []byte("SECRET")},
	}}})

	res := NewScanner(slog.Default()).Sweep(context.Background(),
		[]ClusterSpec{{Name: "prod"}}, SweepOptions{})

	require.Len(t, res.Certificates, 1)
	count := 0
	for _, o := range res.Observations {
		if o.Namespace == "linkerd" && o.SecretName == "linkerd-identity-issuer" && o.DataKey == "tls.crt" {
			count++
		}
	}
	assert.Equal(t, 1, count, "tls-typed mesh target must yield one observation, not one per pass")

	require.Len(t, res.Sweeps, 1)
	assert.True(t, res.Sweeps[0].Complete)
	assert.Equal(t, []string{"secret/linkerd/linkerd-identity-issuer/tls.crt"}, res.Sweeps[0].ObservedKeys)
}

func TestSweepNamespaceFilters(t *testing.T) {
	withFakeAPI(t, &fakeAPI{complete: true, secrets: []secret{
		{Metadata: objectMeta{Namespace: "keep", Name: "a"}, Type: tlsSecretType, Data: map[string][]byte{"tls.crt": pemCert("A")}},
		{Metadata: objectMeta{Namespace: "skip", Name: "b"}, Type: tlsSecretType, Data: map[string][]byte{"tls.crt": pemCert("B")}},
	}})
	res := NewScanner(slog.Default()).Sweep(context.Background(),
		[]ClusterSpec{{Name: "prod"}},
		SweepOptions{ExcludeNamespaces: []string{"skip"}})
	require.Len(t, res.Observations, 1)
	assert.Equal(t, "keep", res.Observations[0].Namespace)
}

func TestSweepSkipsNonRFC1123Names(t *testing.T) {
	// A name containing "/" could forge/collide a location key; skip it (warn),
	// keep collecting the well-formed object.
	withFakeAPI(t, &fakeAPI{complete: true, secrets: []secret{
		{Metadata: objectMeta{Namespace: "default", Name: "evil/../../x"}, Type: tlsSecretType, Data: map[string][]byte{"tls.crt": pemCert("EVIL")}},
		{Metadata: objectMeta{Namespace: "default", Name: "good-tls"}, Type: tlsSecretType, Data: map[string][]byte{"tls.crt": pemCert("GOOD")}},
	}})
	res := NewScanner(slog.Default()).Sweep(context.Background(),
		[]ClusterSpec{{Name: "prod"}}, SweepOptions{})
	require.Len(t, res.Observations, 1)
	assert.Equal(t, "good-tls", res.Observations[0].SecretName)
	require.Len(t, res.Certificates, 1)
	assert.Equal(t, fpOf("GOOD"), res.Certificates[0].FingerprintSHA256)
	for _, k := range res.Sweeps[0].ObservedKeys {
		assert.NotContains(t, k, "evil")
	}
}

func TestSweepIncompleteListNeverAuthorizesReconcile(t *testing.T) {
	withFakeAPI(t, &fakeAPI{complete: false})
	res := NewScanner(slog.Default()).Sweep(context.Background(),
		[]ClusterSpec{{Name: "prod"}}, SweepOptions{})
	require.Len(t, res.Sweeps, 1)
	assert.False(t, res.Sweeps[0].Complete)
}

func TestSweepBytesBudgetTruncates(t *testing.T) {
	// Many large distinct certs must not build a report over the backend's 5 MiB
	// body cap: the sweep truncates (Truncated, Complete=false, no reconcile on
	// a partial view) instead of losing the whole report to a 413. Each cert is
	// ~60 KiB (under maxDERBytes); 40 of them (~2.4 MiB raw) blow the 1.5 MiB
	// sweep byte budget.
	big := strings.Repeat("D", 60*1024)
	var secrets []secret
	for i := 0; i < 40; i++ {
		secrets = append(secrets, secret{
			Metadata: objectMeta{Namespace: "default", Name: fmt.Sprintf("tls-%03d", i)},
			Type:     tlsSecretType,
			Data:     map[string][]byte{"tls.crt": pemCert(fmt.Sprintf("%s-%03d", big, i))},
		})
	}
	withFakeAPI(t, &fakeAPI{complete: true, secrets: secrets})

	res := NewScanner(slog.Default()).Sweep(context.Background(),
		[]ClusterSpec{{Name: "prod"}, {Name: "prod2"}}, SweepOptions{})

	assert.True(t, res.Truncated)
	require.Len(t, res.Sweeps, 2)
	assert.False(t, res.Sweeps[0].Complete, "cluster that hit the byte budget must not reconcile")
	assert.False(t, res.Sweeps[1].Complete, "clusters after a truncation are unswept and must not reconcile")

	total := 0
	for _, c := range res.Certificates {
		total += len(c.DER)
	}
	assert.LessOrEqual(t, total, maxCertBytesPerSweep, "retained DER must stay within the sweep byte budget")
	assert.NotEmpty(t, res.Certificates, "some certs are collected before the budget trips")
}

// erringAPI fails every call with a fixed error, to exercise reason
// classification.
type erringAPI struct{ err error }

func (e *erringAPI) listTLSSecrets(context.Context, string, func(*secret) bool) (bool, error) {
	return false, e.err
}
func (e *erringAPI) getSecret(context.Context, string, string) (*secret, bool, error) {
	return nil, false, e.err
}
func (e *erringAPI) getConfigMap(context.Context, string, string) (*configMap, bool, error) {
	return nil, false, e.err
}

type fakeNetErr struct{}

func (fakeNetErr) Error() string   { return "dial tcp: connection refused" }
func (fakeNetErr) Timeout() bool   { return false }
func (fakeNetErr) Temporary() bool { return false }

func TestClassifyError(t *testing.T) {
	cases := map[string]struct {
		err  error
		want string
	}{
		"401":      {&statusError{code: 401}, "auth_failed"},
		"403":      {&statusError{code: 403}, "forbidden"},
		"500":      {&statusError{code: 500}, "internal"},
		"deadline": {context.DeadlineExceeded, "timeout"},
		"canceled": {context.Canceled, "timeout"},
		"net":      {fakeNetErr{}, "unreachable"},
		"wrapped":  {fmt.Errorf("list: %w", &statusError{code: 403}), "forbidden"},
		"other":    {fmt.Errorf("boom"), "internal"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			assert.Equal(t, tc.want, classifyError(tc.err))
		})
	}
}

func TestSweepReasons(t *testing.T) {
	t.Run("config error when the cluster client cannot be built", func(t *testing.T) {
		orig := newClusterAPI
		newClusterAPI = func(ClusterSpec) (clusterAPI, error) { return nil, fmt.Errorf("no token file") }
		t.Cleanup(func() { newClusterAPI = orig })

		res := NewScanner(slog.Default()).Sweep(context.Background(),
			[]ClusterSpec{{Name: "prod"}}, SweepOptions{})
		require.Len(t, res.Sweeps, 1)
		assert.False(t, res.Sweeps[0].Complete)
		assert.Equal(t, "config_error", res.Sweeps[0].Reason)
	})

	t.Run("forbidden list carries the RBAC reason, first failure wins", func(t *testing.T) {
		orig := newClusterAPI
		newClusterAPI = func(ClusterSpec) (clusterAPI, error) {
			return &erringAPI{err: &statusError{code: 403}}, nil
		}
		t.Cleanup(func() { newClusterAPI = orig })

		res := NewScanner(slog.Default()).Sweep(context.Background(),
			[]ClusterSpec{{Name: "prod"}}, SweepOptions{})
		require.Len(t, res.Sweeps, 1)
		assert.False(t, res.Sweeps[0].Complete)
		assert.Equal(t, "forbidden", res.Sweeps[0].Reason)
	})

	t.Run("a complete sweep carries no reason", func(t *testing.T) {
		withFakeAPI(t, &fakeAPI{complete: true, secrets: []secret{
			{Metadata: objectMeta{Namespace: "default", Name: "web-tls"}, Type: tlsSecretType,
				Data: map[string][]byte{"tls.crt": pemCert("LEAF")}},
		}})
		res := NewScanner(slog.Default()).Sweep(context.Background(),
			[]ClusterSpec{{Name: "prod"}}, SweepOptions{})
		require.Len(t, res.Sweeps, 1)
		assert.True(t, res.Sweeps[0].Complete)
		assert.Empty(t, res.Sweeps[0].Reason)
	})

	t.Run("a per-list truncation is reported as truncated, not an error", func(t *testing.T) {
		// listTLSSecrets returns ok=false (its 5000-secret cap) with no error and
		// too few certs/observations to trip the sweep-wide caps.
		withFakeAPI(t, &fakeAPI{complete: false, secrets: []secret{
			{Metadata: objectMeta{Namespace: "default", Name: "web-tls"}, Type: tlsSecretType,
				Data: map[string][]byte{"tls.crt": pemCert("LEAF")}},
		}})
		res := NewScanner(slog.Default()).Sweep(context.Background(),
			[]ClusterSpec{{Name: "prod"}}, SweepOptions{})
		require.Len(t, res.Sweeps, 1)
		assert.False(t, res.Sweeps[0].Complete)
		assert.Equal(t, "truncated", res.Sweeps[0].Reason)
	})

	t.Run("clusters after a sweep-wide cap are marked skipped", func(t *testing.T) {
		// 1001 distinct one-cert secrets overflow maxCertsPerSweep mid-cluster.
		var secrets []secret
		for i := 0; i < maxCertsPerSweep+1; i++ {
			secrets = append(secrets, secret{
				Metadata: objectMeta{Namespace: "default", Name: fmt.Sprintf("tls-%04d", i)},
				Type:     tlsSecretType,
				Data:     map[string][]byte{"tls.crt": pemCert(fmt.Sprintf("LEAF-%04d", i))},
			})
		}
		withFakeAPI(t, &fakeAPI{complete: true, secrets: secrets})
		res := NewScanner(slog.Default()).Sweep(context.Background(),
			[]ClusterSpec{{Name: "first"}, {Name: "second"}}, SweepOptions{})
		require.Len(t, res.Sweeps, 2)
		assert.False(t, res.Sweeps[0].Complete)
		assert.Equal(t, "truncated", res.Sweeps[0].Reason)
		assert.False(t, res.Sweeps[1].Complete)
		assert.Equal(t, "skipped", res.Sweeps[1].Reason)
		assert.True(t, res.Truncated)
	})
}

// revisitAPI visits the same Secret twice, simulating a 410 continue-token
// restart that re-streams already-seen Secrets.
type revisitAPI struct{ sec secret }

func (r *revisitAPI) listTLSSecrets(_ context.Context, _ string, visit func(*secret) bool) (bool, error) {
	visit(&r.sec)
	visit(&r.sec)
	return true, nil
}
func (r *revisitAPI) getSecret(context.Context, string, string) (*secret, bool, error) {
	return nil, false, nil
}
func (r *revisitAPI) getConfigMap(context.Context, string, string) (*configMap, bool, error) {
	return nil, false, nil
}

// TestSweepDedupsRevisitedSecret pins the 410-restart idempotency: a Secret
// streamed twice must yield exactly one certificate and one observation, since
// collect() dedups by fingerprint and location key.
func TestSweepDedupsRevisitedSecret(t *testing.T) {
	sec := secret{
		Metadata: objectMeta{Namespace: "default", Name: "web-tls"},
		Type:     tlsSecretType,
		Data:     map[string][]byte{"tls.crt": pemCert("LEAF")},
	}
	orig := newClusterAPI
	newClusterAPI = func(ClusterSpec) (clusterAPI, error) { return &revisitAPI{sec: sec}, nil }
	t.Cleanup(func() { newClusterAPI = orig })

	res := NewScanner(slog.Default()).Sweep(context.Background(),
		[]ClusterSpec{{Name: "prod"}}, SweepOptions{})
	assert.Len(t, res.Certificates, 1, "a re-visited Secret must not duplicate certs")
	assert.Len(t, res.Observations, 1, "a re-visited Secret must not duplicate observations")
}
