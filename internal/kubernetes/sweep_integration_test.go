//go:build integration_k8s

package kubernetes

import (
	"context"
	"log/slog"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestSweepAgainstRealCluster runs the connector against a real Kubernetes
// cluster. Opt-in: build with -tags integration_k8s and set K8S_IT_SERVER /
// K8S_IT_CA / K8S_IT_TOKEN (the server/ca_file/token_file trio). The cluster is
// expected to hold: kubernetes.io/tls Secrets demo/web-tls (annotated
// cert-manager.io/certificate-name) and demo/api-tls; demo2/web-copy-tls carrying
// the same certificate as demo/web-tls; an Opaque Secret demo/app-config that must
// be ignored; and the istio/linkerd objects on the mesh allowlist.
func TestSweepAgainstRealCluster(t *testing.T) {
	server, ca, tok := os.Getenv("K8S_IT_SERVER"), os.Getenv("K8S_IT_CA"), os.Getenv("K8S_IT_TOKEN")
	if server == "" || ca == "" || tok == "" {
		t.Skip("set K8S_IT_SERVER / K8S_IT_CA / K8S_IT_TOKEN")
	}

	res := NewScanner(slog.Default()).Sweep(context.Background(),
		[]ClusterSpec{{Name: "lab", Server: server, CAFile: ca, TokenFile: tok}},
		SweepOptions{})

	require.Len(t, res.Sweeps, 1)
	assert.True(t, res.Sweeps[0].Complete, "sweep must complete; reason=%q", res.Sweeps[0].Reason)
	assert.Empty(t, res.Sweeps[0].Reason)
	assert.False(t, res.Truncated)

	locs := map[string]bool{}
	managedBy := map[string]string{}
	fp := map[string][]string{}
	for _, o := range res.Observations {
		lk := LocationKey(o.SourceKind, o.Namespace, o.SecretName, o.DataKey)
		locs[lk] = true
		managedBy[lk] = o.ManagedBy
		fp[lk] = o.ObservedChainFingerprints
	}

	// The kubernetes.io/tls Secrets are listed (server-side fieldSelector);
	// the Opaque decoy is filtered out before it ever reaches the agent.
	assert.True(t, locs["secret/demo/web-tls/tls.crt"])
	assert.True(t, locs["secret/demo/api-tls/tls.crt"])
	assert.True(t, locs["secret/demo2/web-copy-tls/tls.crt"])
	for lk := range locs {
		assert.NotContains(t, lk, "app-config", "the Opaque decoy must never be observed")
	}

	// cert-manager annotation surfaced on the managed Secret only.
	assert.Equal(t, "cert-manager", managedBy["secret/demo/web-tls/tls.crt"])
	assert.Empty(t, managedBy["secret/demo/api-tls/tls.crt"])

	// Cross-namespace dedup: the copy shares web-tls's fingerprint.
	assert.Equal(t, fp["secret/demo/web-tls/tls.crt"], fp["secret/demo2/web-copy-tls/tls.crt"])

	// Mesh allowlist read via targeted gets, public keys only.
	assert.True(t, locs["secret/istio-system/istio-ca-secret/ca-cert.pem"])
	assert.True(t, locs["secret/istio-system/cacerts/ca-cert.pem"])
	assert.True(t, locs["configmap/linkerd/linkerd-identity-trust-roots/ca-bundle.crt"])

	// REDACTION: every observation is keyed on a PUBLIC data key. A private-key
	// key (tls.key, key.pem, ca-key.pem) reaching this point is a leak.
	publicKeys := map[string]bool{
		"tls.crt": true, "ca.crt": true, "ca-cert.pem": true, "root-cert.pem": true,
		"cert-chain.pem": true, "crt.pem": true, "ca-bundle.crt": true,
	}
	for _, o := range res.Observations {
		assert.Truef(t, publicKeys[o.DataKey], "observation reads non-public data key %q (%s/%s)",
			o.DataKey, o.Namespace, o.SecretName)
	}
	// No shipped certificate carries private-key or decoy bytes.
	for _, c := range res.Certificates {
		assert.NotContains(t, string(c.DER), "MUSTNEVERLEAVE")
		assert.NotContains(t, string(c.DER), "super-secret")
		assert.NotContains(t, string(c.DER), "PRIVATE KEY")
	}

	t.Logf("sweep OK: %d certificates, %d observations",
		len(res.Certificates), len(res.Observations))
}
