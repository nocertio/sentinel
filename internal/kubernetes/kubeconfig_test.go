package kubernetes

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func writeFile(t *testing.T, dir, name, content string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	require.NoError(t, os.WriteFile(p, []byte(content), 0o600))
	return p
}

func TestLoadKubeconfigClientCertData(t *testing.T) {
	dir := t.TempDir()
	// base64("CERTPEM") = Q0VSVFBFTQ==, base64("KEYPEM") = S0VZUEVN, base64("CAPEM") = Q0FQRU0=
	p := writeFile(t, dir, "kc.yaml", `
apiVersion: v1
kind: Config
current-context: prod
clusters:
- name: c1
  cluster:
    server: https://10.0.0.1:6443
    certificate-authority-data: Q0FQRU0=
contexts:
- name: prod
  context: {cluster: c1, user: u1}
users:
- name: u1
  user:
    client-certificate-data: Q0VSVFBFTQ==
    client-key-data: S0VZUEVN
`)
	rc, err := loadKubeconfig(p, "")
	require.NoError(t, err)
	assert.Equal(t, "https://10.0.0.1:6443", rc.server)
	assert.Equal(t, []byte("CAPEM"), rc.caPEM)
	assert.Equal(t, []byte("CERTPEM"), rc.clientCertPEM)
	assert.Equal(t, []byte("KEYPEM"), rc.clientKeyPEM)
}

func TestLoadKubeconfigTokenAndFileRefs(t *testing.T) {
	dir := t.TempDir()
	caPath := writeFile(t, dir, "ca.crt", "CA-FROM-FILE")
	p := writeFile(t, dir, "kc.yaml", `
current-context: prod
clusters:
- name: c1
  cluster:
    server: https://k8s.internal:6443
    certificate-authority: `+caPath+`
contexts:
- name: prod
  context: {cluster: c1, user: u1}
users:
- name: u1
  user:
    token: sa-token-value
`)
	rc, err := loadKubeconfig(p, "")
	require.NoError(t, err)
	assert.Equal(t, "sa-token-value", rc.token)
	assert.Equal(t, []byte("CA-FROM-FILE"), rc.caPEM)
}

func TestLoadKubeconfigExplicitContextAndDataPriority(t *testing.T) {
	// *-data fields win over path fields; explicit context overrides current-context.
	dir := t.TempDir()
	p := writeFile(t, dir, "kc.yaml", `
current-context: other
clusters:
- name: c1
  cluster: {server: "https://one:6443", certificate-authority-data: Q0FQRU0=, certificate-authority: /nonexistent}
- name: c2
  cluster: {server: "https://two:6443", certificate-authority-data: Q0FQRU0=}
contexts:
- name: other
  context: {cluster: c2, user: u1}
- name: prod
  context: {cluster: c1, user: u1}
users:
- name: u1
  user: {token: tok}
`)
	rc, err := loadKubeconfig(p, "prod")
	require.NoError(t, err)
	assert.Equal(t, "https://one:6443", rc.server)
	assert.Equal(t, []byte("CAPEM"), rc.caPEM)
}

func TestLoadKubeconfigRejectsExecPlugin(t *testing.T) {
	dir := t.TempDir()
	p := writeFile(t, dir, "kc.yaml", `
current-context: prod
clusters:
- name: c1
  cluster: {server: "https://one:6443", certificate-authority-data: Q0FQRU0=}
contexts:
- name: prod
  context: {cluster: c1, user: u1}
users:
- name: u1
  user:
    exec: {apiVersion: client.authentication.k8s.io/v1, command: aws}
`)
	_, err := loadKubeconfig(p, "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "exec/auth-provider credentials are not supported")
}

func TestLoadKubeconfigRejectsTokenFile(t *testing.T) {
	// A tokenFile path in a kubeconfig (operator-editable, pins its own server +
	// CA) could aim at the sentinel's own 0600 key and exfiltrate it as a bearer
	// token. File-based tokens must go through the config.yaml trio instead.
	dir := t.TempDir()
	p := writeFile(t, dir, "kc.yaml", `
current-context: prod
clusters:
- name: c1
  cluster: {server: "https://one:6443", certificate-authority-data: Q0FQRU0=}
contexts:
- name: prod
  context: {cluster: c1, user: u1}
users:
- name: u1
  user:
    tokenFile: /etc/nocert-sentinel/sentinel-key.json
`)
	_, err := loadKubeconfig(p, "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "tokenFile in a kubeconfig is not supported")
}

func TestLoadKubeconfigRejectsNonHTTPSServer(t *testing.T) {
	// A hostile/http server in a kubeconfig would exfiltrate the token or client
	// key it references; only https:// with a host is accepted, matching the
	// config.go trio check.
	kc := func(server string) string {
		return `
current-context: prod
clusters:
- name: c1
  cluster: {server: "` + server + `", certificate-authority-data: Q0FQRU0=}
contexts:
- name: prod
  context: {cluster: c1, user: u1}
users:
- name: u1
  user: {token: tok}
`
	}
	for _, server := range []string{"http://10.0.0.1:6443", "10.0.0.1:6443", "ftp://x", "https://"} {
		dir := t.TempDir()
		p := writeFile(t, dir, "kc.yaml", kc(server))
		_, err := loadKubeconfig(p, "")
		require.Error(t, err, "server %q must be rejected", server)
		assert.Contains(t, err.Error(), "https")
	}

	dir := t.TempDir()
	p := writeFile(t, dir, "kc.yaml", kc("https://10.0.0.1:6443"))
	rc, err := loadKubeconfig(p, "")
	require.NoError(t, err)
	assert.Equal(t, "https://10.0.0.1:6443", rc.server)
}

func TestLoadKubeconfigMissingContext(t *testing.T) {
	dir := t.TempDir()
	p := writeFile(t, dir, "kc.yaml", "current-context: nope\n")
	_, err := loadKubeconfig(p, "")
	require.Error(t, err)
}
