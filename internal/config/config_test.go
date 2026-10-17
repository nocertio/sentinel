package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLoad(t *testing.T) {
	yaml := `
server_url: "https://nocert.example.com"
log_level: "debug"
polling_interval: 15s
`
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	require.NoError(t, os.WriteFile(path, []byte(yaml), 0644))

	cfg, err := Load(path)
	require.NoError(t, err)

	assert.Equal(t, "https://nocert.example.com", cfg.ServerURL)
	assert.Equal(t, "debug", cfg.LogLevel)
	assert.Equal(t, "json", cfg.LogFormat) // default
	assert.Equal(t, 15*time.Second, cfg.PollingInterval)
	assert.Equal(t, "/etc/nocert-sentinel/sentinel-key.json", cfg.KeyFile) // default
	assert.True(t, *cfg.AllowNetworkScan)                                  // default
}

func TestLoadEmptyConfig(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	// server_url is required, so provide it
	require.NoError(t, os.WriteFile(path, []byte("server_url: https://example.com"), 0644))

	cfg, err := Load(path)
	require.NoError(t, err)

	assert.Equal(t, "/etc/nocert-sentinel/sentinel-key.json", cfg.KeyFile)
	assert.Equal(t, "info", cfg.LogLevel)
	assert.Equal(t, "json", cfg.LogFormat)
	assert.Equal(t, 30*time.Second, cfg.PollingInterval)
	assert.True(t, *cfg.AllowNetworkScan)
}

func TestLoadMissingServerURL(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	require.NoError(t, os.WriteFile(path, []byte(""), 0644))

	_, err := Load(path)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "server_url is required")
}

func TestLoadMissingFile(t *testing.T) {
	_, err := Load("/nonexistent/config.yaml")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "reading config file")
}

func TestLoadInvalidYAML(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	require.NoError(t, os.WriteFile(path, []byte(":::invalid"), 0644))

	_, err := Load(path)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "parsing config file")
}

func TestLoadRejectsAdditionalYAMLDocuments(t *testing.T) {
	for _, suffix := range []string{"---\nallow_network_scan: false\n", "---\n", "---\n[broken"} {
		path := filepath.Join(t.TempDir(), "config.yaml")
		require.NoError(t, os.WriteFile(path, []byte("server_url: https://example.com\n"+suffix), 0600))
		_, err := Load(path)
		require.Error(t, err, "a second document must never silently hide a kill switch")
	}
}

func TestAllowNetworkScanDefault(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	require.NoError(t, os.WriteFile(path, []byte("server_url: https://example.com"), 0644))

	cfg, err := Load(path)
	require.NoError(t, err)
	require.NotNil(t, cfg.AllowNetworkScan)
	assert.True(t, *cfg.AllowNetworkScan)
}

func TestAllowNetworkScanFalse(t *testing.T) {
	yaml := `
server_url: https://example.com
allow_network_scan: false
`
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	require.NoError(t, os.WriteFile(path, []byte(yaml), 0644))

	cfg, err := Load(path)
	require.NoError(t, err)
	require.NotNil(t, cfg.AllowNetworkScan)
	assert.False(t, *cfg.AllowNetworkScan)
}

func TestAllowFilesystemScanDefault(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	require.NoError(t, os.WriteFile(path, []byte("server_url: https://example.com\n"), 0644))

	cfg, err := Load(path)
	require.NoError(t, err)
	assert.True(t, *cfg.AllowFilesystemScan)
}

func TestAllowFilesystemScanFalse(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	require.NoError(t, os.WriteFile(path, []byte("server_url: https://example.com\nallow_filesystem_scan: false\n"), 0644))

	cfg, err := Load(path)
	require.NoError(t, err)
	assert.False(t, *cfg.AllowFilesystemScan)
}

func TestLoadRejectsUnknownKey(t *testing.T) {
	// A typo'd kill switch must be a hard error, not a silently-ignored line.
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	require.NoError(t, os.WriteFile(path, []byte("server_url: https://example.com\nallow_network_scam: false\n"), 0644))

	_, err := Load(path)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "parsing config file")
}

func TestLoadAllowLocalScanFalse(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	require.NoError(t, os.WriteFile(path, []byte("server_url: https://example.com\nallow_local_scan: false\n"), 0644))

	cfg, err := Load(path)
	require.NoError(t, err)
	require.NotNil(t, cfg.AllowLocalScan)
	assert.False(t, *cfg.AllowLocalScan)
}

func TestLoadServerURLValidation(t *testing.T) {
	cases := map[string]bool{ // url -> valid
		"https://app.nocert.io":         true,
		"http://192.0.2.10:8080":        false, // https is mandatory, no exception for private nets / tunnels
		"http://localhost:8080":         false, // ... not even for localhost
		"ftp://app.nocert.io":           false,
		"app.nocert.io":                 false, // no scheme
		"https://user:pw@app.nocert.io": false, // credentials
	}
	for u, valid := range cases {
		dir := t.TempDir()
		path := filepath.Join(dir, "config.yaml")
		require.NoError(t, os.WriteFile(path, []byte("server_url: \""+u+"\"\n"), 0644))
		_, err := Load(path)
		if valid {
			require.NoError(t, err, u)
		} else {
			require.Error(t, err, u)
		}
	}
}

func TestLoadInvalidLogLevel(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	require.NoError(t, os.WriteFile(path, []byte("server_url: https://example.com\nlog_level: verbose\n"), 0644))

	_, err := Load(path)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "log_level must be one of")
}

func TestLoadInvalidLogFormat(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	require.NoError(t, os.WriteFile(path, []byte("server_url: https://example.com\nlog_format: pretty\n"), 0644))

	_, err := Load(path)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "log_format must be one of")
}

func TestKubernetesClustersValidation(t *testing.T) {
	base := "server_url: https://backend.example\n"
	cases := []struct {
		name    string
		yaml    string
		wantErr string
	}{
		{"valid kubeconfig form", base + `
kubernetes_clusters:
  - name: prod
    kubeconfig: /etc/nocert-sentinel/k8s/prod.kubeconfig
`, ""},
		{"valid token trio form", base + `
kubernetes_clusters:
  - name: prod
    server: https://10.0.0.1:6443
    ca_file: /etc/nocert-sentinel/k8s/ca.crt
    token_file: /etc/nocert-sentinel/k8s/token
`, ""},
		{"missing name", base + `
kubernetes_clusters:
  - kubeconfig: /a/b
`, "name is required"},
		{"duplicate names", base + `
kubernetes_clusters:
  - {name: prod, kubeconfig: /a}
  - {name: prod, kubeconfig: /b}
`, "duplicate cluster name"},
		{"both forms", base + `
kubernetes_clusters:
  - {name: prod, kubeconfig: /a, server: "https://x:6443"}
`, "either kubeconfig or server"},
		{"server without ca_file", base + `
kubernetes_clusters:
  - {name: prod, server: "https://x:6443", token_file: /t}
`, "ca_file is required"},
		{"bad name charset", base + `
kubernetes_clusters:
  - {name: "Prod Cluster", kubeconfig: /a}
`, "cluster name"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := filepath.Join(t.TempDir(), "config.yaml")
			require.NoError(t, os.WriteFile(p, []byte(tc.yaml), 0o600))
			_, err := Load(p)
			if tc.wantErr == "" {
				require.NoError(t, err)
			} else {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tc.wantErr)
			}
		})
	}
}

func TestKubernetesClustersCountCap(t *testing.T) {
	// The backend rejects a report carrying more than 16 cluster sweeps, so more
	// than 16 configured clusters would 400 every k8s report; reject at load.
	clusterYAML := func(n int) string {
		var b strings.Builder
		b.WriteString("server_url: https://backend.example\nkubernetes_clusters:\n")
		for i := 0; i < n; i++ {
			fmt.Fprintf(&b, "  - {name: c%d, kubeconfig: /etc/nocert-sentinel/k8s/c%d.kubeconfig}\n", i, i)
		}
		return b.String()
	}

	p16 := filepath.Join(t.TempDir(), "config.yaml")
	require.NoError(t, os.WriteFile(p16, []byte(clusterYAML(16)), 0o600))
	_, err := Load(p16)
	require.NoError(t, err, "16 clusters is the accepted ceiling")

	p17 := filepath.Join(t.TempDir(), "config.yaml")
	require.NoError(t, os.WriteFile(p17, []byte(clusterYAML(17)), 0o600))
	_, err = Load(p17)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "16")
}

func TestAllowKubernetesScanDefaultsTrue(t *testing.T) {
	p := filepath.Join(t.TempDir(), "config.yaml")
	require.NoError(t, os.WriteFile(p, []byte("server_url: https://backend.example\n"), 0o600))
	cfg, err := Load(p)
	require.NoError(t, err)
	require.NotNil(t, cfg.AllowKubernetesScan)
	assert.True(t, *cfg.AllowKubernetesScan)
}
