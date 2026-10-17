package config

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

type Config struct {
	ServerURL string `yaml:"server_url"`

	// Path to the sentinel key file (JSON)
	KeyFile string `yaml:"key_file"`

	// Sentinel identity (set after enrollment)
	SentinelID string `yaml:"sentinel_id"`

	// EnrollToken lets the SERVICE self-enroll on first boot (no key yet) when
	// baked into a VM template. Prefer the NOCERT_ENROLL_TOKEN env var
	// (cloud-init / EnvironmentFile) so the image carries no durable secret.
	// Ignored once the sentinel holds a key file (already enrolled).
	EnrollToken string `yaml:"enroll_token"`

	AllowNetworkScan *bool `yaml:"allow_network_scan"`

	AllowFilesystemScan *bool `yaml:"allow_filesystem_scan"`

	// Set to false to forbid the sentinel from connecting to any local service,
	// even if the backend requests a local_scan - the operator's kill switch for
	// host-local probing.
	AllowLocalScan *bool `yaml:"allow_local_scan"`

	// Set to false to forbid the sentinel from talking to any Kubernetes API
	// server, even if the backend requests a kubernetes_scan - the operator's
	// kill switch for the Kubernetes connector.
	AllowKubernetesScan *bool `yaml:"allow_kubernetes_scan"`

	// KubernetesClusters lists the clusters the Kubernetes connector reads.
	// Credentials stay in this local file (and the files it points to); they
	// are never sent to the backend. Empty list = connector inert.
	KubernetesClusters []KubernetesCluster `yaml:"kubernetes_clusters"`

	// Logging
	LogLevel  string `yaml:"log_level"`
	LogFormat string `yaml:"log_format"`

	// Timing
	PollingInterval          time.Duration `yaml:"polling_interval"`
	KeyRotationCheckInterval time.Duration `yaml:"key_rotation_check_interval"`
	KeyRotationMargin        time.Duration `yaml:"key_rotation_margin"`
}

// KubernetesCluster is one cluster connection recipe: either a kubeconfig
// path (client certs or a static token; exec plugins are rejected), or the
// explicit server + ca_file + token_file trio - the documented ServiceAccount
// setup. Name tags every observation from this cluster.
type KubernetesCluster struct {
	Name       string `yaml:"name"`
	Kubeconfig string `yaml:"kubeconfig"`
	Context    string `yaml:"context"`
	Server     string `yaml:"server"`
	CAFile     string `yaml:"ca_file"`
	TokenFile  string `yaml:"token_file"`
}

// kubernetesClusterNameRE bounds cluster names: they become ES keyword values
// and report fields, so keep them plain.
var kubernetesClusterNameRE = regexp.MustCompile(`^[a-z0-9._-]+$`)

func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading config file: %w", err)
	}

	cfg := &Config{}
	dec := yaml.NewDecoder(bytes.NewReader(data))
	// Reject unknown keys so a typo'd kill switch (allow_network_scam: false) is
	// a startup error, not a silently-ignored line that leaves scanning on.
	dec.KnownFields(true)
	if err := dec.Decode(cfg); err != nil && !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("parsing config file: %w", err)
	}
	// A second document could hide a kill switch that the operator expects
	// to apply. Only a single configuration document is supported.
	var extra any
	if err := dec.Decode(&extra); !errors.Is(err, io.EOF) {
		return nil, errors.New("config file must contain exactly one YAML document")
	}

	cfg.applyDefaults()

	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("invalid configuration: %w", err)
	}

	return cfg, nil
}

func (c *Config) applyDefaults() {
	if c.AllowNetworkScan == nil {
		t := true
		c.AllowNetworkScan = &t
	}
	if c.AllowFilesystemScan == nil {
		t := true
		c.AllowFilesystemScan = &t
	}
	if c.AllowLocalScan == nil {
		t := true
		c.AllowLocalScan = &t
	}
	if c.AllowKubernetesScan == nil {
		t := true
		c.AllowKubernetesScan = &t
	}
	if c.KeyFile == "" {
		// scripts/postinstall.sh mirrors this default to detect an enrolled host; keep in sync.
		c.KeyFile = "/etc/nocert-sentinel/sentinel-key.json"
	}
	if c.LogLevel == "" {
		c.LogLevel = "info"
	}
	if c.LogFormat == "" {
		c.LogFormat = "json"
	}
	if c.PollingInterval == 0 {
		c.PollingInterval = 30 * time.Second
	}
	if c.KeyRotationCheckInterval == 0 {
		c.KeyRotationCheckInterval = 6 * time.Hour
	}
	if c.KeyRotationMargin == 0 {
		c.KeyRotationMargin = 5 * 24 * time.Hour
	}
}

func (c *Config) Validate() error {
	if c.ServerURL == "" {
		return errors.New("server_url is required")
	}
	// Structural check only - never resolve the host (explicit DNS is forbidden).
	// HTTPS is mandatory: this is the single enforcement point for the whole
	// binary (config.Load always runs Validate, and every transport.Client /
	// Register call is built from this validated ServerURL), so plain http can
	// never carry the enrollment Bearer token or scan data in the clear - not
	// for localhost, private networks or tunnels. A scheme-less or
	// credential-bearing URL is rejected.
	u, err := url.Parse(c.ServerURL)
	if err != nil {
		return fmt.Errorf("server_url is not a valid URL: %w", err)
	}
	if u.Scheme != "https" {
		return fmt.Errorf("server_url must use https (got %q)", u.Scheme)
	}
	if u.Host == "" {
		return errors.New("server_url has no host")
	}
	if u.User != nil {
		return errors.New("server_url must not embed credentials (user:password@)")
	}
	switch c.LogLevel {
	case "debug", "info", "warn", "error":
	default:
		return fmt.Errorf("log_level must be one of debug, info, warn, error (got %q)", c.LogLevel)
	}
	switch c.LogFormat {
	case "json", "text":
	default:
		return fmt.Errorf("log_format must be one of json, text (got %q)", c.LogFormat)
	}
	// These feed time.NewTicker, which panics on a non-positive duration. A
	// negative value survives applyDefaults (which only fills a zero), so reject
	// it here with a clear error instead of a runtime panic at startup.
	if c.PollingInterval <= 0 {
		return fmt.Errorf("polling_interval must be positive (got %s)", c.PollingInterval)
	}
	if c.KeyRotationCheckInterval <= 0 {
		return fmt.Errorf("key_rotation_check_interval must be positive (got %s)", c.KeyRotationCheckInterval)
	}
	if c.KeyRotationMargin <= 0 {
		return fmt.Errorf("key_rotation_margin must be positive (got %s)", c.KeyRotationMargin)
	}
	// The whole sweep ships in one report and the backend rejects a report with
	// more than 16 cluster sweeps (the kubernetes_sweeps maxItems of the wire
	// contract). More clusters than that would 400 every
	// k8s report permanently, so fail fast at config load instead.
	if len(c.KubernetesClusters) > 16 {
		return fmt.Errorf("kubernetes_clusters: at most 16 clusters are supported (got %d); the backend rejects a report carrying more than 16 cluster sweeps", len(c.KubernetesClusters))
	}
	names := make(map[string]bool, len(c.KubernetesClusters))
	for i, kc := range c.KubernetesClusters {
		if kc.Name == "" {
			return fmt.Errorf("kubernetes_clusters[%d]: name is required", i)
		}
		if len(kc.Name) > 64 || !kubernetesClusterNameRE.MatchString(kc.Name) {
			return fmt.Errorf("kubernetes_clusters[%d]: cluster name must be 1-64 chars of [a-z0-9._-] (got %q)", i, kc.Name)
		}
		if names[kc.Name] {
			return fmt.Errorf("kubernetes_clusters[%d]: duplicate cluster name %q", i, kc.Name)
		}
		names[kc.Name] = true

		hasKubeconfig := kc.Kubeconfig != ""
		hasTrio := kc.Server != "" || kc.TokenFile != "" || kc.CAFile != ""
		switch {
		case hasKubeconfig && hasTrio:
			return fmt.Errorf("kubernetes_clusters[%d] (%s): set either kubeconfig or server/ca_file/token_file, not both", i, kc.Name)
		case hasKubeconfig:
			if !strings.HasPrefix(kc.Kubeconfig, "/") {
				return fmt.Errorf("kubernetes_clusters[%d] (%s): kubeconfig must be an absolute path", i, kc.Name)
			}
		case hasTrio:
			if kc.Context != "" {
				return fmt.Errorf("kubernetes_clusters[%d] (%s): context only applies to a kubeconfig", i, kc.Name)
			}
			u, err := url.Parse(kc.Server)
			if err != nil || u.Scheme != "https" || u.Host == "" {
				return fmt.Errorf("kubernetes_clusters[%d] (%s): server must be an https:// URL", i, kc.Name)
			}
			if kc.CAFile == "" {
				return fmt.Errorf("kubernetes_clusters[%d] (%s): ca_file is required with server (the API server cert is not publicly trusted)", i, kc.Name)
			}
			if kc.TokenFile == "" {
				return fmt.Errorf("kubernetes_clusters[%d] (%s): token_file is required with server", i, kc.Name)
			}
			if !strings.HasPrefix(kc.CAFile, "/") || !strings.HasPrefix(kc.TokenFile, "/") {
				return fmt.Errorf("kubernetes_clusters[%d] (%s): ca_file and token_file must be absolute paths", i, kc.Name)
			}
		default:
			return fmt.Errorf("kubernetes_clusters[%d] (%s): set either kubeconfig or server/ca_file/token_file", i, kc.Name)
		}
	}
	return nil
}
