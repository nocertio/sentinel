// Package kubernetes reads TLS certificate material from Kubernetes clusters
// through the API server, with a hand-written REST client (stdlib + yaml.v3
// only - no client-go, whose ~67-module dependency tree would defeat this
// binary's auditable go.mod). Scope: paginated LIST of kubernetes.io/tls
// Secrets plus targeted GETs of a named allowlist of well-known mesh CA
// objects. Only public certificate material (allowlisted data keys) ever
// leaves this package; see extract.go.
package kubernetes

import (
	"encoding/base64"
	"errors"
	"fmt"
	"net/url"
	"os"

	"gopkg.in/yaml.v3"
)

// kubeconfig mirrors the subset of the kubeconfig v1 file format this agent
// supports: client certificates and static bearer tokens. The format has been
// stable for years; exec plugins and auth-providers are deliberately rejected
// (operators use a ServiceAccount token instead).
type kubeconfig struct {
	CurrentContext string         `yaml:"current-context"`
	Clusters       []namedCluster `yaml:"clusters"`
	Contexts       []namedContext `yaml:"contexts"`
	Users          []namedUser    `yaml:"users"`
}

type namedCluster struct {
	Name    string `yaml:"name"`
	Cluster struct {
		Server                   string `yaml:"server"`
		CertificateAuthority     string `yaml:"certificate-authority"`
		CertificateAuthorityData string `yaml:"certificate-authority-data"`
	} `yaml:"cluster"`
}

type namedContext struct {
	Name    string `yaml:"name"`
	Context struct {
		Cluster string `yaml:"cluster"`
		User    string `yaml:"user"`
	} `yaml:"context"`
}

type namedUser struct {
	Name string `yaml:"name"`
	User struct {
		Token                 string         `yaml:"token"`
		TokenFile             string         `yaml:"tokenFile"`
		ClientCertificate     string         `yaml:"client-certificate"`
		ClientCertificateData string         `yaml:"client-certificate-data"`
		ClientKey             string         `yaml:"client-key"`
		ClientKeyData         string         `yaml:"client-key-data"`
		Exec                  map[string]any `yaml:"exec"`
		AuthProvider          map[string]any `yaml:"auth-provider"`
	} `yaml:"user"`
}

// restConfig is the resolved connection material for one cluster.
type restConfig struct {
	server        string
	caPEM         []byte
	token         string
	clientCertPEM []byte
	clientKeyPEM  []byte
}

// loadKubeconfig resolves one context of a kubeconfig file into a restConfig.
// contextName == "" uses current-context. Inline *-data fields win over path
// references, matching kubectl semantics.
func loadKubeconfig(path, contextName string) (*restConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading kubeconfig: %w", err)
	}
	var kc kubeconfig
	if err := yaml.Unmarshal(data, &kc); err != nil {
		return nil, fmt.Errorf("parsing kubeconfig %s: %w", path, err)
	}

	if contextName == "" {
		contextName = kc.CurrentContext
	}
	if contextName == "" {
		return nil, errors.New("kubeconfig has no current-context and no context was configured")
	}
	var ctx *namedContext
	for i := range kc.Contexts {
		if kc.Contexts[i].Name == contextName {
			ctx = &kc.Contexts[i]
			break
		}
	}
	if ctx == nil {
		return nil, fmt.Errorf("context %q not found in kubeconfig", contextName)
	}

	var cluster *namedCluster
	for i := range kc.Clusters {
		if kc.Clusters[i].Name == ctx.Context.Cluster {
			cluster = &kc.Clusters[i]
			break
		}
	}
	if cluster == nil || cluster.Cluster.Server == "" {
		return nil, fmt.Errorf("cluster %q not found or has no server", ctx.Context.Cluster)
	}
	// Require https:// with a host, parity with the config.go trio: a kubeconfig
	// is operator-editable and could point server at a hostile endpoint, and
	// plain http would put API traffic (bearer token included) on the wire in
	// the clear. https does NOT by itself stop exfiltration to a hostile TLS
	// server whose CA the same kubeconfig pins - that vector is closed by
	// refusing tokenFile below, so the only file the kubeconfig can turn into a
	// bearer token is one the operator named in config.yaml, not an arbitrary
	// path aimed at the sentinel's own key.
	if u, uerr := url.Parse(cluster.Cluster.Server); uerr != nil || u.Scheme != "https" || u.Host == "" {
		return nil, fmt.Errorf("cluster %q server must be an https:// URL, got %q", ctx.Context.Cluster, cluster.Cluster.Server)
	}

	var user *namedUser
	for i := range kc.Users {
		if kc.Users[i].Name == ctx.Context.User {
			user = &kc.Users[i]
			break
		}
	}
	if user == nil {
		return nil, fmt.Errorf("user %q not found in kubeconfig", ctx.Context.User)
	}
	if user.User.Exec != nil || user.User.AuthProvider != nil {
		return nil, errors.New("exec/auth-provider credentials are not supported; put a ServiceAccount token inline, or use the server/ca_file/token_file trio in config.yaml")
	}
	// A kubeconfig pins its own server AND CA, so a tokenFile path would let a
	// hostile kubeconfig read any file the agent can (its own 0600 Ed25519 key)
	// and POST it as a bearer token to an attacker's endpoint. File-based tokens
	// must go through the explicit server/ca_file/token_file trio in config.yaml
	// (the root trust file), never an arbitrary path a kubeconfig can name.
	if user.User.TokenFile != "" {
		return nil, errors.New("tokenFile in a kubeconfig is not supported; put the token inline, or use the server/ca_file/token_file trio in config.yaml")
	}

	rc := &restConfig{server: cluster.Cluster.Server}

	rc.caPEM, err = inlineOrFile(cluster.Cluster.CertificateAuthorityData, cluster.Cluster.CertificateAuthority)
	if err != nil {
		return nil, fmt.Errorf("cluster CA: %w", err)
	}
	rc.clientCertPEM, err = inlineOrFile(user.User.ClientCertificateData, user.User.ClientCertificate)
	if err != nil {
		return nil, fmt.Errorf("client certificate: %w", err)
	}
	rc.clientKeyPEM, err = inlineOrFile(user.User.ClientKeyData, user.User.ClientKey)
	if err != nil {
		return nil, fmt.Errorf("client key: %w", err)
	}

	rc.token = user.User.Token

	if rc.token == "" && rc.clientCertPEM == nil {
		return nil, errors.New("kubeconfig user has neither a token nor a client certificate")
	}
	return rc, nil
}

// inlineOrFile decodes an inline base64 *-data field, else reads the path.
// Both empty returns (nil, nil).
func inlineOrFile(inlineB64, path string) ([]byte, error) {
	if inlineB64 != "" {
		return base64.StdEncoding.DecodeString(inlineB64)
	}
	if path != "" {
		return os.ReadFile(path)
	}
	return nil, nil
}
