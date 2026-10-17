package kubernetes

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const (
	// listPageSize keeps one page bounded: Secrets can weigh up to ~1 MiB
	// each (etcd cap), so 50/page bounds a response to tens of MiB.
	listPageSize = 50
	// maxSecretsPerList bounds the total Secrets accumulated across all pages of
	// one list. listPageSize + maxResponseBytes bound a single page; this bounds
	// the whole pagination, so a hostile API server handing out continue tokens
	// forever can neither OOM the agent nor stall the (synchronous) sweep. It is
	// generous versus any real cluster's TLS-Secret count (tens to hundreds) yet
	// finite; a truncated list is reported complete=false so the backend never
	// reconciles on it, and the sweep-wide cert cap discards the surplus anyway.
	maxSecretsPerList = 5000
	// maxResponseBytes caps any single API response read.
	maxResponseBytes = 128 << 20
	requestTimeout   = 30 * time.Second
	tlsSecretType    = "kubernetes.io/tls"
)

// ClusterSpec is the resolved connection recipe for one cluster, mapped from
// the agent's local config file. Either Kubeconfig (+optional Context) or the
// Server/CAFile/TokenFile trio is set - config validation enforces that.
type ClusterSpec struct {
	Name       string
	Kubeconfig string
	Context    string
	Server     string
	CAFile     string
	TokenFile  string
}

// objectMeta is the metadata subset the connector reads.
type objectMeta struct {
	Namespace   string            `json:"namespace"`
	Name        string            `json:"name"`
	Annotations map[string]string `json:"annotations"`
}

// secret mirrors core/v1 Secret. Data values are base64 on the wire;
// encoding/json decodes them into []byte transparently.
type secret struct {
	Metadata objectMeta        `json:"metadata"`
	Type     string            `json:"type"`
	Data     map[string][]byte `json:"data"`
}

// configMap mirrors core/v1 ConfigMap (data is plain text, binaryData base64).
type configMap struct {
	Metadata   objectMeta        `json:"metadata"`
	Data       map[string]string `json:"data"`
	BinaryData map[string][]byte `json:"binaryData"`
}

type listMeta struct {
	Continue string `json:"continue"`
}

type secretList struct {
	Metadata listMeta `json:"metadata"`
	Items    []secret `json:"items"`
}

// clusterClient is a minimal read-only core/v1 REST client. The GA wire
// contract (paths, pagination, field selectors) is covered by the Kubernetes
// deprecation policy, which is what makes a hand-written client viable.
type clusterClient struct {
	server string
	token  string
	httpc  *http.Client
}

// newClusterClient resolves a ClusterSpec into a ready client.
func newClusterClient(spec ClusterSpec) (*clusterClient, error) {
	var rc *restConfig
	var err error
	if spec.Kubeconfig != "" {
		rc, err = loadKubeconfig(spec.Kubeconfig, spec.Context)
		if err != nil {
			return nil, err
		}
	} else {
		rc = &restConfig{server: spec.Server}
		if rc.caPEM, err = inlineOrFile("", spec.CAFile); err != nil {
			return nil, fmt.Errorf("ca_file: %w", err)
		}
		tok, err := inlineOrFile("", spec.TokenFile)
		if err != nil {
			return nil, fmt.Errorf("token_file: %w", err)
		}
		rc.token = string(bytes.TrimSpace(tok))
	}
	return newFromRESTConfig(rc)
}

func newFromRESTConfig(rc *restConfig) (*clusterClient, error) {
	tlsCfg := &tls.Config{MinVersion: tls.VersionTLS12}
	if rc.caPEM != nil {
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(rc.caPEM) {
			return nil, errors.New("cluster CA bundle contains no usable certificate")
		}
		tlsCfg.RootCAs = pool
	}
	if rc.clientCertPEM != nil {
		cert, err := tls.X509KeyPair(rc.clientCertPEM, rc.clientKeyPEM)
		if err != nil {
			return nil, fmt.Errorf("client certificate: %w", err)
		}
		tlsCfg.Certificates = []tls.Certificate{cert}
	}
	return &clusterClient{
		server: strings.TrimRight(rc.server, "/"),
		token:  rc.token,
		httpc: &http.Client{
			Timeout: requestTimeout,
			Transport: &http.Transport{
				// API-server traffic follows the same egress proxy policy as
				// backend traffic (many customers force a forward proxy).
				Proxy:           http.ProxyFromEnvironment,
				TLSClientConfig: tlsCfg,
			},
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	}, nil
}

// newClusterClientForTest wires a client at a test server, reusing its
// pre-trusted http.Client. Test-only constructor, kept in prod code because
// it is two lines and avoids exporting internals.
func newClusterClientForTest(server string, httpc *http.Client, token string) (*clusterClient, error) {
	return &clusterClient{server: strings.TrimRight(server, "/"), token: token, httpc: httpc}, nil
}

// errGone signals an expired pagination continue token (HTTP 410).
var errGone = errors.New("continue token expired")

// listTLSSecrets pages through Secrets of type kubernetes.io/tls, calling visit
// for each Secret as it is decoded. Streaming per page (rather than
// accumulating every page first) keeps whole Secrets - which carry tls.key -
// from all sitting in memory at once, so a large or hostile cluster can only
// pin one page's worth, not the whole list. The fieldSelector is applied
// server-side, so values of non-TLS Secrets never reach this process for the
// cluster-wide list. namespace=="" lists cluster-wide; otherwise the namespaced
// path is used (fits namespace-scoped RBAC). visit returns false to stop early
// (a caller-side cap was hit). Returns complete=false when pagination could not
// finish, so the caller never reconciles on a truncated view.
func (c *clusterClient) listTLSSecrets(ctx context.Context, namespace string, visit func(*secret) bool) (bool, error) {
	page := func() (bool, error) {
		cont := ""
		seen := 0
		for {
			basePath := "/api/v1/secrets"
			if namespace != "" {
				basePath = "/api/v1/namespaces/" + url.PathEscape(namespace) + "/secrets"
			}
			q := url.Values{}
			q.Set("fieldSelector", "type="+tlsSecretType)
			q.Set("limit", fmt.Sprint(listPageSize))
			if cont != "" {
				q.Set("continue", cont)
			}
			var pg secretList
			if err := c.getJSON(ctx, basePath+"?"+q.Encode(), &pg); err != nil {
				return false, err
			}
			for i := range pg.Items {
				if !visit(&pg.Items[i]) {
					return false, nil // caller asked to stop (sweep-wide cap)
				}
				seen++
				if seen >= maxSecretsPerList {
					// Hard cap: stop and report incomplete so the caller marks the
					// cluster Complete=false (never reconcile on a truncated view).
					// Guards against infinite continue tokens.
					return false, nil
				}
			}
			if pg.Metadata.Continue == "" {
				return true, nil
			}
			cont = pg.Metadata.Continue
		}
	}

	complete, err := page()
	if errors.Is(err, errGone) {
		// The continue token expired mid-list; restart once from scratch.
		// Already-visited Secrets are visited again, but the caller's collect()
		// dedups by fingerprint and location key, so a restart is idempotent.
		complete, err = page()
	}
	if err != nil {
		return false, err
	}
	return complete, nil
}

// getSecret treats 404 as absence. A forbidden read is a coverage gap and
// must prevent reconciliation of previously observed material.
func (c *clusterClient) getSecret(ctx context.Context, namespace, name string) (*secret, bool, error) {
	var s secret
	err := c.getJSON(ctx, "/api/v1/namespaces/"+url.PathEscape(namespace)+"/secrets/"+url.PathEscape(name), &s)
	return maybeAbsent(&s, err)
}

// getConfigMap fetches one ConfigMap with the same absent semantics.
func (c *clusterClient) getConfigMap(ctx context.Context, namespace, name string) (*configMap, bool, error) {
	var cm configMap
	err := c.getJSON(ctx, "/api/v1/namespaces/"+url.PathEscape(namespace)+"/configmaps/"+url.PathEscape(name), &cm)
	return maybeAbsent(&cm, err)
}

func maybeAbsent[T any](v *T, err error) (*T, bool, error) {
	var se *statusError
	if errors.As(err, &se) && se.code == http.StatusNotFound {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	return v, true, nil
}

// statusError carries a non-2xx API server response code.
type statusError struct{ code int }

func (e *statusError) Error() string { return fmt.Sprintf("api server returned status %d", e.code) }

func (c *clusterClient) getJSON(ctx context.Context, pathAndQuery string, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.server+pathAndQuery, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}
	resp, err := c.httpc.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	switch {
	case resp.StatusCode == http.StatusGone:
		return errGone
	case resp.StatusCode < 200 || resp.StatusCode > 299:
		return &statusError{code: resp.StatusCode}
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes))
	if err != nil {
		return err
	}
	return json.Unmarshal(body, out)
}
