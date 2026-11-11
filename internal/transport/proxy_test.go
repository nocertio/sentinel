package transport

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"nocert.io/common/pkg/httpsig"
	"nocert.io/sentinel/internal/testutil"
)

func TestEnterpriseProxy(t *testing.T) {
	// Go caches environment proxy settings and system roots for the process.
	if os.Getenv("NOCERT_PROXY_TEST_CHILD") != "1" {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		executable, err := os.Executable()
		if err != nil {
			t.Fatal(err)
		}
		cmd := exec.CommandContext(ctx, executable, "-test.run=^TestEnterpriseProxy$", "-test.v", "-test.timeout=25s")
		cmd.Env = append(os.Environ(), "NOCERT_PROXY_TEST_CHILD=1")
		if output, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("proxy integration: %v\n%s", err, output)
		}
		return
	}

	for _, key := range []string{"HTTP_PROXY", "HTTPS_PROXY", "NO_PROXY", "http_proxy", "https_proxy", "no_proxy", "REQUEST_METHOD"} {
		t.Setenv(key, "")
	}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	agentKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x31}, ed25519.SeedSize))
	serverKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x32}, ed25519.SeedSize))
	var tamper atomic.Bool
	var requests atomic.Int32
	backend := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		if r.Header.Get("Proxy-Authorization") != "" {
			t.Error("proxy credentials reached backend")
		}
		if r.URL.Path == "/api/v1/sentinels/register" {
			if r.Method != http.MethodPost || r.Header.Get("Authorization") != "Bearer fixture-token" {
				t.Error("invalid enrollment request")
			}
			_, _ = io.WriteString(w, `{"sentinel_id":"fixture"}`)
			return
		}
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Error(err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		if r.Header.Get("Content-Digest") != httpsig.ContentDigest(body) {
			t.Error("request body does not match its signed digest")
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		if err := httpsig.VerifyRequest(r, agentKey.Public().(ed25519.PublicKey), "agent-key", nil); err != nil {
			t.Error(err)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		details, err := httpsig.RequestDetails(r)
		if err != nil {
			t.Error(err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		response := []byte(`{"config":{},"tasks":[]}`)
		if r.Method == http.MethodPost {
			response = []byte(`{"accepted":true}`)
		}
		digest, input, signature := httpsig.SignResponse(http.StatusOK, response, details.Nonce, serverKey, "server-key")
		w.Header().Set("Content-Digest", digest)
		w.Header().Set("Signature-Input", input)
		w.Header().Set("Signature", signature)
		if tamper.Load() {
			response = []byte(`{"config":{"network_scan_enabled":true},"tasks":[]}`)
		}
		_, _ = w.Write(response)
	}))
	cert := testutil.Certificate(t, func(c *x509.Certificate) {
		c.DNSNames = []string{"fixture.invalid", "bypass.invalid"}
	})
	backend.TLS = &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}
	backend.Config.ErrorLog = slog.NewLogLogger(logger.Handler(), slog.LevelError)
	backend.StartTLS()
	defer backend.Close()

	dir := t.TempDir()
	caPath := filepath.Join(dir, "ca.pem")
	if err := os.WriteFile(caPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Certificate[0]}), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SSL_CERT_FILE", caPath)
	t.Setenv("SSL_CERT_DIR", dir)
	_, port, _ := net.SplitHostPort(backend.Listener.Addr().String())
	target := net.JoinHostPort("fixture.invalid", port)
	bypass := net.JoinHostPort("bypass.invalid", port)
	proxyURL, connections := newConnectProxy(t, target, backend.Listener.Addr().String())
	t.Setenv("HTTPS_PROXY", proxyURL.String())
	t.Setenv("HTTP_PROXY", proxyURL.String())
	t.Setenv("NO_PROXY", "bypass.invalid,192.0.2.0/24")

	original := sharedTransport
	tr := original.Clone()
	defer tr.CloseIdleConnections()
	sharedTransport = tr
	defer func() { sharedTransport = original }()
	// Map fixture names locally and reject all other destinations, including DNS.
	tr.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		switch addr {
		case target, bypass:
			addr = backend.Listener.Addr().String()
		case proxyURL.Host:
		default:
			return nil, errors.New("unexpected test destination")
		}
		return (&net.Dialer{}).DialContext(ctx, network, addr)
	}
	newClient := func(host string) *Client {
		c := NewClient("https://"+host, "fixture", "agent-key", agentKey, serverKey.Public().(ed25519.PublicKey), "server-key", "test", logger)
		c.httpClient.Timeout = 3 * time.Second
		return c
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	t.Run("signed_requests_and_enrollment", func(t *testing.T) {
		c := newClient(target)
		if _, err := c.GetTasks(ctx); err != nil {
			t.Fatal(err)
		}
		if err := c.PostReport(ctx, &ReportRequest{}); err != nil {
			t.Fatal(err)
		}
		reg, err := Register(ctx, "https://"+target, "fixture-token", RegisterRequest{})
		if err != nil {
			t.Fatal(err)
		}
		if reg.SentinelID != "fixture" || connections.Load() == 0 || requests.Load() != 3 {
			t.Fatal("expected enrollment and signed requests through CONNECT")
		}
	})
	t.Run("no_proxy", func(t *testing.T) {
		before := connections.Load()
		if _, err := newClient(bypass).GetTasks(ctx); err != nil {
			t.Fatal(err)
		}
		if connections.Load() != before {
			t.Fatal("NO_PROXY destination reached proxy")
		}
		for _, tc := range []struct {
			host    string
			proxied bool
		}{{target, true}, {bypass, false}, {"192.0.2.1:443", false}, {"198.51.100.1:443", true}} {
			req, _ := http.NewRequest(http.MethodGet, "https://"+tc.host, nil)
			selected, err := tr.Proxy(req)
			if err != nil || (selected != nil) != tc.proxied {
				t.Fatalf("unexpected proxy selection for %s", tc.host)
			}
		}
	})
	t.Run("untrusted_certificate", func(t *testing.T) {
		untrusted := tr.Clone()
		defer untrusted.CloseIdleConnections()
		untrusted.TLSClientConfig.RootCAs = x509.NewCertPool()
		c := newClient(target)
		c.httpClient.Transport = untrusted
		before := requests.Load()
		_, err := c.GetTasks(ctx)
		var unknown x509.UnknownAuthorityError
		if !errors.As(err, &unknown) || requests.Load() != before {
			t.Fatalf("untrusted TLS peer was not rejected before HTTP: %v", err)
		}
	})
	t.Run("changed_signed_response", func(t *testing.T) {
		tamper.Store(true)
		defer tamper.Store(false)
		if _, err := newClient(target).GetTasks(ctx); err == nil || Retryable(err) {
			t.Fatal("trusted TLS must not bypass response signature verification")
		}
	})
	t.Run("proxy_authentication_refused", func(t *testing.T) {
		for _, tc := range []struct {
			name string
			user *url.Userinfo
		}{
			{"missing", nil},
			{"invalid", url.UserPassword("fixture-user", "fixture-password-rejected")},
		} {
			t.Run(tc.name, func(t *testing.T) {
				refusedURL := *proxyURL
				refusedURL.User = tc.user
				refused := tr.Clone()
				defer refused.CloseIdleConnections()
				refused.Proxy = http.ProxyURL(&refusedURL)
				sharedTransport = refused
				defer func() { sharedTransport = tr }()
				before := requests.Load()
				_, pollErr := newClient(target).GetTasks(ctx)
				_, enrollErr := Register(ctx, "https://"+target, "fixture-token", RegisterRequest{})
				for _, err := range []error{pollErr, enrollErr} {
					if err == nil {
						t.Fatal("request succeeded despite proxy refusal")
					}
					for _, marker := range []string{"proxy-body-marker", "proxy-header-marker", "fixture-token", "fixture-password"} {
						if strings.Contains(err.Error(), marker) {
							t.Fatal("proxy response or credentials exposed in error")
						}
					}
				}
				if requests.Load() != before {
					t.Fatal("backend reached despite proxy refusal")
				}
			})
		}
	})
}

func newConnectProxy(t *testing.T, target, upstreamAddr string) (*url.URL, *atomic.Int32) {
	t.Helper()
	var connections atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		connections.Add(1)
		if r.Method != http.MethodConnect || r.Host != target {
			t.Error("unexpected CONNECT destination")
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		if r.Header.Get("Authorization") != "" || r.Header.Get("Signature") != "" {
			t.Error("backend credentials exposed in CONNECT")
		}
		want := "Basic " + base64.StdEncoding.EncodeToString([]byte("fixture-user:fixture-password"))
		if r.Header.Get("Proxy-Authorization") != want {
			w.Header().Set("Proxy-Authenticate", `Basic realm="proxy-header-marker"`)
			http.Error(w, "proxy-body-marker\nforged log entry", http.StatusProxyAuthRequired)
			return
		}
		upstream, err := net.DialTimeout("tcp", upstreamAddr, 3*time.Second)
		if err != nil {
			t.Error(err)
			w.WriteHeader(http.StatusBadGateway)
			return
		}
		defer upstream.Close()
		downstream, buffered, err := w.(http.Hijacker).Hijack()
		if err != nil {
			t.Error(err)
			return
		}
		defer downstream.Close()
		_ = downstream.SetDeadline(time.Now().Add(10 * time.Second))
		_ = upstream.SetDeadline(time.Now().Add(10 * time.Second))
		if _, err := buffered.WriteString("HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
			t.Error(err)
			return
		}
		if err := buffered.Flush(); err != nil {
			t.Error(err)
			return
		}
		done := make(chan struct{})
		go func() {
			defer close(done)
			_, _ = io.Copy(upstream, buffered)
			_ = upstream.Close()
		}()
		_, _ = io.Copy(downstream, upstream)
		_ = downstream.Close()
		<-done
	}))
	t.Cleanup(server.Close)
	proxyURL, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	proxyURL.User = url.UserPassword("fixture-user", "fixture-password")
	return proxyURL, &connections
}
