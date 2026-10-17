package tlsprobe

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// CheckHSTS performs a plain HTTPS GET of "/" and returns whether the response
// advertises Strict-Transport-Security with a non-negative max-age.
//
// Requires opts.Dialer (same contract as Probe). The HTTP client uses that
// dialer so HSTS shares the SSRF protection of Probe. Redirects are not
// followed. Total budget = ConnectTimeout + HandshakeTimeout + 5s read.
func CheckHSTS(ctx context.Context, host string, port int, opts Options) (enabled bool, maxAge int, err error) {
	if opts.Dialer == nil {
		return false, 0, fmt.Errorf("tlsprobe: Options.Dialer is required")
	}
	opts = opts.withDefaults()

	u := &url.URL{
		Scheme: "https",
		Host:   net.JoinHostPort(host, strconv.Itoa(port)),
		Path:   "/",
	}

	transport := &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return DialContext(ctx, opts.Dialer, network, addr, opts.ConnectTimeout)
		},
		ResponseHeaderTimeout:  5 * time.Second,
		MaxResponseHeaderBytes: 64 << 10,
		TLSHandshakeTimeout:    opts.HandshakeTimeout,
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
			NextProtos:         []string{"http/1.1"},
		},
	}
	defer transport.CloseIdleConnections()

	client := &http.Client{
		Timeout:   opts.ConnectTimeout + opts.HandshakeTimeout + 5*time.Second,
		Transport: transport,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return false, 0, fmt.Errorf("build HSTS request: %w", err)
	}

	resp, err := client.Do(req)
	if err != nil {
		return false, 0, fmt.Errorf("HSTS request to %s: %w", u.Host, err)
	}
	defer resp.Body.Close()

	header := resp.Header.Get("Strict-Transport-Security")
	if header == "" {
		return false, 0, nil
	}
	return parseHSTSHeader(header)
}

// parseHSTSHeader returns (enabled, maxAge, err). The header is considered
// enabled only if a non-negative max-age directive is present.
func parseHSTSHeader(header string) (bool, int, error) {
	var maxAge int
	var found bool
	for _, part := range strings.Split(header, ";") {
		part = strings.TrimSpace(part)
		const prefix = "max-age="
		if !strings.HasPrefix(strings.ToLower(part), prefix) {
			continue
		}
		val := part[len(prefix):]
		val = strings.Trim(val, `"`)
		n, err := strconv.Atoi(val)
		if err != nil {
			return false, 0, fmt.Errorf("invalid max-age %q: %w", val, err)
		}
		if n < 0 {
			// RFC 6797 says negative is invalid; treat header as absent.
			return false, 0, nil
		}
		maxAge = n
		found = true
	}
	if !found {
		// Per RFC 6797, max-age is REQUIRED. A header without max-age is
		// malformed - treat as not enabled.
		return false, 0, nil
	}
	return true, maxAge, nil
}
