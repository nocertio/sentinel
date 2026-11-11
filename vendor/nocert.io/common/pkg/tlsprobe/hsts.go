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
	// Invalid policy syntax is a completed measurement, not a network failure.
	// Return the negative observation so callers replace stale positive evidence.
	enabled, age, _ := parseHSTSHeader(header)
	return enabled, age, nil
}

// parseHSTSHeader validates RFC 6797 section 6.1. The boolean means a valid
// policy header was observed, including max-age=0 (which disables HSTS).
// Durations saturate at 2^31-1 seconds to keep the existing int wire field
// consistent across architectures. Unknown, syntactically valid directives
// are ignored. Duplicate directives invalidate the entire header.
func parseHSTSHeader(header string) (bool, int, error) {
	invalid := func() (bool, int, error) { return false, 0, fmt.Errorf("invalid HSTS policy") }
	seen := make(map[string]bool)
	var maxAge int
	for rest := header; ; {
		rest = strings.TrimLeft(rest, " \t;")
		if rest == "" {
			break
		}
		i := 0
		for i < len(rest) && hstsTokenByte(rest[i]) {
			i++
		}
		if i == 0 {
			return invalid()
		}
		name := strings.ToLower(rest[:i])
		if seen[name] {
			return invalid()
		}
		seen[name] = true
		rest = strings.TrimLeft(rest[i:], " \t")
		value, hasValue := "", false
		if strings.HasPrefix(rest, "=") {
			hasValue = true
			var ok bool
			value, rest, ok = hstsValue(strings.TrimLeft(rest[1:], " \t"))
			if !ok {
				return invalid()
			}
			rest = strings.TrimLeft(rest, " \t")
		}
		if rest != "" && rest[0] != ';' {
			return invalid()
		}
		switch name {
		case "max-age":
			if !hasValue || value == "" {
				return invalid()
			}
			for _, c := range []byte(value) {
				if c < '0' || c > '9' {
					return invalid()
				}
				if maxAge < 2147483647 {
					// Use int64 for the intermediate product on 32-bit hosts.
					maxAge = int(min(int64(maxAge)*10+int64(c-'0'), 2147483647))
				}
			}
		case "includesubdomains":
			if hasValue {
				return invalid()
			}
		}
	}
	if !seen["max-age"] {
		return false, 0, nil
	}
	return true, maxAge, nil
}

func hstsTokenByte(c byte) bool {
	return c > 32 && c < 127 && !strings.ContainsRune("()<>@,;:\"/[]?={}\\", rune(c))
}

// hstsValue reads a token or quoted-string, including quoted-pair escaping.
// Separators inside quoted unknown directives must not split the policy.
func hstsValue(s string) (value, rest string, ok bool) {
	if s == "" {
		return "", "", false
	}
	if s[0] != '"' {
		i := 0
		for i < len(s) && hstsTokenByte(s[i]) {
			i++
		}
		return s[:i], s[i:], i > 0
	}
	var b strings.Builder
	for i := 1; i < len(s); i++ {
		c := s[i]
		if c == '"' {
			return b.String(), s[i+1:], true
		}
		if c == '\\' {
			i++
			if i == len(s) {
				return "", "", false
			}
			c = s[i]
		}
		if (c < 32 && c != '\t') || c == 127 {
			return "", "", false
		}
		b.WriteByte(c)
	}
	return "", "", false
}
