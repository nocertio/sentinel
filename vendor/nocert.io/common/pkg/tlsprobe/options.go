package tlsprobe

import (
	"context"
	"net"
	"time"
)

const (
	DefaultConnectTimeout   = 5 * time.Second
	DefaultHandshakeTimeout = 5 * time.Second

	MaxChainDepth = 10
	// MaxCertSize is the per-certificate upper bound applied right after
	// the TLS handshake. 64 KiB covers the corpus of real-world certs
	// (peaks at 4.5 KiB) with ample headroom plus post-quantum sigs
	// starting to appear in 2026 (ML-DSA-87 leaves ~12-14 KiB with SCTs,
	// SLH-DSA-128f ~17 KiB), and accommodates enterprise weirdness (long
	// policy/EKU/SAN trees). Must stay equal to the backend parser's max
	// DER size and nocert-sentinel's MaxCertSize - drift means a
	// probe ships a cert the parser refuses, or vice versa.
	MaxCertSize = 65536 // 64 KiB
)

// ContextDialer is the subset of net.Dialer used by Probe and CheckHSTS.
// *net.Dialer and *netguard.Dialer both satisfy it naturally.
type ContextDialer interface {
	DialContext(ctx context.Context, network, addr string) (net.Conn, error)
}

type Options struct {
	ConnectTimeout   time.Duration
	HandshakeTimeout time.Duration
	ServerName       string // SNI override; defaults to host

	// Dialer is used for the initial TCP connection. Required - nil returns
	// an error. Pass a plain *net.Dialer for unrestricted access, or a
	// *netguard.Dialer to refuse non-public IPs.
	Dialer ContextDialer
}

func (opts Options) withDefaults() Options {
	if opts.ConnectTimeout <= 0 {
		opts.ConnectTimeout = DefaultConnectTimeout
	}
	if opts.HandshakeTimeout <= 0 {
		opts.HandshakeTimeout = DefaultHandshakeTimeout
	}
	return opts
}

// DialContext applies a connection budget, allowing dialers with a local
// admission queue to exclude that wait from the DNS/TCP timeout.
func DialContext(ctx context.Context, dialer ContextDialer, network, addr string, timeout time.Duration) (net.Conn, error) {
	if d, ok := dialer.(interface {
		DialContextWithTimeout(context.Context, string, string, time.Duration) (net.Conn, error)
	}); ok {
		return d.DialContextWithTimeout(ctx, network, addr, timeout)
	}
	if timeout <= 0 {
		return dialer.DialContext(ctx, network, addr)
	}
	dialCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	return dialer.DialContext(dialCtx, network, addr)
}
