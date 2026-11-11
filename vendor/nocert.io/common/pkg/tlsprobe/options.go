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
	// MaxCertSize bounds each certificate after the handshake. Keep it aligned
	// with the certparser and Sentinel DER limits, including post-quantum keys.
	MaxCertSize = 65536 // 64 KiB
)

// ContextDialer is the subset of net.Dialer used by Probe and CheckHSTS.
// *net.Dialer and *netguard.Dialer both satisfy it naturally.
type ContextDialer interface {
	DialContext(ctx context.Context, network, addr string) (net.Conn, error)
}

type Options struct {
	// DisableALPN makes certificate discovery independent of HTTP negotiation.
	DisableALPN      bool
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
