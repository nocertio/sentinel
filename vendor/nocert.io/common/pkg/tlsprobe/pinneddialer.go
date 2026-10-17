package tlsprobe

import (
	"context"
	"fmt"
	"net"
	"time"
)

// PinnedDialer wraps a ContextDialer and forces every DialContext to connect to
// a fixed, already-resolved peer IP: it ignores the host in the requested
// address but preserves its port. It exists so the post-probe stages
// (CheckHSTS, tlsenum) reach the SAME server the fast probe observed - a
// round-robin / split-horizon FQDN would otherwise resolve each stage
// independently to a different backend, binding a certificate to TLS parameters
// measured on another host.
//
// The caller keeps passing the FQDN as the address ("fqdn:port"), so the SNI
// and HTTP Host header still carry the FQDN and virtual-hosted endpoints serve
// the right certificate - only the TCP destination is pinned.
//
// The pinned IP is validated at construction. The wrapped dialer still runs on
// the rewritten "ip:port" address, so a netguard.Dialer underneath re-validates
// the literal IP and refuses non-public addresses on the Internet path.
type PinnedDialer struct {
	inner ContextDialer
	ip    string // canonical net.IP string (IPv4 or IPv6)
}

// NewPinnedDialer returns a PinnedDialer pinned to peerIP. It errors on a nil
// inner dialer or an unparseable IP (v4 or v6).
func NewPinnedDialer(inner ContextDialer, peerIP string) (*PinnedDialer, error) {
	if inner == nil {
		return nil, fmt.Errorf("tlsprobe: PinnedDialer requires a non-nil inner dialer")
	}
	ip := net.ParseIP(peerIP)
	if ip == nil {
		return nil, fmt.Errorf("tlsprobe: PinnedDialer requires a valid peer IP, got %q", peerIP)
	}
	return &PinnedDialer{inner: inner, ip: ip.String()}, nil
}

// DialContext dials the pinned IP on the port taken from addr, delegating to the
// wrapped dialer. The host portion of addr is discarded.
func (d *PinnedDialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	_, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, fmt.Errorf("tlsprobe: PinnedDialer: invalid address %q: %w", addr, err)
	}
	return d.inner.DialContext(ctx, network, net.JoinHostPort(d.ip, port))
}

func (d *PinnedDialer) DialContextWithTimeout(ctx context.Context, network, addr string, timeout time.Duration) (net.Conn, error) {
	_, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, fmt.Errorf("tlsprobe: PinnedDialer: invalid address %q: %w", addr, err)
	}
	return DialContext(ctx, d.inner, network, net.JoinHostPort(d.ip, port), timeout)
}
