package scanner

import (
	"context"
	"net"
	"time"

	"nocert.io/common/pkg/certinfo"
	"nocert.io/common/pkg/tlsconst"
	"nocert.io/common/pkg/tlsenum"
	"nocert.io/common/pkg/tlsprobe"
)

func (p *tlsProber) Probe(ctx context.Context, host string, port int, timeout time.Duration, serverName string) (*tlsprobe.Result, error) {
	base := p.dialer
	if base == nil {
		base = &net.Dialer{}
	}
	base = upgradeDialer{base: base}
	dialer := &peerDialer{base: base}
	result, err := tlsprobe.Probe(ctx, host, port, tlsprobe.Options{
		DisableALPN: true, ConnectTimeout: timeout, HandshakeTimeout: timeout, ServerName: serverName, Dialer: dialer,
	})
	if result != nil {
		actualSNI := serverName
		if actualSNI == "" {
			actualSNI = host
		}
		if net.ParseIP(actualSNI) != nil {
			actualSNI = ""
		}
		result.ObservedServerName = &actualSNI
	}
	if err == nil || dialer.peerIP == "" || ctx.Err() != nil {
		return result, err
	}
	pinned, pinErr := tlsprobe.NewPinnedDialer(base, dialer.peerIP)
	if pinErr != nil {
		return nil, err
	}
	if serverName == "" {
		serverName = host
	}
	collected, _ := tlsenum.Collect(ctx, host, port, serverName, tlsenum.Options{DisableALPN: true, Dialer: pinned, HandshakeTimeout: timeout})
	if collected == nil {
		return nil, err
	}
	return collectionResult(collected), nil
}

func collectionResult(c *tlsenum.Collection) *tlsprobe.Result {
	complete := false
	obs := &certinfo.TLSObservation{
		TLSVersionID: &c.Version, TLSVersion: tlsconst.VersionString(c.Version),
		HandshakeComplete: &complete, DHBits: uint16(c.DHBits), SSL2CipherSpecs: c.SSL2Ciphers,
	}
	if c.Version != 0x0002 {
		obs.CipherSuiteID, obs.CipherSuite = &c.Cipher, tlsconst.CipherName(c.Cipher)
	}
	return &tlsprobe.Result{PeerIP: c.PeerIP, RawChain: c.Certificates, ObservedServerName: &c.ServerName, TLS: obs}
}

// peerDialer records the actual first peer without consuming admission wait as
// connection time. Subsequent collection attempts are pinned to that address.
type peerDialer struct {
	base   tlsprobe.ContextDialer
	peerIP string
}

func (d *peerDialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	return d.DialContextWithTimeout(ctx, network, addr, 0)
}

func (d *peerDialer) DialContextWithTimeout(ctx context.Context, network, addr string, timeout time.Duration) (net.Conn, error) {
	conn, err := tlsprobe.DialContext(ctx, d.base, network, addr, timeout)
	if err == nil {
		if remote, ok := conn.RemoteAddr().(*net.TCPAddr); ok {
			d.peerIP = remote.IP.String()
		}
	}
	return conn, err
}

func resultFingerprint(r *tlsprobe.Result) string {
	if len(r.RawChain) > 0 {
		return Fingerprint(r.RawChain[0])
	}
	if r.Certificate != nil {
		return r.Certificate.Fingerprint
	}
	return ""
}
