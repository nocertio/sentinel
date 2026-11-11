package tlsprobe

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"strconv"

	"nocert.io/common/pkg/certinfo"
	"nocert.io/common/pkg/tlsconst"
)

// DefaultALPN is the HTTP protocol list advertised by Probe. Inventory callers
// can set DisableALPN to avoid excluding services with other application protocols.
var DefaultALPN = []string{"h2", "http/1.1"}

// legacyCipherSuites offers all TLS <= 1.2 suites supported by crypto/tls,
// including weak suites needed to inventory legacy endpoints. The probe sends
// no credentials or application data. TLS 1.3 suites are controlled by Go.
var legacyCipherSuites = buildLegacyCipherSuites()

func buildLegacyCipherSuites() []uint16 {
	seen := make(map[uint16]bool)
	ids := make([]uint16, 0, 32)
	add := func(suites []*tls.CipherSuite) {
		for _, s := range suites {
			legacy := false
			for _, v := range s.SupportedVersions {
				if v <= tls.VersionTLS12 {
					legacy = true
				}
			}
			if !legacy || seen[s.ID] {
				continue
			}
			seen[s.ID] = true
			ids = append(ids, s.ID)
		}
	}
	add(tls.CipherSuites())         // secure/recommended suites first
	add(tls.InsecureCipherSuites()) // then RSA-kx, CBC-SHA, 3DES/RC4 for legacy inventory
	return ids
}

type Result struct {
	// RawChain is set by collectors that do not parse X.509.
	RawChain           [][]byte
	ObservedServerName *string

	Certificate *certinfo.CertificateInfo
	Chain       []certinfo.ChainEntry
	TLS         *certinfo.TLSObservation
	// PeerCerts is the presented chain, capped at MaxChainDepth and dropping any
	// cert over MaxCertSize - the same set fed to Chain.
	PeerCerts []*x509.Certificate
	// PeerIP is the resolved IP the TCP connection reached, from RemoteAddr.
	PeerIP string
	// NegotiatedProtocol is the ALPN value the server selected; empty if none.
	NegotiatedProtocol string
}

func Probe(ctx context.Context, host string, port int, opts Options) (*Result, error) {
	if opts.Dialer == nil {
		return nil, fmt.Errorf("tlsprobe: Options.Dialer is required")
	}
	opts = opts.withDefaults()

	addr := net.JoinHostPort(host, strconv.Itoa(port))
	serverName := opts.ServerName
	if serverName == "" {
		serverName = host
	}

	tcpConn, err := DialContext(ctx, opts.Dialer, "tcp", addr, opts.ConnectTimeout)
	if err != nil {
		return nil, fmt.Errorf("dial %s: %w", addr, err)
	}

	var peerIP string
	if tcpAddr, ok := tcpConn.RemoteAddr().(*net.TCPAddr); ok && tcpAddr != nil && tcpAddr.IP != nil {
		peerIP = tcpAddr.IP.String()
	}

	alpn := DefaultALPN
	if opts.DisableALPN {
		alpn = nil
	}
	tlsConn := tls.Client(tcpConn, &tls.Config{
		InsecureSkipVerify: true,
		ServerName:         serverName,
		NextProtos:         alpn,
		// Inventory probe: negotiate down to TLS 1.0 so a legacy-only endpoint
		// is still observed (cert + negotiated version) instead of vanishing.
		// MaxVersion stays unset, so TLS 1.3 remains enabled and preferred with
		// modern servers. CipherSuites offers the explicit ≤1.2 legacy set; it
		// has no effect on the (non-configurable) TLS 1.3 suites Go negotiates.
		MinVersion:   tls.VersionTLS10,
		CipherSuites: legacyCipherSuites,
		// Use Go's default groups to observe exchanges supported by the active
		// toolchain, including newly supported post-quantum groups.
	})

	handshakeCtx, handshakeCancel := context.WithTimeout(ctx, opts.HandshakeTimeout)
	defer handshakeCancel()

	handshakeErr := tlsConn.HandshakeContext(handshakeCtx)
	defer tcpConn.Close()

	state := tlsConn.ConnectionState()

	if len(state.PeerCertificates) == 0 {
		if handshakeErr != nil {
			return nil, fmt.Errorf("tls handshake %s: %w", addr, handshakeErr)
		}
		return nil, fmt.Errorf("no certificates presented by %s", addr)
	}

	leaf := state.PeerCertificates[0]

	if len(leaf.Raw) > MaxCertSize {
		return nil, fmt.Errorf("certificate from %s exceeds size limit (%d > %d bytes)",
			addr, len(leaf.Raw), MaxCertSize)
	}

	peerCerts := state.PeerCertificates
	if len(peerCerts) > MaxChainDepth {
		peerCerts = peerCerts[:MaxChainDepth]
	}

	var validChainCerts []*x509.Certificate
	for _, c := range peerCerts {
		if len(c.Raw) <= MaxCertSize {
			validChainCerts = append(validChainCerts, c)
		}
	}

	complete := handshakeErr == nil
	tlsObs := extractTLSObservation(&state)
	tlsObs.HandshakeComplete = &complete
	result := &Result{
		Certificate:        certinfo.FromX509(leaf),
		Chain:              certinfo.ChainFromX509(validChainCerts),
		TLS:                tlsObs,
		PeerCerts:          validChainCerts,
		PeerIP:             peerIP,
		NegotiatedProtocol: state.NegotiatedProtocol,
	}

	return result, nil
}

func extractTLSObservation(state *tls.ConnectionState) *certinfo.TLSObservation {
	version, cipher, group := state.Version, state.CipherSuite, uint16(state.CurveID)
	return &certinfo.TLSObservation{
		TLSVersion:   tlsconst.VersionString(state.Version),
		TLSVersionID: &version, CipherSuiteID: &cipher, NegotiatedGroupID: &group,
		CipherSuite:     tlsconst.CipherName(state.CipherSuite),
		NegotiatedGroup: tlsconst.GroupString(state.CurveID),
		OCSPStapling:    len(state.OCSPResponse) > 0,
	}
}
