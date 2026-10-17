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

// DefaultALPN is the ALPN protocol list advertised by Probe in the
// ClientHello. Real HTTPS servers (nginx, apache, caddy, IIS, Go's
// stdlib) negotiate one of these; non-HTTP TLS services (SMTPS, IMAPS,
// LDAPS, DoT, AMQPS) leave NegotiatedProtocol empty. Test servers and
// any code that wants to mirror Probe's offer should use this list.
var DefaultALPN = []string{"h2", "http/1.1"}

// legacyCipherSuites is the explicit ≤TLS 1.2 cipher-suite offer used by the
// inventory handshake: the union of Go's secure and INSECURE ≤1.2 suites
// (strong ones first), deduplicated. Offering the weak suites (RSA key
// exchange, CBC-SHA, 3DES/RC4 where the toolchain still exposes them) is
// deliberate - this is a read-only inventory probe with InsecureSkipVerify
// that sends no credentials and no application data. The goal is only to
// complete a handshake with a legacy-only endpoint so its certificate and
// negotiated version become observable; a permissive offer maximises the set
// of legacy servers we can inventory, and the confidentiality of the (empty)
// payload is irrelevant. TLS 1.3 suites are intentionally excluded: crypto/tls
// ignores CipherSuites for TLS 1.3, so listing them would be meaningless.
var legacyCipherSuites = buildLegacyCipherSuites()

func buildLegacyCipherSuites() []uint16 {
	tls13 := map[uint16]bool{
		tls.TLS_AES_128_GCM_SHA256:       true,
		tls.TLS_AES_256_GCM_SHA384:       true,
		tls.TLS_CHACHA20_POLY1305_SHA256: true,
	}
	seen := make(map[uint16]bool)
	ids := make([]uint16, 0, 32)
	add := func(suites []*tls.CipherSuite) {
		for _, s := range suites {
			if tls13[s.ID] || seen[s.ID] {
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

	tlsConn := tls.Client(tcpConn, &tls.Config{
		InsecureSkipVerify: true,
		ServerName:         serverName,
		NextProtos:         DefaultALPN,
		// Inventory probe: negotiate down to TLS 1.0 so a legacy-only endpoint
		// is still observed (cert + negotiated version) instead of vanishing.
		// MaxVersion stays unset, so TLS 1.3 remains enabled and preferred with
		// modern servers. CipherSuites offers the explicit ≤1.2 legacy set; it
		// has no effect on the (non-configurable) TLS 1.3 suites Go negotiates.
		MinVersion:   tls.VersionTLS10,
		CipherSuites: legacyCipherSuites,
		// CurvePreferences is intentionally left unset. An explicit list can only
		// SUBTRACT from Go's default (crypto/tls ignores the list order and just
		// filters the default down to it), so pinning one silently drops any group
		// not enumerated - including the post-quantum ML-KEM hybrids Go enables by
		// default (X25519MLKEM768 since 1.24; SecP256r1MLKEM768 + SecP384r1MLKEM1024
		// since 1.26) and any future group. For an inventory probe that must OBSERVE
		// PQC key exchange, tracking the default is correct and picks up new groups
		// with no code change. (This does not enlarge the ClientHello: Go leads the
		// default with X25519MLKEM768, so the big keyshare is sent either way.)
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
	return &certinfo.TLSObservation{
		TLSVersion:      tlsconst.VersionString(state.Version),
		CipherSuite:     tlsconst.CipherName(state.CipherSuite),
		NegotiatedGroup: tlsconst.GroupString(state.CurveID),
		OCSPStapling:    len(state.OCSPResponse) > 0,
	}
}
