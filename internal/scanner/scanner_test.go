package scanner

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"log/slog"
	"math/big"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	commonsentinel "nocert.io/common/pkg/api/sentinel"
	"nocert.io/common/pkg/certinfo"
	"nocert.io/common/pkg/tlsprobe"
)

// generateTestCA creates a self-signed CA certificate and key pair for testing.
func generateTestCA() (certPEM []byte, keyPEM []byte, cert *x509.Certificate, key *ecdsa.PrivateKey) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic("generate CA key: " + err.Error())
	}
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	template := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{Organization: []string{"NoCert Test CA"}, CommonName: "NoCert Test CA"},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		panic("create CA cert: " + err.Error())
	}
	cert, _ = x509.ParseCertificate(certDER)
	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyDER, _ := x509.MarshalECPrivateKey(key)
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	return
}

// generateTestLeaf creates a leaf certificate signed by the given CA.
func generateTestLeaf(ca *x509.Certificate, caKey *ecdsa.PrivateKey, hosts ...string) (certPEM []byte, keyPEM []byte) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic("generate leaf key: " + err.Error())
	}
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{Organization: []string{"NoCert Test"}, CommonName: "test-leaf"},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
	}
	for _, h := range hosts {
		if ip := net.ParseIP(h); ip != nil {
			template.IPAddresses = append(template.IPAddresses, ip)
		} else {
			template.DNSNames = append(template.DNSNames, h)
		}
	}
	certDER, err := x509.CreateCertificate(rand.Reader, template, ca, &key.PublicKey, caKey)
	if err != nil {
		panic("create leaf cert: " + err.Error())
	}
	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyDER, _ := x509.MarshalECPrivateKey(key)
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	return
}

// startTLSServer starts a TLS server on a random port and returns its address.
func startTLSServer(t *testing.T) string {
	t.Helper()

	_, _, caCert, caKey := generateTestCA()
	certPEM, keyPEM := generateTestLeaf(caCert, caKey, "127.0.0.1", "localhost")

	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	require.NoError(t, err)

	listener, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{cert},
	})
	require.NoError(t, err)

	t.Cleanup(func() { _ = listener.Close() })

	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			// Complete the handshake then close
			tlsConn := conn.(*tls.Conn)
			_ = tlsConn.Handshake()
			_ = tlsConn.Close()
		}
	}()

	return listener.Addr().String()
}

// makeTestCert generates a self-signed cert for use in mock probe results.
// Returns the parsed cert and its DER bytes.
func makeTestCert(t *testing.T) (*x509.Certificate, []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "mock"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	return cert, der
}

func TestScanLocalTLSServer(t *testing.T) {
	addr := startTLSServer(t)
	host, portStr, _ := net.SplitHostPort(addr)
	var port int
	_, err := fmt.Sscanf(portStr, "%d", &port)
	require.NoError(t, err)

	s := New(slog.Default())

	result, err := s.Scan(context.Background(), ScanConfig{
		IPRanges: []string{host + "/32"},
		Ports:    []int{port},
		Timeout:  5 * time.Second,
	})
	require.NoError(t, err)
	require.NotNil(t, result)

	assert.NotEmpty(t, result.ScanID)
	assert.False(t, result.StartedAt.IsZero())
	assert.False(t, result.CompletedAt.IsZero())

	require.Len(t, result.NetworkObservations, 1)
	obs := result.NetworkObservations[0]
	assert.Equal(t, host, obs.IP)
	assert.Equal(t, port, obs.Port)
	assert.NotEmpty(t, obs.ObservedChainFingerprints)
	assert.NotEmpty(t, result.Certificates)
}

func TestScanConnectionRefused(t *testing.T) {
	s := New(slog.Default())

	result, err := s.Scan(context.Background(), ScanConfig{
		IPRanges: []string{"127.0.0.1/32"},
		Ports:    []int{1}, // port 1 is unlikely to be listening
		Timeout:  1 * time.Second,
	})
	require.NoError(t, err)

	assert.Empty(t, result.NetworkObservations)
	assert.Empty(t, result.Certificates)
}

func TestScanContextCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel immediately

	s := New(slog.Default())

	result, err := s.Scan(ctx, ScanConfig{
		IPRanges: []string{"10.0.0.0/24"},
		Ports:    []int{443},
		Timeout:  5 * time.Second,
	})

	// Should return partial results and the cancellation error
	assert.ErrorIs(t, err, context.Canceled)
	assert.NotNil(t, result)
}

func TestScanInvalidCIDR(t *testing.T) {
	s := New(slog.Default())

	result, err := s.Scan(context.Background(), ScanConfig{
		IPRanges: []string{"not-a-cidr"},
		Ports:    []int{443},
		Timeout:  1 * time.Second,
	})
	require.NoError(t, err)

	// Invalid CIDR is skipped, no targets to scan
	assert.Empty(t, result.NetworkObservations)
}

// mockProber is used for unit testing the Scanner without real network calls.
type mockProber struct {
	results map[string]*tlsprobe.Result
	errors  map[string]error
}

func (m *mockProber) Probe(_ context.Context, host string, port int, _ time.Duration, _ string) (*tlsprobe.Result, error) {
	key := fmt.Sprintf("%s:%d", host, port)
	if err, ok := m.errors[key]; ok {
		return nil, err
	}
	if r, ok := m.results[key]; ok {
		// Mirror real tlsprobe: PeerIP comes from the resolved TCP RemoteAddr.
		// Test fixtures pass IP literals in `host`, so default PeerIP = host.
		if r.PeerIP == "" {
			r.PeerIP = host
		}
		return r, nil
	}
	return nil, fmt.Errorf("connection refused")
}

func TestScanWithMockProber(t *testing.T) {
	_, der := makeTestCert(t)
	prober := &mockProber{
		results: map[string]*tlsprobe.Result{
			"10.0.0.1:443": {
				Certificate: &certinfo.CertificateInfo{
					SubjectCN:   "test.example.com",
					Fingerprint: "AB:CD:EF",
					RawDER:      der,
				},
				TLS: &certinfo.TLSObservation{TLSVersion: "TLSv1.3"},
			},
		},
		errors: map[string]error{
			"10.0.0.2:443": fmt.Errorf("connection timed out"),
		},
	}

	s := NewWithProber(slog.Default(), prober)

	result, err := s.Scan(context.Background(), ScanConfig{
		IPRanges: []string{"10.0.0.0/29"}, // .1 through .6
		Ports:    []int{443},
		Timeout:  1 * time.Second,
	})
	require.NoError(t, err)

	require.Len(t, result.NetworkObservations, 1)
	assert.Equal(t, "10.0.0.1", result.NetworkObservations[0].IP)
	require.Len(t, result.Certificates, 1)
}

// TestScanHostname_IPFromPeerIP guarantees the FQDN-target path reports
// the resolved peer IP in NetworkObservation.IP, never the input FQDN.
// The backend's `observations.ip` mapping is strict `type: ip` and
// rejects hostnames.
func TestScanHostname_IPFromPeerIP(t *testing.T) {
	_, der := makeTestCert(t)
	prober := &fqdnMockProber{
		results: map[string]*tlsprobe.Result{
			"shop.example.com:443": {
				Certificate: &certinfo.CertificateInfo{
					SubjectCN:   "shop.example.com",
					Fingerprint: "AB:CD:EF",
					RawDER:      der,
				},
				PeerIP: "192.0.2.42", // resolved IP, distinct from the FQDN
				TLS:    &certinfo.TLSObservation{TLSVersion: "TLSv1.3"},
			},
		},
	}

	s := NewWithProber(slog.Default(), prober)
	resultCh, _ := s.ScanHostname(context.Background(), "shop.example.com", []int{443}, time.Second, false)

	var outputs []ProbeOutput
	for out := range resultCh {
		outputs = append(outputs, out)
	}
	require.Len(t, outputs, 1)
	assert.Equal(t, "192.0.2.42", outputs[0].IP, "IP must be the resolved PeerIP, never the input FQDN")
}

// TestProbeResultToOutput_DropsEmptyPeerIP ensures we never emit an
// observation without a real peer IP (defensive - the backend would
// reject it anyway, but better to skip at the source).
func TestProbeResultToOutput_DropsEmptyPeerIP(t *testing.T) {
	_, der := makeTestCert(t)
	s := NewWithProber(slog.Default(), &noPeerIPProber{cert: der})
	result, err := s.Scan(context.Background(), ScanConfig{
		IPRanges: []string{"10.0.0.1/32"},
		Ports:    []int{443},
		Timeout:  time.Second,
	})
	require.NoError(t, err)
	assert.Empty(t, result.NetworkObservations, "no observation must be emitted when PeerIP is empty")
}

// TestProbeResultToOutput_AttachesCipherEnumeration verifies that when
// the caller passes a non-nil findings slice (deep enum was run for
// this target), CipherEnumeration is set on the emitted observation -
// regardless of whether the fast probe returned a TLS sub-struct.
func TestProbeResultToOutput_AttachesCipherEnumeration(t *testing.T) {
	_, der := makeTestCert(t)
	s := NewWithProber(slog.Default(), nil)

	findings := []commonsentinel.CipherFinding{
		{Version: "TLSv1.2", Cipher: "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"},
	}

	t.Run("with TLS sub-struct", func(t *testing.T) {
		out := s.probeResultToOutput(443, "", &tlsprobe.Result{
			Certificate: &certinfo.CertificateInfo{Fingerprint: "FE:ED", RawDER: der},
			PeerIP:      "203.0.113.1",
			TLS:         &certinfo.TLSObservation{TLSVersion: "TLS 1.2"},
		}, findings, true)
		require.NotNil(t, out)
		require.NotNil(t, out.TLS)
		assert.Equal(t, findings, out.TLS.CipherEnumeration)
		assert.True(t, out.TLS.DeepEnumAttempted)
		assert.Equal(t, "TLS 1.2", out.TLS.TLSVersion)
	})

	t.Run("no TLS sub-struct still attaches enum", func(t *testing.T) {
		out := s.probeResultToOutput(443, "", &tlsprobe.Result{
			Certificate: &certinfo.CertificateInfo{Fingerprint: "FE:ED", RawDER: der},
			PeerIP:      "203.0.113.1",
		}, findings, true)
		require.NotNil(t, out)
		require.NotNil(t, out.TLS, "enum-only result should still get a TLS sub-struct")
		assert.Equal(t, findings, out.TLS.CipherEnumeration)
		assert.True(t, out.TLS.DeepEnumAttempted)
		assert.Empty(t, out.TLS.TLSVersion, "TLS sub-struct fields stay zero when no fast-probe TLS")
	})

	t.Run("attempted with empty findings stamps flag only", func(t *testing.T) {
		out := s.probeResultToOutput(443, "", &tlsprobe.Result{
			Certificate: &certinfo.CertificateInfo{Fingerprint: "FE:ED", RawDER: der},
			PeerIP:      "203.0.113.1",
			TLS:         &certinfo.TLSObservation{TLSVersion: "TLS 1.3"},
		}, nil, true)
		require.NotNil(t, out)
		require.NotNil(t, out.TLS)
		assert.Empty(t, out.TLS.CipherEnumeration)
		assert.True(t, out.TLS.DeepEnumAttempted, "TLS-1.3-only path: flag must persist so the backend stamps last_cipher_enum_at")
	})

	t.Run("not attempted keeps enum + flag clear", func(t *testing.T) {
		out := s.probeResultToOutput(443, "", &tlsprobe.Result{
			Certificate: &certinfo.CertificateInfo{Fingerprint: "FE:ED", RawDER: der},
			PeerIP:      "203.0.113.1",
			TLS:         &certinfo.TLSObservation{TLSVersion: "TLS 1.2"},
		}, nil, false)
		require.NotNil(t, out)
		require.NotNil(t, out.TLS)
		assert.Nil(t, out.TLS.CipherEnumeration)
		assert.False(t, out.TLS.DeepEnumAttempted)
	})

	t.Run("leaf not duplicated when result.Chain includes it", func(t *testing.T) {
		// tlsprobe.Result.Chain is the full presented chain (leaf first, from
		// PeerCerts); result.Certificate is that same leaf. The output must carry
		// the leaf ONCE, never duplicated.
		intermediate := []byte{0x30, 0x02, 0xAA, 0xBB}
		out := s.probeResultToOutput(443, "", &tlsprobe.Result{
			Certificate: &certinfo.CertificateInfo{Fingerprint: "FE:ED", RawDER: der},
			Chain: []certinfo.ChainEntry{
				{RawDER: der},          // leaf, as presented at index 0
				{RawDER: intermediate}, // intermediate
			},
			PeerIP: "203.0.113.1",
		}, nil, false)
		require.NotNil(t, out)
		require.Len(t, out.Chain, 2, "leaf must appear once, not duplicated")
		assert.Equal(t, der, out.Chain[0])
		assert.Equal(t, intermediate, out.Chain[1])
	})
}

// fqdnMockProber keys on "host:port" without auto-populating PeerIP, so
// tests can assert what happens when the result carries a distinct
// PeerIP (FQDN-target scenario).
type fqdnMockProber struct {
	results map[string]*tlsprobe.Result
}

func (m *fqdnMockProber) Probe(_ context.Context, host string, port int, _ time.Duration, _ string) (*tlsprobe.Result, error) {
	key := fmt.Sprintf("%s:%d", host, port)
	if r, ok := m.results[key]; ok {
		return r, nil
	}
	return nil, fmt.Errorf("connection refused")
}

// noPeerIPProber always returns a successful probe with an empty PeerIP.
type noPeerIPProber struct {
	cert []byte
}

func (p *noPeerIPProber) Probe(_ context.Context, _ string, _ int, _ time.Duration, _ string) (*tlsprobe.Result, error) {
	return &tlsprobe.Result{
		Certificate: &certinfo.CertificateInfo{
			Fingerprint: "FE:ED:FA:CE",
			RawDER:      p.cert,
		},
		PeerIP: "",
	}, nil
}

func TestScanLocalTLSServer_FieldsComplete(t *testing.T) {
	addr := startTLSServer(t)
	host, portStr, _ := net.SplitHostPort(addr)
	var port int
	_, err := fmt.Sscanf(portStr, "%d", &port)
	require.NoError(t, err)

	s := New(slog.Default())
	result, err := s.Scan(context.Background(), ScanConfig{
		IPRanges: []string{host + "/32"},
		Ports:    []int{port},
		Timeout:  5 * time.Second,
	})
	require.NoError(t, err)
	require.Len(t, result.NetworkObservations, 1)

	obs := result.NetworkObservations[0]
	assert.NotEmpty(t, obs.ObservedChainFingerprints)
	assert.NotNil(t, obs.TLS)
	assert.NotEmpty(t, obs.TLS.TLSVersion)
}

// sniMockProber keys on "host:port:serverName" to return different certs per SNI.
type sniMockProber struct {
	results map[string]*tlsprobe.Result
}

func (m *sniMockProber) Probe(_ context.Context, host string, port int, _ time.Duration, serverName string) (*tlsprobe.Result, error) {
	key := fmt.Sprintf("%s:%d:%s", host, port, serverName)
	if r, ok := m.results[key]; ok {
		if r.PeerIP == "" {
			r.PeerIP = host
		}
		return r, nil
	}
	return nil, fmt.Errorf("connection refused")
}

func TestSNIReprobing(t *testing.T) {
	// Default cert has "other.example.com" as a SAN - this is what triggers the re-probe
	defaultCert := generateTestCertWithSANs(t, "default.example.com", []string{"other.example.com"})
	sniCert := generateTestCertWithSANs(t, "other.example.com", nil)

	mock := &sniMockProber{
		results: map[string]*tlsprobe.Result{
			// Default probe (empty serverName)
			"10.0.0.1:443:": {
				Certificate: certinfo.FromX509(defaultCert),
				Chain:       nil,
				TLS:         &certinfo.TLSObservation{TLSVersion: "TLSv1.3"},
				PeerCerts:   []*x509.Certificate{defaultCert},
			},
			// Re-probe with "default.example.com" returns same cert (deduplicated)
			"10.0.0.1:443:default.example.com": {
				Certificate: certinfo.FromX509(defaultCert),
				Chain:       nil,
				TLS:         &certinfo.TLSObservation{TLSVersion: "TLSv1.3"},
				PeerCerts:   []*x509.Certificate{defaultCert},
			},
			// Re-probe with "other.example.com" returns a DIFFERENT cert
			"10.0.0.1:443:other.example.com": {
				Certificate: certinfo.FromX509(sniCert),
				Chain:       nil,
				TLS:         &certinfo.TLSObservation{TLSVersion: "TLSv1.3"},
				PeerCerts:   []*x509.Certificate{sniCert},
			},
		},
	}

	scanner := NewWithProber(slog.Default(), mock)
	result, err := scanner.Scan(context.Background(), ScanConfig{
		IPRanges: []string{"10.0.0.1/32"},
		Ports:    []int{443},
		Timeout:  1 * time.Second,
	})

	require.NoError(t, err)
	require.Len(t, result.NetworkObservations, 2)

	// First observation is the default (no SNI)
	assert.Equal(t, "", result.NetworkObservations[0].SNI)
	assert.Equal(t, "10.0.0.1", result.NetworkObservations[0].IP)

	// Second observation found via SNI re-probe
	assert.Equal(t, "other.example.com", result.NetworkObservations[1].SNI)
	assert.Equal(t, "10.0.0.1", result.NetworkObservations[1].IP)

	// Two distinct fingerprints across the two certs
	require.Len(t, result.Certificates, 2)
}

// ScanHostname's primary observation must record the FQDN as its SNI, matching
// the SNI the fast probe sent on the wire.
func TestScanHostname_PrimaryObservationCarriesFQDNAsSNI(t *testing.T) {
	_, der := makeTestCert(t)
	prober := &fqdnMockProber{
		results: map[string]*tlsprobe.Result{
			"shop.example.com:443": {
				Certificate: &certinfo.CertificateInfo{SubjectCN: "shop.example.com", Fingerprint: "AB:CD:EF", RawDER: der},
				PeerIP:      "192.0.2.42",
				TLS:         &certinfo.TLSObservation{TLSVersion: "TLSv1.3"},
			},
		},
	}
	s := NewWithProber(slog.Default(), prober)
	resultCh, _ := s.ScanHostname(context.Background(), "shop.example.com", []int{443}, time.Second, false)

	var outputs []ProbeOutput
	for out := range resultCh {
		outputs = append(outputs, out)
	}
	require.Len(t, outputs, 1)
	assert.Equal(t, "shop.example.com", outputs[0].SNI,
		"ScanHostname's primary observation must record the FQDN as SNI")
}

// startTLS12EnumServer starts a real TLS 1.2+ loopback server (single cert) so a
// pinned cipher enumeration against it finds ciphers. Returns its port.
func startTLS12EnumServer(t *testing.T) int {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(9001),
		Subject:      pkix.Name{CommonName: "enum.local"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}},
		MinVersion:   tls.VersionTLS12,
	})
	require.NoError(t, err)
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			_ = c.(*tls.Conn).Handshake()
			_ = c.Close()
		}
	}()
	_, portStr, _ := net.SplitHostPort(ln.Addr().String())
	var p int
	_, _ = fmt.Sscanf(portStr, "%d", &p)
	return p
}

// A deep enum is pinned to the primary SNI's handshake. An SNI re-probe that
// selects a DIFFERENT certificate may be a different vhost with a different TLS
// policy, so it must NOT inherit the primary's enum - attributing wrong evidence
// is worse than a brief gap the backend's targeted per-SNI DeepEnum then fills.
func TestSNIReprobe_DoesNotInheritServerLevelDeepEnum(t *testing.T) {
	port := startTLS12EnumServer(t)
	primaryCert := generateTestCertWithSANs(t, "primary.local", []string{"alt.example.com"})
	altCert := generateTestCertWithSANs(t, "alt.example.com", nil)

	key := func(sni string) string { return fmt.Sprintf("127.0.0.1:%d:%s", port, sni) }
	mock := &sniMockProber{
		results: map[string]*tlsprobe.Result{
			key(""): {
				Certificate: certinfo.FromX509(primaryCert),
				PeerCerts:   []*x509.Certificate{primaryCert},
				PeerIP:      "127.0.0.1",
				TLS:         &certinfo.TLSObservation{TLSVersion: "TLSv1.2"},
			},
			key("alt.example.com"): {
				Certificate: certinfo.FromX509(altCert),
				PeerCerts:   []*x509.Certificate{altCert},
				PeerIP:      "127.0.0.1",
				TLS:         &certinfo.TLSObservation{TLSVersion: "TLSv1.2"},
			},
		},
	}

	scanner := NewWithProber(slog.Default(), mock)
	result, err := scanner.Scan(context.Background(), ScanConfig{
		IPRanges: []string{"127.0.0.1/32"},
		Ports:    []int{port},
		Timeout:  3 * time.Second,
		DeepEnum: true,
	})
	require.NoError(t, err)
	require.Len(t, result.NetworkObservations, 2)

	var sawPrimary, sawReprobe bool
	for i := range result.NetworkObservations {
		o := result.NetworkObservations[i]
		require.NotNil(t, o.TLS)
		switch o.SNI {
		case "":
			sawPrimary = true
			assert.True(t, o.TLS.DeepEnumAttempted, "primary observation must carry the deep enum")
			assert.NotEmpty(t, o.TLS.CipherEnumeration, "primary enum against a real TLS 1.2 server finds ciphers")
		case "alt.example.com":
			sawReprobe = true
			assert.False(t, o.TLS.DeepEnumAttempted, "the SAN re-probe (different cert) must NOT inherit the primary's enum")
			assert.Empty(t, o.TLS.CipherEnumeration, "no enum evidence must be attributed to the alt-SNI cert")
		}
	}
	assert.True(t, sawPrimary && sawReprobe, "expected both the primary and the SNI re-probe observations")
}

func TestSNIReprobing_WildcardSkipped(t *testing.T) {
	cert := generateTestCertWithSANs(t, "example.com", []string{"*.example.com", "www.example.com"})
	mock := &sniMockProber{
		results: map[string]*tlsprobe.Result{
			"10.0.0.1:443:": {
				Certificate: certinfo.FromX509(cert),
				PeerCerts:   []*x509.Certificate{cert},
			},
			"10.0.0.1:443:example.com": {
				Certificate: certinfo.FromX509(cert),
				PeerCerts:   []*x509.Certificate{cert},
			},
			"10.0.0.1:443:www.example.com": {
				Certificate: certinfo.FromX509(cert),
				PeerCerts:   []*x509.Certificate{cert},
			},
		},
	}

	scanner := NewWithProber(slog.Default(), mock)
	result, err := scanner.Scan(context.Background(), ScanConfig{
		IPRanges: []string{"10.0.0.1/32"},
		Ports:    []int{443},
		Timeout:  1 * time.Second,
	})

	require.NoError(t, err)
	// Only 1 observation - all re-probes return same fingerprint (sentinel
	// scanner deduplicates by fingerprint at the SNI level).
	assert.Len(t, result.NetworkObservations, 1)
	// And only 1 unique cert in the dedup'd list.
	assert.Len(t, result.Certificates, 1)
}

func TestSNIReprobing_DeduplicatesFingerprints(t *testing.T) {
	cert := generateTestCertWithSANs(t, "a.example.com", []string{"b.example.com", "c.example.com"})
	mock := &sniMockProber{
		results: map[string]*tlsprobe.Result{
			"10.0.0.1:443:": {
				Certificate: certinfo.FromX509(cert),
				PeerCerts:   []*x509.Certificate{cert},
			},
			"10.0.0.1:443:a.example.com": {
				Certificate: certinfo.FromX509(cert),
				PeerCerts:   []*x509.Certificate{cert},
			},
			"10.0.0.1:443:b.example.com": {
				Certificate: certinfo.FromX509(cert),
				PeerCerts:   []*x509.Certificate{cert},
			},
			"10.0.0.1:443:c.example.com": {
				Certificate: certinfo.FromX509(cert),
				PeerCerts:   []*x509.Certificate{cert},
			},
		},
	}

	scanner := NewWithProber(slog.Default(), mock)
	result, err := scanner.Scan(context.Background(), ScanConfig{
		IPRanges: []string{"10.0.0.1/32"},
		Ports:    []int{443},
		Timeout:  1 * time.Second,
	})

	require.NoError(t, err)
	assert.Len(t, result.NetworkObservations, 1, "same fingerprint on all SANs should not produce duplicates")
	assert.Len(t, result.Certificates, 1)
}

func generateTestCertWithSANs(t *testing.T, cn string, extraSANs []string) *x509.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	dnsNames := append([]string{cn}, extraSANs...)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: cn},
		DNSNames:     dnsNames,
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
	}
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(certDER)
	require.NoError(t, err)
	return cert
}

// slowMockProber simulates a prober that takes a long time to respond.
type slowMockProber struct {
	delay time.Duration
}

func (p *slowMockProber) Probe(ctx context.Context, host string, port int, timeout time.Duration, serverName string) (*tlsprobe.Result, error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-time.After(p.delay):
		return nil, fmt.Errorf("timeout")
	}
}

func TestScanStream_BasicOperation(t *testing.T) {
	_, der := makeTestCert(t)
	prober := &mockProber{
		results: map[string]*tlsprobe.Result{
			"10.0.0.1:443": {
				Certificate: &certinfo.CertificateInfo{
					SubjectCN:   "test.example.com",
					Fingerprint: "AB:CD:EF",
					RawDER:      der,
				},
			},
		},
	}

	s := NewWithProber(slog.Default(), prober)
	resultCh, meta := s.ScanStream(context.Background(), ScanConfig{
		IPRanges:      []string{"10.0.0.1/32"},
		Ports:         []int{443},
		Timeout:       1 * time.Second,
		Workers:       2,
		MaxConnPerSec: 1000,
	})

	assert.NotEmpty(t, meta.ScanID)
	assert.Equal(t, 1, meta.TotalTargets)

	var results []ProbeOutput
	for r := range resultCh {
		results = append(results, r)
	}

	require.Len(t, results, 1)
	assert.Equal(t, "10.0.0.1", results[0].IP)
	assert.Equal(t, 443, results[0].Port)
	assert.NotEmpty(t, results[0].Chain)
}

func TestScanStream_ContextCancellation(t *testing.T) {
	s := NewWithProber(slog.Default(), &slowMockProber{delay: 5 * time.Second})

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	resultCh, _ := s.ScanStream(ctx, ScanConfig{
		IPRanges:      []string{"10.0.0.0/24"},
		Ports:         []int{443},
		Timeout:       1 * time.Second,
		Workers:       5,
		MaxConnPerSec: 10000,
	})

	var count int
	for range resultCh {
		count++
	}
	// Channel should close quickly; we get few or no results
	assert.Less(t, count, 254)
}

func TestExpandAllCIDRs_Shuffled(t *testing.T) {
	s := New(slog.Default())

	ips1 := s.expandAllCIDRs([]string{"10.0.0.0/24"})
	ips2 := s.expandAllCIDRs([]string{"10.0.0.0/24"})

	assert.Len(t, ips1, 254)
	assert.Len(t, ips2, 254)

	// Same IPs, different order
	set1 := map[string]bool{}
	set2 := map[string]bool{}
	for _, ip := range ips1 {
		set1[ip.String()] = true
	}
	for _, ip := range ips2 {
		set2[ip.String()] = true
	}
	assert.Equal(t, set1, set2)

	different := 0
	for i := range ips1 {
		if ips1[i].String() != ips2[i].String() {
			different++
		}
	}
	assert.Greater(t, different, 0, "two shuffles of 254 IPs should differ")
}

// TestExpandAllCIDRs_TruncatesAtCap guards the OOM bound on the CIDR
// aggregate break site: two /16s expand past MaxTotalTargets, so the
// aggregate is trimmed to the cap.
func TestExpandAllCIDRs_TruncatesAtCap(t *testing.T) {
	s := New(slog.Default())
	ips := s.expandAllCIDRs([]string{"10.0.0.0/16", "10.1.0.0/16"})
	assert.Len(t, ips, MaxTotalTargets)
}

// TestScanStream_TruncatesTargetsAtCap guards the OOM bound on the
// per-port target break site: one wide CIDR crossed with several ports
// exceeds MaxTotalTargets, so the assembled target set is capped.
func TestScanStream_TruncatesTargetsAtCap(t *testing.T) {
	s := NewWithProber(slog.Default(), &mockProber{})
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // don't actually probe; we only assert the pre-computed target count

	_, meta := s.ScanStream(ctx, ScanConfig{
		IPRanges:      []string{"10.0.0.0/17"}, // ~32766 IPs
		Ports:         []int{80, 443, 8443, 8080},
		Timeout:       time.Second,
		Workers:       1,
		MaxConnPerSec: 1,
	})
	assert.Equal(t, MaxTotalTargets, meta.TotalTargets)
}

// TestFingerprint_Stable verifies the fingerprint helper produces a
// 64-char lowercase hex SHA-256 for arbitrary DER bytes. This is the
// canonical fingerprint format on the wire.
func TestFingerprint_Stable(t *testing.T) {
	der := []byte{0x30, 0x82, 0x01, 0x02, 0x03}
	fp := Fingerprint(der)
	require.Len(t, fp, 64)
	// Stability across two calls.
	assert.Equal(t, fp, Fingerprint(der))
	// Different input → different fingerprint.
	assert.NotEqual(t, fp, Fingerprint(append(der, 0x04)))
}
