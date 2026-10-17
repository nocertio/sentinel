package scanner

import (
	"context"
	"crypto/mldsa"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"log/slog"
	"math/big"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestInventoryTLSCompatibility(t *testing.T) {
	_, _, ca, key := generateTestCA()
	certPEM, keyPEM := generateTestLeaf(ca, key, "localhost")
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	require.NoError(t, err)
	for _, tc := range []struct {
		name    string
		version uint16
		group   tls.CurveID
	}{
		{"TLSv1.0", tls.VersionTLS10, 0},
		{"TLSv1.1", tls.VersionTLS11, 0},
		{"TLSv1.2", tls.VersionTLS12, 0},
		{"X25519MLKEM768", tls.VersionTLS13, tls.X25519MLKEM768},
		{"SecP256r1MLKEM768", tls.VersionTLS13, tls.SecP256r1MLKEM768},
		{"SecP384r1MLKEM1024", tls.VersionTLS13, tls.SecP384r1MLKEM1024},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tc.version, MaxVersion: tc.version}
			if tc.group != 0 {
				cfg.CurvePreferences = []tls.CurveID{tc.group}
			} else {
				cfg.CipherSuites = []uint16{tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA}
			}
			listener, err := tls.Listen("tcp", "127.0.0.1:0", cfg)
			require.NoError(t, err)
			t.Cleanup(func() { _ = listener.Close() })
			done := make(chan error, 1)
			go func() {
				conn, err := listener.Accept()
				if err != nil {
					done <- err
					return
				}
				defer func() { _ = conn.Close() }()
				_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
				done <- conn.(*tls.Conn).Handshake()
			}()
			addr := listener.Addr().(*net.TCPAddr)
			prober := &tlsProber{logger: slog.Default()}
			result, err := prober.Probe(context.Background(), "127.0.0.1", addr.Port, 5*time.Second, "localhost")
			require.NoError(t, err)
			require.NoError(t, <-done)
			require.Equal(t, cert.Certificate[0], result.Certificate.RawDER)
			if tc.group != 0 {
				require.Equal(t, "TLSv1.3", result.TLS.TLSVersion)
				require.Equal(t, strings.ToLower(tc.name), result.TLS.NegotiatedGroup)
			} else {
				require.Equal(t, tc.name, result.TLS.TLSVersion)
			}
		})
	}
}

func TestInventoryMLDSA(t *testing.T) {
	for _, params := range []mldsa.Parameters{mldsa.MLDSA44(), mldsa.MLDSA65(), mldsa.MLDSA87()} {
		t.Run(params.String(), func(t *testing.T) {
			key, err := mldsa.GenerateKey(params)
			require.NoError(t, err)
			cert := &x509.Certificate{SerialNumber: big.NewInt(1), DNSNames: []string{"localhost"},
				NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
			der, err := x509.CreateCertificate(rand.Reader, cert, cert, key.Public(), key)
			require.NoError(t, err)
			listener, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
				Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}},
				MinVersion:   tls.VersionTLS13,
			})
			require.NoError(t, err)
			t.Cleanup(func() { _ = listener.Close() })
			done := make(chan error, 1)
			go func() {
				conn, err := listener.Accept()
				if err != nil {
					done <- err
					return
				}
				defer func() { _ = conn.Close() }()
				_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
				done <- conn.(*tls.Conn).Handshake()
			}()
			addr := listener.Addr().(*net.TCPAddr)
			prober := &tlsProber{logger: slog.Default()}
			result, err := prober.Probe(context.Background(), "127.0.0.1", addr.Port, 5*time.Second, "localhost")
			require.NoError(t, err)
			require.NoError(t, <-done)
			require.Equal(t, der, result.Certificate.RawDER)
			require.Equal(t, "TLSv1.3", result.TLS.TLSVersion)
		})
	}
}
