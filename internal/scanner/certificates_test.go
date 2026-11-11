package scanner

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"io"
	"log/slog"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"nocert.io/common/pkg/tlsprobe"
	"nocert.io/sentinel/internal/testutil"
)

func TestUnusualCertificates(t *testing.T) {
	t.Setenv("GODEBUG", "x509negativeserial=0")
	for _, tc := range testutil.UnusualCertificates(t) {
		t.Run(tc.Name, func(t *testing.T) {
			_, parseErr := x509.ParseCertificate(tc.Certificate.Certificate[0])
			require.Equal(t, tc.Parseable, parseErr == nil, "fixture parseability")
			for _, version := range []uint16{tls.VersionTLS12, tls.VersionTLS13} {
				t.Run(tls.VersionName(version), func(t *testing.T) {
					port, connections := certificateServer(t, tc.Certificate, version)
					prober := &tlsProber{}
					ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
					defer cancel()
					result, err := prober.Probe(ctx, "127.0.0.1", port, time.Second, "fixture.invalid")
					require.NoError(t, ctx.Err(), "probe must finish within its budget")
					require.LessOrEqual(t, connections.Load(), int32(7))
					if !tc.Parseable && version == tls.VersionTLS13 {
						// Go rejects the DER before exposing it; the plaintext
						// collector cannot recover TLS 1.3's encrypted Certificate.
						require.Error(t, err)
						require.Nil(t, result)
					} else {
						require.NoError(t, err)
						out := (&Scanner{}).probeResultToOutput(port, "fixture.invalid", result, nil, false)
						require.NotNil(t, out)
						require.Equal(t, tc.Certificate.Certificate, out.Chain)
						require.Equal(t, version, *out.TLS.TLSVersionID)
						require.Equal(t, tc.Parseable, *out.TLS.HandshakeComplete)
					}
				})
			}
		})
	}
}

func TestCertificateChainLimits(t *testing.T) {
	leaf := testutil.Certificate(t, nil)
	large := testutil.Certificate(t, func(c *x509.Certificate) {
		c.Subject.CommonName = strings.Repeat("x", tlsprobe.MaxCertSize)
	})
	require.Greater(t, len(large.Certificate[0]), tlsprobe.MaxCertSize)
	long := leaf
	long.Certificate = make([][]byte, tlsprobe.MaxChainDepth+1)
	for i := range long.Certificate {
		long.Certificate[i] = testutil.Certificate(t, nil).Certificate[0]
	}
	long.Certificate[0] = leaf.Certificate[0]
	malformedLong := long
	malformedLong.Certificate = append([][]byte(nil), long.Certificate...)
	malformedLong.Certificate[len(malformedLong.Certificate)-1] = []byte{0x30, 0}
	intermediate := leaf
	intermediate.Certificate = [][]byte{leaf.Certificate[0], large.Certificate[0]}
	for _, tc := range []struct {
		name     string
		cert     tls.Certificate
		retained int
	}{
		{"long_chain", long, tlsprobe.MaxChainDepth},
		{"oversized_intermediate", intermediate, 1},
		{"oversized_leaf", large, 0},
		{"malformed_long_chain", malformedLong, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for _, version := range []uint16{tls.VersionTLS12, tls.VersionTLS13} {
				t.Run(tls.VersionName(version), func(t *testing.T) {
					port, connections := certificateServer(t, tc.cert, version)
					prober := &tlsProber{}
					ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
					defer cancel()
					result, err := prober.Probe(ctx, "127.0.0.1", port, time.Second, "fixture.invalid")
					require.NoError(t, ctx.Err())
					require.LessOrEqual(t, connections.Load(), int32(7))
					if tc.retained == 0 && version == tls.VersionTLS13 {
						require.Error(t, err)
						require.Nil(t, result)
					} else {
						require.NoError(t, err)
						out := (&Scanner{}).probeResultToOutput(port, "fixture.invalid", result, nil, false)
						require.NotNil(t, out)
						require.Len(t, out.Chain, tc.retained)
						for i, der := range out.Chain {
							require.Equal(t, tc.cert.Certificate[i], der)
						}
						require.Equal(t, tc.retained > 0, *out.TLS.HandshakeComplete)
					}
				})
			}
		})
	}
}

func TestCertificateRejectionDoesNotStopScan(t *testing.T) {
	t.Setenv("GODEBUG", "x509negativeserial=0")
	var targets []target
	for _, tc := range testutil.UnusualCertificates(t) {
		if !tc.Parseable {
			port, _ := certificateServer(t, tc.Certificate, tls.VersionTLS13)
			targets = append(targets, target{host: "127.0.0.1", port: port})
		}
	}
	cert := testutil.Certificate(t, nil)
	port, _ := certificateServer(t, cert, tls.VersionTLS13)
	targets = append(targets, target{host: "127.0.0.1", port: port})
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	scanner := New(slog.New(slog.NewTextHandler(io.Discard, nil)))
	results, _ := scanner.ScanStream(ctx, ScanConfig{
		Targets: targets, Workers: 1, Timeout: time.Second, MaxConnPerSec: 1000, SkipSNIReprobe: true,
	})
	var got []ProbeOutput
	for result := range results {
		got = append(got, result)
	}
	require.NoError(t, ctx.Err())
	require.Len(t, got, 1)
	require.Equal(t, port, got[0].Port)
	require.Equal(t, cert.Certificate, got[0].Chain)
	require.True(t, *got[0].TLS.HandshakeComplete)
}

func certificateServer(t *testing.T, cert tls.Certificate, version uint16) (int, *atomic.Int32) {
	t.Helper()
	listener, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{cert}, MinVersion: version, MaxVersion: version,
	})
	require.NoError(t, err)
	var connections atomic.Int32
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			connections.Add(1)
			_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
			_ = conn.(*tls.Conn).Handshake()
			_ = conn.Close()
		}
	}()
	t.Cleanup(func() { _ = listener.Close(); <-done })
	return listener.Addr().(*net.TCPAddr).Port, &connections
}
