package scanner

import (
	"context"
	"crypto/tls"
	"errors"
	"log/slog"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

type notifiedDialer struct{ calls chan string }

func (d *notifiedDialer) DialContext(_ context.Context, network, addr string) (net.Conn, error) {
	d.calls <- network + ":" + addr
	return nil, errors.New("test dial refused")
}

func TestRateLimitedDialerSharesTokens(t *testing.T) {
	ticks := make(chan time.Time)
	base := &notifiedDialer{calls: make(chan string, 8)}
	d := &rateLimitedDialer{base: base, ticks: ticks}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var wg sync.WaitGroup
	for range 8 {
		wg.Add(1)
		go func() { defer wg.Done(); _, _ = d.DialContext(ctx, "tcp", "127.0.0.1:443") }()
	}
	for range 3 {
		select {
		case ticks <- time.Now():
		case <-time.After(time.Second):
			t.Fatal("connections did not wait for a token")
		}
		select {
		case addr := <-base.calls:
			require.Equal(t, "tcp:127.0.0.1:443", addr)
		case <-time.After(time.Second):
			t.Fatal("released token did not reach dialer")
		}
	}
	cancel()
	wg.Wait()
	require.Empty(t, base.calls, "waiting connections must not dial after cancellation")
}

func TestRateLimitedDialerCancelledWithReadyToken(t *testing.T) {
	ticks := make(chan time.Time, 1)
	ticks <- time.Now()
	base := &notifiedDialer{calls: make(chan string, 1)}
	d := &rateLimitedDialer{base: base, ticks: ticks}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := d.DialContext(ctx, "tcp", "127.0.0.1:443")
	require.ErrorIs(t, err, context.Canceled)
	require.Empty(t, base.calls)
}

func TestScanEnumerationSharesConnectionBudget(t *testing.T) {
	_, _, ca, key := generateTestCA()
	certPEM, keyPEM := generateTestLeaf(ca, key, "localhost")
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	require.NoError(t, err)
	for _, deep := range []bool{false, true} {
		name := "fast"
		if deep {
			name = "deep"
		}
		t.Run(name, func(t *testing.T) {
			listener, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
				Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS13,
			})
			require.NoError(t, err)
			t.Cleanup(func() { _ = listener.Close() })
			arrivals := make(chan time.Time, 32)
			go func() {
				for {
					conn, err := listener.Accept()
					if err != nil {
						return
					}
					arrivals <- time.Now()
					_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
					_ = conn.(*tls.Conn).Handshake()
					_ = conn.Close()
				}
			}()
			port := listener.Addr().(*net.TCPAddr).Port
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			s := New(slog.Default())
			started := time.Now()
			ch, _ := s.ScanStream(ctx, ScanConfig{
				Targets: []target{{host: "127.0.0.1", port: port}, {host: "127.0.0.1", port: port}},
				Workers: 2, MaxConnPerSec: 10, Timeout: time.Second, DeepEnum: deep, SkipSNIReprobe: true,
			})
			count := 0
			for out := range ch {
				count++
				require.Equal(t, cert.Certificate[0], out.Chain[0])
				require.Equal(t, deep, out.TLS.DeepEnumAttempted)
			}
			require.NoError(t, ctx.Err())
			require.Equal(t, 2, count)
			want := 2
			if deep {
				want = 8
			} // one fast probe + three declined legacy versions per target
			require.Len(t, arrivals, want)
			require.GreaterOrEqual(t, time.Since(started), time.Duration(want)*100*time.Millisecond-50*time.Millisecond,
				"enumeration workers must share the fast probes' connection budget")
		})
	}
}
