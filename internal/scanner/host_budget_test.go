package scanner

import (
	"context"
	"crypto/tls"
	"log/slog"
	"net"
	"net/netip"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"nocert.io/sentinel/internal/testutil"
)

func TestHostBudgetSerializesAndReleases(t *testing.T) {
	var b hostBudget
	ip := netip.MustParseAddr("192.0.2.1")
	release, err := b.acquire(context.Background(), ip, 0)
	require.NoError(t, err)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	_, err = b.acquire(ctx, netip.MustParseAddr("::ffff:192.0.2.1"), 0)
	require.ErrorIs(t, err, context.DeadlineExceeded)
	other, err := b.acquire(context.Background(), netip.MustParseAddr("192.0.2.2"), 0)
	require.NoError(t, err)
	other()
	release()
	release()
	var wg sync.WaitGroup
	for range 20 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			done, err := b.acquire(context.Background(), ip, 0)
			if err == nil {
				done()
			}
		}()
	}
	wg.Wait()
	b.mu.Lock()
	defer b.mu.Unlock()
	require.Empty(t, b.hosts)
}

func TestHostBudgetCooldownSurvivesIdleAndCancellation(t *testing.T) {
	var b hostBudget
	ip := netip.MustParseAddr("192.0.2.1")
	release, err := b.acquire(context.Background(), ip, 60*time.Millisecond)
	require.NoError(t, err)
	release()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err = b.acquire(ctx, ip, 60*time.Millisecond)
	require.Error(t, err)
	start := time.Now()
	done, err := b.acquire(context.Background(), ip, 0)
	require.NoError(t, err)
	require.GreaterOrEqual(t, time.Since(start), 40*time.Millisecond)
	done()
	require.Eventually(t, func() bool { b.mu.Lock(); defer b.mu.Unlock(); return len(b.hosts) == 0 }, time.Second, time.Millisecond)
}

func TestScanDialerSharesIPAcrossPortsAndHostname(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer listener.Close()
	ticks := make(chan time.Time, 10)
	for range 10 {
		ticks <- time.Now()
	}
	d := &scanDialer{hosts: &hostBudget{}, ticks: ticks}
	first, err := d.DialContext(context.Background(), "tcp", listener.Addr().String())
	require.NoError(t, err)
	server, err := listener.Accept()
	require.NoError(t, err)
	defer server.Close()
	defer first.Close()
	port := listener.Addr().(*net.TCPAddr).Port
	for _, addr := range []string{net.JoinHostPort("localhost", strconv.Itoa(port)), "127.0.0.1:1"} {
		ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
		_, err := d.DialContextWithTimeout(ctx, "tcp", addr, time.Second)
		cancel()
		require.ErrorIs(t, err, context.DeadlineExceeded)
	}
	require.NoError(t, first.Close())
	next, err := d.DialContext(context.Background(), "tcp", listener.Addr().String())
	require.NoError(t, err)
	next.Close()
}

func TestGentleScanSkipsExtraProbes(t *testing.T) {
	for _, kind := range []string{"targeted", "hostname"} {
		t.Run(kind, func(t *testing.T) {
			cert := testutil.Certificate(t, nil)
			port, connections := certificateServer(t, cert, tls.VersionTLS13)
			s := New(slog.Default())
			s.SetGentle(true)
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			var ch <-chan ProbeOutput
			if kind == "targeted" {
				ch, _ = s.ScanTargets(ctx, []Target{{Host: "127.0.0.1", Port: port}}, time.Second)
			} else {
				ch, _ = s.ScanHostname(ctx, "127.0.0.1", []int{port}, time.Second, true)
			}
			var got []ProbeOutput
			for r := range ch {
				got = append(got, r)
			}
			require.NoError(t, ctx.Err())
			require.Len(t, got, 1)
			require.False(t, got[0].TLS.DeepEnumAttempted)
			require.Equal(t, int32(1), connections.Load())
		})
	}
}

func TestInterleaveTargets(t *testing.T) {
	targets := []target{{host: "a", port: 1}, {host: "a", port: 2}, {host: "a", port: 3}, {host: "b", port: 1}, {host: "b", port: 2}, {host: "c", port: 1}}
	require.Equal(t, []target{targets[0], targets[3], targets[5], targets[1], targets[4], targets[2]}, interleaveTargets(targets))
}
