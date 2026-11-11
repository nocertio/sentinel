package scanner

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestLegacyFallbackRetainsProtocolAndOpaqueCertificate(t *testing.T) {
	for _, withCert := range []bool{false, true} {
		t.Run(map[bool]string{false: "protocol_only", true: "certificate_only"}[withCert], func(t *testing.T) {
			listener, err := net.Listen("tcp", "127.0.0.1:0")
			require.NoError(t, err)
			t.Cleanup(func() { _ = listener.Close() })
			var connections atomic.Int32
			go func() {
				for {
					conn, err := listener.Accept()
					if err != nil {
						return
					}
					index := connections.Add(1)
					_ = conn.SetDeadline(time.Now().Add(time.Second))
					var header [5]byte
					if _, err := io.ReadFull(conn, header[:]); err == nil && header[0] == 22 {
						body := make([]byte, int(binary.BigEndian.Uint16(header[3:])))
						_, _ = io.ReadFull(conn, body)
						if index > 1 {
							hello := append([]byte{3, 3}, make([]byte, 32)...)
							hello = append(hello, 0, 0, 0x33, 0)
							flight := append([]byte{2, 0, 0, byte(len(hello))}, hello...)
							if withCert {
								flight = append(flight, 11, 0, 0, 9, 0, 0, 6, 0, 0, 3, 0x30, 0x01, 0xFF)
							}
							record := append([]byte{22, 3, 3, byte(len(flight) >> 8), byte(len(flight))}, flight...)
							_, _ = conn.Write(record)
						}
					}
					_ = conn.Close()
				}
			}()
			port := listener.Addr().(*net.TCPAddr).Port
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			result, err := (&tlsProber{}).Probe(ctx, "127.0.0.1", port, time.Second, "legacy.invalid")
			require.NoError(t, err)
			out := (&Scanner{}).probeResultToOutput(port, "legacy.invalid", result, nil, false)
			require.NotNil(t, out)
			require.Equal(t, "127.0.0.1", out.IP)
			require.Equal(t, "legacy.invalid", out.SNI)
			require.Equal(t, uint16(0x0303), *out.TLS.TLSVersionID)
			require.False(t, *out.TLS.HandshakeComplete)
			if withCert {
				require.Equal(t, [][]byte{{0x30, 0x01, 0xFF}}, out.Chain)
			} else {
				require.Empty(t, out.Chain)
			}
			require.LessOrEqual(t, connections.Load(), int32(7))
		})
	}
}
