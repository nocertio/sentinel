package tlsenum

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"slices"
	"strconv"
	"time"

	"nocert.io/common/pkg/tlsconst"
	"nocert.io/common/pkg/tlsprobe"
)

const (
	versionSSL30      = 0x0300
	versionSSL20      = 0x0002 // SSLv2 wire value, not the historical display ID 0x0200.
	collectionTimeout = 10 * time.Second
)

// Collection contains unauthenticated server messages. Certificates are opaque
// DER; no X.509 parsing or legacy cryptographic operation is performed here.
type Collection struct {
	PeerIP       string
	ServerName   string
	Version      uint16
	Cipher       uint16
	Certificates [][]byte
	DHBits       int
	SSL2Ciphers  []uint32
}

type collectionProfile struct {
	version    uint16
	extensions bool
}

// Collect tries at most six ClientHellos within a shared ten-second budget.
// A non-nil result remains positive evidence when a later message is malformed
// or missing. A timeout or refusal alone never constitutes protocol detection.
func Collect(ctx context.Context, host string, port int, serverName string, opts Options) (*Collection, error) {
	if opts.Dialer == nil || len(serverName) > maxHostnameLen {
		return nil, errors.New("tlsenum: invalid collection options")
	}
	ctx, cancel := context.WithTimeout(ctx, collectionTimeout)
	defer cancel()
	var best *Collection
	var lastErr error
	profiles := []collectionProfile{{versionTLS12, true}, {versionTLS12, false}, {versionTLS11, false}, {versionTLS10, false}, {versionSSL30, false}, {versionSSL20, false}}
	for i, p := range profiles {
		if ctx.Err() != nil {
			return best, ctx.Err()
		}
		attempt := opts
		deadline, _ := ctx.Deadline()
		share := time.Until(deadline) / time.Duration(len(profiles)-i)
		if attempt.HandshakeTimeout <= 0 || attempt.HandshakeTimeout > share {
			attempt.HandshakeTimeout = share
		}
		r, err := collectOnce(ctx, host, port, serverName, p, nil, attempt)
		if r != nil {
			if best == nil || len(r.Certificates) > 0 {
				best = r
			}
			if len(r.Certificates) > 0 {
				return r, err
			}
		}
		lastErr = err
	}
	return best, lastErr
}

// CollectObsolete checks SSLv3 and SSLv2 even when modern TLS is available.
// Only positive responses are returned; absence and failed probes are unknown.
func CollectObsolete(ctx context.Context, host string, port int, opts Options) []*Collection {
	ctx, cancel := context.WithTimeout(ctx, collectionTimeout)
	defer cancel()
	var out []*Collection
	for _, v := range []uint16{versionSSL30, versionSSL20} {
		if ctx.Err() != nil {
			break
		}
		r, _ := collectOnce(ctx, host, port, "", collectionProfile{v, false}, nil, opts)
		if r != nil {
			out = append(out, r)
		}
	}
	return out
}

func collectOnce(ctx context.Context, host string, port int, serverName string, profile collectionProfile, ciphers []uint16, opts Options) (*Collection, error) {
	if opts.Dialer == nil {
		return nil, errors.New("tlsenum: missing dialer")
	}
	per := opts.HandshakeTimeout
	if per <= 0 {
		per = defaultHandshakeTimeout
	}
	conn, err := tlsprobe.DialContext(ctx, opts.Dialer, "tcp", net.JoinHostPort(host, strconv.Itoa(port)), per)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()
	if err = conn.SetDeadline(time.Now().Add(per)); err != nil {
		return nil, err
	}
	var random [32]byte
	if _, err = rand.Read(random[:]); err != nil {
		return nil, err
	}
	if net.ParseIP(serverName) != nil || !profile.extensions {
		serverName = ""
	}
	var hello []byte
	if profile.version == versionSSL20 {
		hello = ssl2ClientHello(random)
	} else {
		if ciphers == nil {
			if profile.version == versionSSL30 {
				ciphers = ssl3Ciphers()
			} else {
				ciphers = ciphersForVersion(profile.version)
			}
		}
		hello = buildClientHelloProfile(serverName, profile.version, ciphers, random, profile.extensions, opts.DisableALPN)
	}
	if n, err := conn.Write(hello); err != nil || n != len(hello) {
		if err == nil {
			err = io.ErrShortWrite
		}
		return nil, err
	}
	var result *Collection
	if profile.version == versionSSL20 {
		result, err = readSSL2Hello(conn)
	} else {
		result, err = readServerFlight(conn, profile.version, ciphers)
	}
	if result != nil {
		result.ServerName = serverName
		if addr, ok := conn.RemoteAddr().(*net.TCPAddr); ok {
			result.PeerIP = addr.IP.String()
		}
	}
	return result, err
}

// SSLv3 predates extensions and the later AES/ECC suites (RFC 6101, Appendix A.6).
func ssl3Ciphers() []uint16 {
	return []uint16{0x000A, 0x0005, 0x0004, 0x0016, 0x0013, 0x0009, 0x0015, 0x0012, 0x0007, 0x0003, 0x0006, 0x0008, 0x0014, 0x0011, 0x0001, 0x0002, 0x0018, 0x001B, 0x0017, 0x0019, 0x001A, 0x000B, 0x000C, 0x000D, 0x000E, 0x000F, 0x0010}
}

func validateSelection(version, cipher, offeredVersion uint16, offered []uint16) error {
	if version < versionSSL30 || version > offeredVersion || !slices.Contains(offered, cipher) {
		return errors.New("tlsenum: unoffered server parameters")
	}
	if offeredVersion != versionSSL30 && version == versionSSL30 {
		return errors.New("tlsenum: SSLv3 requires a dedicated probe")
	}
	if version != versionSSL30 && !tlsconst.LookupCipher(cipher).SupportsVersion(version) {
		return fmt.Errorf("tlsenum: cipher incompatible with version 0x%04x", version)
	}
	return nil
}

func u24(b []byte) int { return int(b[0])<<16 | int(b[1])<<8 | int(b[2]) }

func appendU24(b []byte, n int) []byte { return append(b, byte(n>>16), byte(n>>8), byte(n)) }

func readVector16(b []byte) (value, rest []byte, ok bool) {
	if len(b) < 2 {
		return nil, nil, false
	}
	n := int(binary.BigEndian.Uint16(b))
	if n == 0 || n > len(b)-2 {
		return nil, nil, false
	}
	return b[2 : 2+n], b[2+n:], true
}
