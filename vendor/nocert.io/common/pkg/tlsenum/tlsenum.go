// Package tlsenum performs hand-crafted TLS cipher suite enumeration against
// a target host. It probes TLS 1.0, 1.1, and 1.2 per cipher (TLS 1.3 is out of
// scope - see spec 2026-05-05-tls-cipher-enumeration-design.md). Zero external
// dependencies beyond the Go standard library and nocert.io/common/pkg/{tlsconst,
// tlsprobe}.
package tlsenum

import (
	"context"
	cryptorand "crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"time"

	"nocert.io/common/pkg/tlsconst"
	"nocert.io/common/pkg/tlsprobe"
)

// Wire-format TLS protocol versions (RFC 5246 §A.1).
const (
	versionTLS10 uint16 = 0x0301
	versionTLS11 uint16 = 0x0302
	versionTLS12 uint16 = 0x0303
)

// maxHostnameLen bounds SNI hostnames per RFC 1035; defense-in-depth on
// untrusted FQDN input from the backend.
const maxHostnameLen = 255

// Result is the outcome of enumeration against one target. Empty Findings is
// a valid result ONLY when the returned error is nil: it then means the target
// cleanly declined every enumerated cipher across the probed versions (e.g. a
// TLS 1.3-only server). When Enumerate returns a non-nil error, any Findings
// are partial and MUST NOT be treated as an authoritative "these are the only
// suites" - the enumeration did not complete cleanly.
type Result struct {
	Findings []CipherFinding
	PeerIP   string
}

// CipherFinding describes one (version, cipher) pair the server accepted.
type CipherFinding struct {
	Version string // "TLSv1.0", "TLSv1.1", "TLSv1.2"
	Cipher  string // IANA name from tlsconst registry
}

// Options controls dialing and timeouts. Dialer is REQUIRED.
type Options struct {
	Dialer           tlsprobe.ContextDialer
	HandshakeTimeout time.Duration // per attempt; default 3s if zero
}

const (
	maxTargetCiphers        = 256
	defaultHandshakeTimeout = 3 * time.Second
)

// targetCiphers is the union of every non-TLS-1.3 cipher in the tlsconst
// registry, used as the offer list for TLS 1.0/1.1/1.2 enumeration.
var targetCiphers []uint16

func init() {
	for _, c := range tlsconst.AllCiphers() {
		// Exclude the whole TLS 1.3 suite range (0x13xx: AES-GCM, ChaCha20,
		// CCM, CCM_8) - they are meaningless in a ≤1.2 ClientHello. An ID
		// list would silently start offering any newly-registered 1.3 suite.
		if c.ID&0xFF00 == 0x1300 {
			continue
		}
		targetCiphers = append(targetCiphers, c.ID)
	}
	if len(targetCiphers) > maxTargetCiphers {
		panic(fmt.Sprintf("tlsenum: target cipher list size %d exceeds cap %d",
			len(targetCiphers), maxTargetCiphers))
	}
}

// Enumerate probes the target across TLS 1.0, 1.1, and 1.2 using the
// remove-and-retry loop (see enumVersion), aggregating findings in
// server-preference order per version.
//
// A nil error means every version reached a clean terminal. Errors on one
// version do not prevent probing the others, but the aggregate remains partial.
// Callers must not replace complete evidence or stamp freshness on an error.
// Pass a context deadline to bound the entire enumeration.
func Enumerate(ctx context.Context, host string, port int, opts Options) (*Result, error) {
	if opts.Dialer == nil {
		return nil, errors.New("tlsenum: Options.Dialer is required")
	}
	if l := len(host); l == 0 || l > maxHostnameLen {
		return nil, fmt.Errorf("tlsenum: host length out of range: %d", l)
	}
	per := opts.HandshakeTimeout
	if per <= 0 {
		per = defaultHandshakeTimeout
	}
	res := &Result{}
	var incomplete error
	for _, ver := range []uint16{versionTLS10, versionTLS11, versionTLS12} {
		if err := ctx.Err(); err != nil {
			return res, err
		}
		findings, ip, err := enumVersion(ctx, opts.Dialer, host, port, ver, targetCiphers, per)
		if res.PeerIP == "" && ip != "" {
			res.PeerIP = ip
		}
		res.Findings = append(res.Findings, findings...)
		if err != nil {
			if ctx.Err() != nil {
				return res, ctx.Err()
			}
			incomplete = errors.Join(incomplete, fmt.Errorf("tlsenum: %s: %w", versionLabel[ver], err))
		}
	}
	if incomplete != nil {
		return res, incomplete
	}
	return res, nil
}

// buildClientHello constructs a minimal TLS 1.0/1.1/1.2 ClientHello record
// offering the given cipher suites for the given inner version. random is
// injected by the caller so tests can use deterministic bytes. The outer
// record-layer version is pinned to 0x0301 (TLS 1.0) for middlebox
// compatibility, and an empty serverName omits the SNI extension (RFC 6066
// disallows zero-length host names).
//
// Callers must pass serverName <= 255 bytes and len(ciphers) <= 256; both hold
// via Enumerate's validation and the package-init cap on targetCiphers.
func buildClientHello(serverName string, innerVersion uint16, ciphers []uint16, random [32]byte) []byte {
	body := make([]byte, 0, 256)
	body = append(body, byte(innerVersion>>8), byte(innerVersion))
	body = append(body, random[:]...)
	body = append(body, 0x00) // session_id_length

	body = appendU16(body, uint16(len(ciphers)*2))
	for _, c := range ciphers {
		body = appendU16(body, c)
	}
	body = append(body, 0x01, 0x00) // compression_methods: null

	extBuf := make([]byte, 0, 128)
	if serverName != "" {
		extBuf = append(extBuf, buildSNIExtension(serverName)...)
	}
	extBuf = append(extBuf, buildSupportedGroupsExtension()...)
	extBuf = append(extBuf, buildECPointFormatsExtension()...)
	if innerVersion == versionTLS12 {
		extBuf = append(extBuf, buildSignatureAlgorithmsExtension()...)
	}
	extBuf = append(extBuf, buildALPNExtension()...)
	body = appendU16(body, uint16(len(extBuf)))
	body = append(body, extBuf...)

	hs := make([]byte, 0, len(body)+4)
	hs = append(hs, 0x01) // ClientHello
	bodyLen := uint32(len(body))
	hs = append(hs, byte(bodyLen>>16), byte(bodyLen>>8), byte(bodyLen))
	hs = append(hs, body...)

	rec := make([]byte, 0, len(hs)+5)
	rec = append(rec, 0x16, 0x03, 0x01)
	rec = appendU16(rec, uint16(len(hs)))
	rec = append(rec, hs...)
	return rec
}

func appendU16(b []byte, v uint16) []byte { return binary.BigEndian.AppendUint16(b, v) }

func buildSNIExtension(name string) []byte {
	hn := []byte(name)
	inner := make([]byte, 0, 5+len(hn))
	inner = appendU16(inner, uint16(3+len(hn))) // list length
	inner = append(inner, 0x00)                 // host_name
	inner = appendU16(inner, uint16(len(hn)))
	inner = append(inner, hn...)
	out := []byte{0x00, 0x00}
	out = appendU16(out, uint16(len(inner)))
	out = append(out, inner...)
	return out
}

func buildSupportedGroupsExtension() []byte {
	groups := []uint16{0x0017, 0x0018, 0x0019, 0x001D} // secp256r1, secp384r1, secp521r1, x25519
	inner := make([]byte, 0, 2+2*len(groups))
	inner = appendU16(inner, uint16(2*len(groups)))
	for _, g := range groups {
		inner = appendU16(inner, g)
	}
	out := []byte{0x00, 0x0A}
	out = appendU16(out, uint16(len(inner)))
	out = append(out, inner...)
	return out
}

func buildECPointFormatsExtension() []byte {
	return []byte{0x00, 0x0B, 0x00, 0x02, 0x01, 0x00}
}

func buildSignatureAlgorithmsExtension() []byte {
	// Advertise what a modern client offers so a server whose cert needs a
	// signature scheme we didn't list (ECDSA-P521, Ed25519, RSA-PSS) doesn't
	// answer handshake_failure - which enumVersion would misread as "no more
	// ciphers" and record an authoritative-looking empty result. Extra schemes
	// never hurt: the server picks whichever one its cert can use.
	algs := []uint16{
		0x0403, 0x0503, 0x0603, // ecdsa_secp{256r1,384r1,521r1}_sha{256,384,512}
		0x0804, 0x0805, 0x0806, // rsa_pss_rsae_sha{256,384,512}
		0x0401, 0x0501, 0x0601, // rsa_pkcs1_sha{256,384,512}
		0x0807, // ed25519
		0x0201, // rsa_pkcs1_sha1 (legacy TLS 1.0/1.1 servers)
	}
	inner := make([]byte, 0, 2+2*len(algs))
	inner = appendU16(inner, uint16(2*len(algs)))
	for _, a := range algs {
		inner = appendU16(inner, a)
	}
	out := []byte{0x00, 0x0D}
	out = appendU16(out, uint16(len(inner)))
	out = append(out, inner...)
	return out
}

// buildALPNExtension advertises the same ALPN protocols as tlsprobe (h2 +
// http/1.1) so that hardened servers (HAProxy/F5 strict configs) which reject
// ClientHellos missing ALPN still hand back a ServerHello. Without this, deep
// enum could miss findings on targets that pass-1 fast probe handles fine.
// Type 0x0010, RFC 7301.
func buildALPNExtension() []byte {
	protos := []string{"h2", "http/1.1"}
	listBuf := make([]byte, 0, 14)
	for _, p := range protos {
		listBuf = append(listBuf, byte(len(p)))
		listBuf = append(listBuf, []byte(p)...)
	}
	inner := make([]byte, 0, 2+len(listBuf))
	inner = appendU16(inner, uint16(len(listBuf)))
	inner = append(inner, listBuf...)
	out := []byte{0x00, 0x10}
	out = appendU16(out, uint16(len(inner)))
	out = append(out, inner...)
	return out
}

const (
	maxResponseBytes = 8 * 1024
	recordHandshake  = 0x16
	recordAlert      = 0x15
	hsServerHello    = 0x02
	maxSessionIDLen  = 32 // RFC 5246 §7.4.1.2
)

// parseResponse identifies whether the server replied with a ServerHello
// (extracting cipher_suite AND the negotiated server_version) or an Alert. It
// returns:
//   - (cipher, version, false, nil) on a valid ServerHello
//   - (0, 0, true, nil)             on a "no acceptable suite" alert (clean terminal)
//   - (0, 0, false, err)            on any other alert, or truncated/malformed input
//
// The negotiated version matters because a pre-1.3 server whose max is below the
// version we offered downgrades (a TLS 1.0 server answers a TLS 1.2 ClientHello
// with a TLS 1.0 ServerHello + cipher rather than an alert). The caller must
// compare it to the offered version so a cipher isn't recorded under a version
// the server does not actually negotiate.
//
// A ServerHello may be split across several handshake records, so handshake
// records are read and concatenated until the message is complete. The total
// is bounded by maxResponseBytes via a single shared io.LimitReader.
func parseResponse(r io.Reader) (cipher uint16, version uint16, alert bool, err error) {
	limited := io.LimitReader(r, maxResponseBytes)

	recType, frag, err := readRecord(limited)
	if err != nil {
		return 0, 0, false, err
	}
	switch recType {
	case recordAlert:
		return classifyAlert(frag)
	case recordHandshake:
		for !handshakeMessageComplete(frag) {
			t, more, err := readRecord(limited)
			if err != nil {
				return 0, 0, false, err
			}
			if t != recordHandshake {
				return 0, 0, false, fmt.Errorf("non-handshake record 0x%02X mid-ServerHello", t)
			}
			frag = append(frag, more...)
		}
		c, v, perr := parseServerHelloBody(frag)
		return c, v, false, perr
	default:
		return 0, 0, false, fmt.Errorf("unexpected record type 0x%02X", recType)
	}
}

// TLS alert descriptions (RFC 8446 §6.2). Only these three mean the server has
// no acceptable parameters for the offered suites/version - the legitimate "no
// more suites" terminal of the remove-and-retry loop. Every other alert
// (internal_error, decode_error, access_denied, …) is a broken or overloaded peer.
const (
	alertHandshakeFailure     = 40
	alertProtocolVersion      = 70
	alertInsufficientSecurity = 71
)

// classifyAlert maps a TLS alert record fragment ([level, description]) to an
// enumeration outcome. Only "no acceptable parameters" alerts are a CLEAN
// terminal; any other alert is an ERROR, so a truncated cipher list is never
// recorded as the server's complete offer.
//
// The alert LEVEL is deliberately NOT used to decide severity: Go's crypto/tls
// sends essentially every alert at fatal level (including a benign
// unrecognized_name when the SNI doesn't match a vhost - which our own CIDR
// sweeps provoke by sending an IP literal as SNI), so "fatal" says nothing about
// whether the peer is broken.
func classifyAlert(frag []byte) (cipher uint16, version uint16, alert bool, err error) {
	if len(frag) < 2 {
		return 0, 0, false, fmt.Errorf("truncated alert record (%d bytes)", len(frag))
	}
	switch desc := frag[1]; desc {
	case alertHandshakeFailure, alertInsufficientSecurity, alertProtocolVersion:
		return 0, 0, true, nil
	default:
		return 0, 0, false, fmt.Errorf("tls alert %d is not a clean enumeration terminal", desc)
	}
}

// readRecord reads one TLS record (a 5-byte header plus its fragment) from r,
// which the caller must already have length-limited.
func readRecord(r io.Reader) (recType byte, frag []byte, err error) {
	header := make([]byte, 5)
	if _, err := io.ReadFull(r, header); err != nil {
		return 0, nil, fmt.Errorf("read record header: %w", err)
	}
	fragLen := int(binary.BigEndian.Uint16(header[3:5]))
	if fragLen == 0 || fragLen > maxResponseBytes-5 {
		return 0, nil, fmt.Errorf("invalid record length %d", fragLen)
	}
	frag = make([]byte, fragLen)
	if _, err := io.ReadFull(r, frag); err != nil {
		return 0, nil, fmt.Errorf("read record fragment: %w", err)
	}
	return header[0], frag, nil
}

// handshakeMessageComplete reports whether frag holds a whole handshake message:
// its 4-byte header plus the 24-bit body length that header declares.
func handshakeMessageComplete(frag []byte) bool {
	if len(frag) < 4 {
		return false
	}
	msgLen := int(frag[1])<<16 | int(frag[2])<<8 | int(frag[3])
	return len(frag) >= 4+msgLen
}

// parseServerHelloBody extracts the negotiated server_version and cipher_suite
// from a record-fragment that begins with a handshake-layer ServerHello. The
// handshake u24 length field is honored: we slice down to that length so
// concatenated handshake messages or attacker padding cannot make us read past
// the ServerHello body.
func parseServerHelloBody(frag []byte) (cipher uint16, version uint16, err error) {
	if len(frag) < 4 {
		return 0, 0, fmt.Errorf("handshake header truncated")
	}
	if frag[0] != hsServerHello {
		return 0, 0, fmt.Errorf("expected ServerHello, got 0x%02X", frag[0])
	}
	u24Len := uint32(frag[1])<<16 | uint32(frag[2])<<8 | uint32(frag[3])
	if int(u24Len) > len(frag)-4 {
		return 0, 0, fmt.Errorf("handshake length %d exceeds fragment", u24Len)
	}
	body := frag[4 : 4+u24Len]

	// body: server_version (2) + random (32) + session_id_len (1) + sid + cipher_suite (2)
	const minBody = 2 + 32 + 1
	if len(body) < minBody {
		return 0, 0, fmt.Errorf("ServerHello body too short")
	}
	version = binary.BigEndian.Uint16(body[0:2])
	off := 2 + 32
	sidLen := int(body[off])
	if sidLen > maxSessionIDLen {
		return 0, 0, fmt.Errorf("session_id_length %d exceeds RFC limit", sidLen)
	}
	off++
	if off+sidLen+2 > len(body) {
		return 0, 0, fmt.Errorf("session_id or cipher_suite truncated")
	}
	off += sidLen
	cipher = binary.BigEndian.Uint16(body[off : off+2])
	return cipher, version, nil
}

// attemptHandshake performs one connection attempt: dial -> write ClientHello ->
// read ServerHello/Alert. Returns the negotiated cipher_suite, the negotiated
// server_version, an alert flag, the resolved peer IP, or an error on any I/O or
// parse failure. Both the dial and the subsequent handshake I/O are bounded by
// perAttempt, so a target that stalls at any stage cannot pin the caller for
// longer than that.
func attemptHandshake(ctx context.Context, dialer tlsprobe.ContextDialer, host string, port int,
	innerVersion uint16, ciphers []uint16, perAttempt time.Duration) (cipher uint16, version uint16, alert bool, peerIP string, err error) {

	conn, err := tlsprobe.DialContext(ctx, dialer, "tcp", net.JoinHostPort(host, strconv.Itoa(port)), perAttempt)
	if err != nil {
		return 0, 0, false, "", fmt.Errorf("dial: %w", err)
	}
	defer conn.Close()
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()

	if a, ok := conn.RemoteAddr().(*net.TCPAddr); ok && a.IP != nil {
		peerIP = a.IP.String()
	}

	if perAttempt > 0 {
		_ = conn.SetDeadline(time.Now().Add(perAttempt))
	}

	var random [32]byte
	if _, err := cryptorand.Read(random[:]); err != nil {
		return 0, 0, false, peerIP, fmt.Errorf("rand: %w", err)
	}
	hello := buildClientHello(host, innerVersion, ciphers, random)
	if _, err := conn.Write(hello); err != nil {
		return 0, 0, false, peerIP, fmt.Errorf("write ClientHello: %w", err)
	}
	cipher, version, alert, err = parseResponse(conn)
	if err != nil {
		return 0, 0, false, peerIP, err
	}
	return cipher, version, alert, peerIP, nil
}

var versionLabel = map[uint16]string{
	versionTLS10: tlsconst.VersionTLS10,
	versionTLS11: tlsconst.VersionTLS11,
	versionTLS12: tlsconst.VersionTLS12,
}

// enumVersion runs the remove-and-retry enumeration loop for one TLS version.
// Returns findings (in server-preference order), the first non-empty peer IP
// captured during the loop, and an error.
//
// A nil error is a clean terminal: either the version's ciphers were exhausted,
// or the server cleanly declined the remaining offer with a TLS alert (a
// genuine "no more acceptable suites"). A non-nil error means an I/O failure,
// a malformed response, an unreachable dial, or context cancellation stopped
// the loop before a clean terminal - the findings are then partial.
func enumVersion(ctx context.Context, dialer tlsprobe.ContextDialer, host string, port int,
	innerVersion uint16, target []uint16, perAttempt time.Duration) ([]CipherFinding, string, error) {

	// Copy the input so we never mutate the caller's slice (targetCiphers is
	// shared package state).
	remaining := append([]uint16(nil), target...)
	var found []CipherFinding
	peerIP := ""

	for len(remaining) > 0 {
		if err := ctx.Err(); err != nil {
			return found, peerIP, err
		}
		cipher, version, alert, ip, err := attemptHandshake(ctx, dialer, host, port, innerVersion, remaining, perAttempt)
		if peerIP == "" && ip != "" {
			peerIP = ip
		}
		if err != nil {
			// Dial, write, read, or parse failure: we never reached a clean
			// terminal for this version. Surface it so the caller retries
			// rather than recording an unreachable enum as "no ciphers".
			return found, peerIP, err
		}
		if alert {
			// Server declined the remaining offer - the normal end of a
			// version's enumeration. Clean, not an error.
			break
		}
		if version != innerVersion {
			// The server negotiated a DIFFERENT version than we offered - a
			// pre-1.3 server whose max is below innerVersion downgrades (answers
			// with a lower ServerHello version instead of an alert), and a
			// misbehaving server could claim a higher one. Either way it does not
			// actually negotiate innerVersion, so stop enumerating this version
			// (a clean terminal) rather than recording a phantom finding here.
			// The version the server DID negotiate is enumerated on its own pass.
			break
		}
		match := false
		for _, x := range remaining {
			if x == cipher {
				match = true
				break
			}
		}
		if !match {
			break // server picked a cipher we didn't offer - stop for this version
		}
		found = append(found, CipherFinding{
			Version: versionLabel[innerVersion],
			Cipher:  tlsconst.CipherName(cipher),
		})
		remaining = removeCipher(remaining, cipher)
	}
	return found, peerIP, nil
}

// removeCipher returns a new slice with every occurrence of c removed, leaving
// the input untouched (see the copy rationale in enumVersion).
func removeCipher(s []uint16, c uint16) []uint16 {
	out := make([]uint16, 0, len(s))
	for _, x := range s {
		if x != c {
			out = append(out, x)
		}
	}
	return out
}
