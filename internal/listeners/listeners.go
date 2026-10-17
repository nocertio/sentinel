// Package listeners enumerates the TCP ports listening on the sentinel's own
// host by reading /proc/net/tcp and /proc/net/tcp6 (no root, no external
// binary, no dependency). It returns one probe target per distinct listening
// socket (loopback for wildcard/loopback binds, the bound IP otherwise) so a
// local_scan can grab the certificate each service
// actually presents - the signal for "cert renewed on disk but the running
// service was never reloaded".
//
// Only LISTEN sockets (st == 0x0A) are returned, minus a denylist of well-known
// plaintext / STARTTLS-only ports where a bare TLS ClientHello yields no
// certificate and only logs noise on the host's own services. Implicit-TLS
// ports (443, 465, 636, 853, 993, 995, 3389, 8443, ...) are kept.
//
// netns caveat: /proc/net/tcp only shows sockets in the reader's own network
// namespace. A sentinel inside a container sees only that container's
// listeners; published container ports are DNAT rules, not listeners, so they
// do not appear here. Run the sentinel on the host (or network_mode: host) for
// this to cover the host's services.
package listeners

import (
	"bufio"
	"encoding/hex"
	"io"
	"net/netip"
	"os"
	"strconv"
	"strings"
)

const (
	procTCPPath  = "/proc/net/tcp"
	procTCP6Path = "/proc/net/tcp6"

	// stateListen is the TCP_LISTEN value in /proc/net/tcp (column `st`).
	stateListen = "0A"

	// maxLocalTargets caps how many ports a single local_scan probes. A host
	// with >256 distinct TLS-bearing loopback listeners is already pathological;
	// this bounds the scan's worst-case duration (cap x probe timeout / workers)
	// so it can't sit for minutes holding the scan flag.
	maxLocalTargets = 256
)

// denyPorts are TCP ports that are plaintext or STARTTLS BY DEFAULT, where a
// bare TLS ClientHello almost always yields no certificate and instead writes a
// protocol-violation error to the host's own service log - so we skip them to
// stay quiet. A few (Redis 6379, MongoDB 27017) CAN be TLS-enabled on the same
// port; we accept silently missing those rare cases (the network / filesystem
// scans still surface the cert) rather than spam the common plaintext setup.
// Implicit-TLS ports (DoT 853, LDAPS 636, SMTPS 465, IMAPS 993, POP3S 995,
// RDP 3389) are kept - intentionally absent here.
var denyPorts = map[int]bool{
	21:    true, // FTP
	22:    true, // SSH
	23:    true, // Telnet
	25:    true, // SMTP (STARTTLS)
	53:    true, // DNS (plaintext; systemd-resolved binds 127.0.0.53)
	110:   true, // POP3 (STLS)
	143:   true, // IMAP (STARTTLS)
	389:   true, // LDAP (STARTTLS)
	587:   true, // SMTP submission (STARTTLS)
	3306:  true, // MySQL
	5222:  true, // XMPP client
	5432:  true, // PostgreSQL
	6379:  true, // Redis (plaintext)
	9092:  true, // Kafka (plaintext)
	11211: true, // memcached
	27017: true, // MongoDB
}

// Target is a loopback (or host-local) address:port to probe for a TLS cert.
type Target struct {
	Host string // "127.0.0.1", "::1", or a specific bound IP
	Port int
}

// Enumerate reads the host's listening TCP sockets and returns the probe
// targets plus whether the result is complete enough to authorize destructive
// reconciliation. Missing/truncated /proc input or a target-cap truncation
// keeps the usable targets but returns complete=false.
func Enumerate() ([]Target, bool) {
	v4, close4, v4OK := openProcChecked(procTCPPath)
	defer close4()
	v6, close6, v6OK := openProcChecked(procTCP6Path)
	defer close6()
	targets, parsedOK := enumerateChecked(v4, v6)
	return targets, v4OK && v6OK && parsedOK
}

func openProc(path string) (io.Reader, func()) {
	r, closeFn, _ := openProcChecked(path)
	return r, closeFn
}

func openProcChecked(path string) (io.Reader, func(), bool) {
	f, err := os.Open(path)
	if err != nil {
		return strings.NewReader(""), func() {}, false
	}
	return f, func() { _ = f.Close() }, true
}

// enumerate is the testable core: it consumes the two /proc streams.
func enumerate(v4r, v6r io.Reader) []Target {
	targets, _ := enumerateChecked(v4r, v6r)
	return targets
}

func enumerateChecked(v4r, v6r io.Reader) ([]Target, bool) {
	seen := make(map[string]bool)
	var targets []Target
	add := func(host string, port int) {
		key := host + "\x00" + strconv.Itoa(port)
		if seen[key] {
			return
		}
		seen[key] = true
		targets = append(targets, Target{Host: host, Port: port})
	}

	v4, v4OK := parseProc(v4r)
	for _, l := range v4 {
		if denyPorts[l.port] {
			continue
		}
		add(dialHost(l.ip), l.port)
	}
	v6, v6OK := parseProc(v6r)
	for _, l := range v6 {
		if denyPorts[l.port] {
			continue
		}
		add(dialHost(l.ip), l.port)
	}

	targets = collapseDualStackLoopback(targets)
	complete := v4OK && v6OK
	if len(targets) > maxLocalTargets {
		targets = targets[:maxLocalTargets]
		complete = false
	}
	return targets, complete
}

type listener struct {
	ip   netip.Addr
	port int
}

// parseProc parses one /proc/net/tcp{,6} stream and returns its LISTEN
// sockets. The header line and any malformed line are skipped silently.
func parseProc(r io.Reader) ([]listener, bool) {
	var out []listener
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		// Need at least: sl, local_address, rem_address, st.
		if len(fields) < 4 || !strings.EqualFold(fields[3], stateListen) {
			continue
		}
		addr, port, ok := parseLocalAddress(fields[1])
		if !ok {
			continue
		}
		out = append(out, listener{ip: addr, port: port})
	}
	return out, sc.Err() == nil
}

// parseLocalAddress decodes a "HEXIP:HEXPORT" local_address column. IPv4 is
// little-endian per byte; IPv6 is byte-swapped within each 32-bit word.
func parseLocalAddress(s string) (netip.Addr, int, bool) {
	host, portHex, found := strings.Cut(s, ":")
	if !found {
		return netip.Addr{}, 0, false
	}
	port, err := strconv.ParseUint(portHex, 16, 16)
	if err != nil || port == 0 {
		return netip.Addr{}, 0, false
	}
	raw, err := hex.DecodeString(host)
	if err != nil {
		return netip.Addr{}, 0, false
	}
	switch len(raw) {
	case 4:
		return netip.AddrFrom4([4]byte{raw[3], raw[2], raw[1], raw[0]}), int(port), true
	case 16:
		var b [16]byte
		for w := 0; w < 4; w++ { // reverse each 32-bit word
			b[w*4+0] = raw[w*4+3]
			b[w*4+1] = raw[w*4+2]
			b[w*4+2] = raw[w*4+1]
			b[w*4+3] = raw[w*4+0]
		}
		return netip.AddrFrom16(b).Unmap(), int(port), true
	default:
		return netip.Addr{}, 0, false
	}
}

// dialHost maps a bind address to the address to actually connect to. Wildcard
// (0.0.0.0 / ::) and loopback binds are dialed on loopback; a specific bound IP
// is dialed as-is (the service only answers there).
func dialHost(a netip.Addr) string {
	if a.IsUnspecified() || a.IsLoopback() {
		if a.Is4() {
			return "127.0.0.1"
		}
		return "::1"
	}
	return a.String()
}

// collapseDualStackLoopback drops a ::1 target whose port is already covered by
// a 127.0.0.1 target - a dual-stack service (bound on both 0.0.0.0 and ::)
// presents the same certificate on both loopbacks, so one probe is enough.
func collapseDualStackLoopback(in []Target) []Target {
	v4Ports := make(map[int]bool)
	for _, t := range in {
		if t.Host == "127.0.0.1" {
			v4Ports[t.Port] = true
		}
	}
	out := in[:0]
	for _, t := range in {
		if t.Host == "::1" && v4Ports[t.Port] {
			continue
		}
		out = append(out, t)
	}
	return out
}
