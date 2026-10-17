package listeners

import (
	"io"
	"net/netip"
	"strconv"
	"strings"
	"testing"
)

// Real /proc/net/tcp{,6} lines. Column layout:
//
//	sl  local_address rem_address st ...
//
// local_address is HEXIP:HEXPORT; st 0A == LISTEN. IPv4 is little-endian
// per-byte (0100007F == 127.0.0.1, 01BB == port 443); the wildcard 00000000
// == 0.0.0.0. IPv6 is byte-swapped within each 32-bit word.
const procTCPv4 = `  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 0100007F:01BB 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 1
   1: 00000000:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 2
   2: 0500000A:01BB 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 3
   3: 0100007F:0016 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 4
   4: 0100007F:115C 0100007F:01BB 01 00000000:00000000 00:00000000 00000000     0        0 5
   5: 00000000:0019 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 6
`

// :01BB=443, :1F90=8080, 0500000A=10.0.0.5, :0016=22 (SSH, denylisted),
// :0019=25 (SMTP, denylisted), line 4 is st 01 (ESTABLISHED) -> skipped.

const procTCPv6 = `  sl  local_address                         remote_address                        st ...
   0: 00000000000000000000000001000000:1F91 00000000000000000000000000000000:0000 0A 0
   1: 00000000000000000000000000000000:01BB 00000000000000000000000000000000:0000 0A 0
   2: 00000000000000000000000000000000:1F90 00000000000000000000000000000000:0000 0A 0
`

// v6 line 0: ...01000000 == ::1 (loopback), :1F91=8081
// v6 line 1: all-zero == :: (wildcard), :01BB=443  -> collapses with v4 127.0.0.1:443
// v6 line 2: :: wildcard :1F90=8080 -> collapses with v4 0.0.0.0:8080 -> 127.0.0.1:8080

func collect(targets []Target) map[string]bool {
	out := make(map[string]bool, len(targets))
	for _, t := range targets {
		out[t.Host+":"+strconv.Itoa(t.Port)] = true
	}
	return out
}

func TestEnumerate_DecodesAndFiltersListeners(t *testing.T) {
	got := collect(enumerate(strings.NewReader(procTCPv4), strings.NewReader(procTCPv6)))

	want := []string{
		"127.0.0.1:443",  // v4 loopback 0100007F:01BB
		"127.0.0.1:8080", // v4 wildcard 00000000:1F90 -> loopback
		"10.0.0.5:443",   // v4 specific bind -> dialed as-is
		"::1:8081",       // v6 loopback :1F91
	}
	for _, w := range want {
		if !got[w] {
			t.Errorf("missing target %q in %v", w, got)
		}
	}

	// SSH (22) and SMTP (25) are denylisted -> never probed.
	if got["127.0.0.1:22"] {
		t.Errorf("denylisted port 22 should be skipped, got %v", got)
	}
	if got["127.0.0.1:25"] {
		t.Errorf("denylisted port 25 should be skipped, got %v", got)
	}
	// ESTABLISHED socket (st 01) is not a listener.
	if got["127.0.0.1:4444"] {
		t.Errorf("non-LISTEN socket should be skipped")
	}
}

func TestEnumerate_CollapsesDualStackLoopback(t *testing.T) {
	got := collect(enumerate(strings.NewReader(procTCPv4), strings.NewReader(procTCPv6)))

	// 443 listens on both v4 (loopback) and v6 (::) -> only the v4 loopback
	// probe is kept; the ::1:443 duplicate is dropped (same cert, same backend
	// doc, no point dialing twice).
	if got["::1:443"] {
		t.Errorf("dual-stack loopback should collapse to v4, got ::1:443 in %v", got)
	}
	if !got["127.0.0.1:443"] {
		t.Errorf("expected collapsed 127.0.0.1:443")
	}
	// 8080 listens on v4 wildcard and v6 wildcard -> collapse to 127.0.0.1:8080.
	if got["::1:8080"] {
		t.Errorf("dual-stack 8080 should collapse to v4")
	}
}

func TestEnumerate_EmptyAndGarbageLinesAreIgnored(t *testing.T) {
	in := "  sl  local_address ...\n   0: GARBAGE 00000000:0000 0A 0\n   bad line\n"
	got := enumerate(strings.NewReader(in), strings.NewReader(""))
	if len(got) != 0 {
		t.Errorf("garbage should yield no targets, got %v", got)
	}
}

func TestOpenProc_MissingFileDegradesGracefully(t *testing.T) {
	r, closeFn := openProc("/proc/does-not-exist-nocert-test")
	defer closeFn()
	b, err := io.ReadAll(r)
	if err != nil {
		t.Fatalf("reader from missing file errored: %v", err)
	}
	if len(b) != 0 {
		t.Errorf("expected empty reader, got %q", b)
	}
}

func TestEnumerate_MissingProcYieldsNoTargets(t *testing.T) {
	r4, close4 := openProc("/proc/does-not-exist-nocert-test-4")
	defer close4()
	r6, close6 := openProc("/proc/does-not-exist-nocert-test-6")
	defer close6()
	if got := enumerate(r4, r6); len(got) != 0 {
		t.Errorf("missing /proc should yield no targets, got %v", got)
	}
}

func TestParseLocalAddress(t *testing.T) {
	tests := []struct {
		name     string
		in       string
		wantOK   bool
		wantIP   string
		wantPort int
	}{
		{name: "ipv4 loopback", in: "0100007F:01BB", wantOK: true, wantIP: "127.0.0.1", wantPort: 443},
		{name: "ipv6 loopback", in: "00000000000000000000000001000000:1F91", wantOK: true, wantIP: "::1", wantPort: 8081},
		{name: "non-hex host", in: "ZZZZ:01BB", wantOK: false},
		{name: "three-byte hex", in: "010203:01BB", wantOK: false},
		{name: "six-byte hex", in: "010203040506:01BB", wantOK: false},
		{name: "missing colon", in: "0100007F01BB", wantOK: false},
		{name: "port zero", in: "0100007F:0000", wantOK: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			addr, port, ok := parseLocalAddress(tt.in)
			if ok != tt.wantOK {
				t.Fatalf("ok = %v, want %v", ok, tt.wantOK)
			}
			if !tt.wantOK {
				return
			}
			if addr.String() != tt.wantIP {
				t.Errorf("ip = %q, want %q", addr.String(), tt.wantIP)
			}
			if port != tt.wantPort {
				t.Errorf("port = %d, want %d", port, tt.wantPort)
			}
		})
	}
}

func TestParseLocalAddress_IPv4MappedIsUnmapped(t *testing.T) {
	// "::ffff:127.0.0.1" as it appears in /proc/net/tcp6: 32-bit words
	// byte-swapped, so the final two words are FFFF0000 and 0100007F.
	const in = "0000000000000000FFFF00000100007F:01BB"
	addr, _, ok := parseLocalAddress(in)
	if !ok {
		t.Fatal("expected parse to succeed")
	}
	if addr != netip.MustParseAddr("127.0.0.1") {
		t.Errorf("expected unmapped 127.0.0.1, got %q (Is4=%v)", addr, addr.Is4())
	}
}

func TestEnumerate_CapsTargets(t *testing.T) {
	var b strings.Builder
	b.WriteString("  sl  local_address rem_address st\n")
	// 0x3000 distinct loopback ports, all LISTEN -> must be capped.
	for p := 0x3000; p < 0x3000+maxLocalTargets+50; p++ {
		b.WriteString("   0: 0100007F:")
		b.WriteString(strings.ToUpper(strconv.FormatInt(int64(p), 16)))
		b.WriteString(" 00000000:0000 0A 0\n")
	}
	got, complete := enumerateChecked(strings.NewReader(b.String()), strings.NewReader(""))
	if len(got) > maxLocalTargets {
		t.Errorf("target count %d exceeds cap %d", len(got), maxLocalTargets)
	}
	if complete {
		t.Error("a capped enumeration must not authorize destructive reconciliation")
	}
}
