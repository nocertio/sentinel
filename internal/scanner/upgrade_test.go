package scanner

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/hex"
	"io"
	"net"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"nocert.io/common/pkg/tlsenum"
	"nocert.io/common/pkg/tlsprobe"
	"nocert.io/sentinel/internal/testutil"
)

type preambleFixture struct {
	name                string
	port                int
	responses, requests []string
}

func upgradeFixtures() []preambleFixture {
	return []preambleFixture{
		{"smtp", 25, []string{"220 fixture\r\n", "250-fixture\r\n250-PIPELINING\r\n250 STARTTLS\r\n", "220 ready\r\n"}, []string{"EHLO sentinel.invalid\r\n", "STARTTLS\r\n"}},
		{"submission", 587, []string{"220 fixture\r\n", "250-fixture\r\n250 STARTTLS\r\n", "220 ready\r\n"}, []string{"EHLO sentinel.invalid\r\n", "STARTTLS\r\n"}},
		{"ftp", 21, []string{"220-fixture\r\n welcome\r\n220 ready\r\n", "234 ready\r\n"}, []string{"AUTH TLS\r\n"}},
		{"pop3", 110, []string{"+OK fixture\r\n", "+OK ready\r\n"}, []string{"STLS\r\n"}},
		{"imap", 143, []string{"* OK fixture\r\n", "* CAPABILITY IMAP4rev1 STARTTLS\r\na001 OK ready\r\n"}, []string{"a001 STARTTLS\r\n"}},
		{"postgres", 5432, []string{"", "S"}, []string{"\x00\x00\x00\x08\x04\xd2\x16\x2f"}},
		{"ldap", 389, []string{"", "\x30\x0c\x02\x01\x01\x78\x07\x0a\x01\x00\x04\x00\x04\x00"}, []string{"\x30\x1d\x02\x01\x01\x77\x18\x80\x161.3.6.1.4.1.1466.20037"}},
		{"rdp", 3389, []string{"", "\x03\x00\x00\x13\x0e\xd0\x00\x00\x12\x34\x00\x02\x00\x08\x00\x02\x00\x00\x00"}, []string{"\x03\x00\x00\x13\x0e\xe0\x00\x00\x00\x00\x00\x01\x00\x08\x00\x0b\x00\x00\x00"}},
	}
}

// Fixtures validate every byte sent before TLS; fragmented writes exercise readers.
func serveUpgrade(conn net.Conn, f preambleFixture) error {
	for i, response := range f.responses {
		if i > 0 {
			got := make([]byte, len(f.requests[i-1]))
			if _, err := io.ReadFull(conn, got); err != nil {
				return err
			}
			if string(got) != f.requests[i-1] {
				return errTLSUpgrade
			}
		}
		for _, b := range []byte(response) {
			if _, err := conn.Write([]byte{b}); err != nil {
				return err
			}
		}
	}
	return nil
}

type redirectDialer struct {
	base  tlsprobe.ContextDialer
	addr  string
	calls atomic.Int32
}

func (d *redirectDialer) DialContext(ctx context.Context, network, _ string) (net.Conn, error) {
	d.calls.Add(1)
	return d.base.DialContext(ctx, network, d.addr)
}

func protocolServer(t *testing.T, f preambleFixture, cert tls.Certificate, version uint16, alpn []string) (string, *atomic.Int32) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	var calls atomic.Int32
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			calls.Add(1)
			_ = c.SetDeadline(time.Now().Add(2 * time.Second))
			if len(f.responses) == 0 || serveUpgrade(c, f) == nil {
				tc := tls.Server(c, &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: version, MaxVersion: version, NextProtos: alpn})
				_ = tc.Handshake()
			}
			_ = c.Close()
		}
	}()
	t.Cleanup(func() { ln.Close(); <-done })
	return ln.Addr().String(), &calls
}

func TestProtocolDiscovery(t *testing.T) {
	cert := testutil.Certificate(t, nil)
	for _, f := range upgradeFixtures() {
		t.Run(f.name, func(t *testing.T) {
			for _, version := range []uint16{tls.VersionTLS12, tls.VersionTLS13} {
				t.Run(tls.VersionName(version), func(t *testing.T) {
					addr, calls := protocolServer(t, f, cert, version, nil)
					d := &redirectDialer{base: &net.Dialer{}, addr: addr}
					result, err := (&tlsProber{dialer: d}).Probe(t.Context(), "127.0.0.1", f.port, time.Second, "")
					require.NoError(t, err)
					require.NotNil(t, result)
					out := (&Scanner{}).probeResultToOutput(f.port, "", result, nil, false)
					require.Equal(t, cert.Certificate, out.Chain)
					require.True(t, *out.TLS.HandshakeComplete)
					require.Equal(t, int32(1), calls.Load())
				})
			}
		})
	}
}

func TestDiscoveryWithoutHTTPALPN(t *testing.T) {
	cert := testutil.Certificate(t, nil)
	for _, version := range []uint16{tls.VersionTLS12, tls.VersionTLS13} {
		for _, alpn := range [][]string{nil, {"mqtt"}, {"h2", "http/1.1"}} {
			t.Run(tls.VersionName(version)+"/"+strings.Join(alpn, ","), func(t *testing.T) {
				addr, calls := protocolServer(t, preambleFixture{}, cert, version, alpn)
				host, p, _ := net.SplitHostPort(addr)
				port, _ := strconv.Atoi(p)
				result, err := (&tlsProber{}).Probe(t.Context(), host, port, time.Second, "")
				require.NoError(t, err)
				require.Equal(t, cert.Certificate[0], result.PeerCerts[0].Raw)
				require.True(t, *result.TLS.HandshakeComplete)
				require.Equal(t, int32(1), calls.Load())
				if version == tls.VersionTLS12 {
					dialer := &net.Dialer{}
					raw, err := tlsenum.Collect(t.Context(), host, port, "", tlsenum.Options{Dialer: dialer, DisableALPN: true})
					require.NoError(t, err)
					require.Equal(t, cert.Certificate, raw.Certificates)
					enum, err := tlsenum.Enumerate(t.Context(), host, port, tlsenum.Options{Dialer: dialer, DisableALPN: true})
					require.NoError(t, err)
					require.NotEmpty(t, enum.Findings)
				}
			})
		}
	}
}

func TestUpgradeRawFallback(t *testing.T) {
	t.Setenv("GODEBUG", "x509negativeserial=0")
	var cert tls.Certificate
	for _, f := range testutil.UnusualCertificates(t) {
		if !f.Parseable {
			cert = f.Certificate
			break
		}
	}
	require.NotEmpty(t, cert.Certificate)
	for _, f := range upgradeFixtures() {
		t.Run(f.name, func(t *testing.T) {
			addr, calls := protocolServer(t, f, cert, tls.VersionTLS12, nil)
			d := &redirectDialer{base: &net.Dialer{}, addr: addr}
			result, err := (&tlsProber{dialer: d}).Probe(t.Context(), "127.0.0.1", f.port, time.Second, "")
			require.NoError(t, err)
			require.False(t, *result.TLS.HandshakeComplete)
			require.Equal(t, cert.Certificate, result.RawChain)
			require.Equal(t, int32(2), calls.Load())
		})
	}
}

type scriptedConn struct {
	net.Conn
	input  *bytes.Reader
	output bytes.Buffer
}

func (c *scriptedConn) Read(b []byte) (int, error)  { return c.input.Read(b) }
func (c *scriptedConn) Write(b []byte) (int, error) { return c.output.Write(b) }

func TestUpgradeRejectsMalformedResponses(t *testing.T) {
	cases := []struct {
		name     string
		port     int
		response string
	}{
		{"smtp_refusal", 25, "554 no\r\n"},
		{"smtp_missing_capability", 25, "220 ready\r\n250 fixture\r\n"},
		{"smtp_capability_suffix", 25, "220 ready\r\n250-fixture\r\n250 STARTTLSX\r\n"},
		{"smtp_changed_code", 25, "220-fixture\r\n250 ready\r\n"},
		{"smtp_too_long", 25, "220 " + strings.Repeat("x", 4096) + "\r\n"},
		{"smtp_too_many_lines", 25, strings.Repeat("220-x\r\n", 65)},
		{"smtp_byte_budget", 25, strings.Repeat("220-"+strings.Repeat("x", 1000)+"\r\n", 17)},
		{"pop_prefix", 110, "+OKAY ready\r\n"},
		{"imap_preauth", 143, "* PREAUTH ready\r\n"},
		{"imap_bye", 143, "* OK ready\r\n* BYE closing\r\n"},
		{"imap_wrong_tag", 143, "* OK ready\r\na002 OK ready\r\n"},
		{"postgres_refusal", 5432, "N"},
		{"rdp_no_tls", 3389, "\x03\x00\x00\x0b"},
		{"rdp_oversized", 3389, "\x03\x00\xff\xff"},
		{"ldap_indefinite", 389, "\x30\x80"},
		{"ldap_oversized", 389, "\x30\x82\x10\x01"},
	}
	for _, f := range upgradeFixtures() {
		for i := 0; i < len(f.responses[len(f.responses)-1]); i++ {
			responses := append([]string(nil), f.responses...)
			responses[len(responses)-1] = responses[len(responses)-1][:i]
			cases = append(cases, struct {
				name     string
				port     int
				response string
			}{f.name + "_truncated_" + strconv.Itoa(i), f.port, strings.Join(responses, "")})
		}
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := &scriptedConn{input: bytes.NewReader([]byte(tc.response))}
			require.Error(t, upgradeTLS(c, tc.port))
		})
	}
	// A failure code must not be mistaken for an accepted RDP security protocol.
	rdp := upgradeFixtures()[7].responses[1]
	for _, index := range []int{5, 11, 13, 15} {
		response := []byte(rdp)
		response[index] = 0
		require.Error(t, upgradeTLS(&scriptedConn{input: bytes.NewReader(response)}, 3389))
	}
}

func TestUpgradeCancellationAndBudgetRelease(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer ln.Close()
	for _, cancelled := range []bool{false, true} {
		hosts := &hostBudget{}
		ticks := make(chan time.Time, 2)
		ticks <- time.Now()
		ticks <- time.Now()
		base := &scanDialer{hosts: hosts, ticks: ticks}
		d := &redirectDialer{base: base, addr: ln.Addr().String()}
		ctx, cancel := context.WithCancel(t.Context())
		done := make(chan error, 1)
		go func() {
			_, err := (&tlsProber{dialer: d}).Probe(ctx, "127.0.0.1", 25, 50*time.Millisecond, "")
			done <- err
		}()
		conn, err := ln.Accept()
		require.NoError(t, err)
		if cancelled {
			cancel()
		}
		select {
		case err := <-done:
			require.Error(t, err)
		case <-time.After(time.Second):
			t.Fatal("upgrade did not stop")
		}
		cancel()
		conn.Close()
		require.Equal(t, int32(1), d.calls.Load(), "no raw retry after failed preamble")
		hosts.mu.Lock()
		require.Empty(t, hosts.hosts)
		hosts.mu.Unlock()
	}
}

func FuzzLDAPUpgrade(f *testing.F) {
	for _, s := range []string{"02010178070a010004000400", "0201017881070a010004000400"} {
		b, _ := hex.DecodeString(s)
		f.Add(b)
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		if len(b) <= 4096 {
			_ = parseLDAPUpgrade(b)
		}
	})
}

func TestUpgradeEnumeration(t *testing.T) {
	cert := testutil.Certificate(t, nil)
	for _, f := range upgradeFixtures() {
		t.Run(f.name, func(t *testing.T) {
			addr, calls := protocolServer(t, f, cert, tls.VersionTLS12, nil)
			d := upgradeDialer{base: &redirectDialer{base: &net.Dialer{}, addr: addr}}
			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
			defer cancel()
			result, err := tlsenum.Enumerate(ctx, "127.0.0.1", f.port, tlsenum.Options{Dialer: d, DisableALPN: true, HandshakeTimeout: time.Second})
			require.NoError(t, err)
			require.NotEmpty(t, result.Findings)
			require.Greater(t, calls.Load(), int32(1))
			for _, finding := range result.Findings {
				require.Equal(t, uint16(tls.VersionTLS12), finding.VersionID)
			}
		})
	}
}

func TestLDAPUpgradeResponse(t *testing.T) {
	for _, tc := range []struct {
		hex string
		ok  bool
	}{
		{"02010178070a010004000400", true},
		{"0201017881070a010004000400", true},
		{"020101781f0a0100040004008a16312e332e362e312e342e312e313436362e3230303337", true},
		{"02010278070a010004000400", false},
		{"02010178070a010104000400", false},
		{"02010178080a02000004000400", false},
		{"02010178070a01000400040000", false},
		{"020101780a0a0100040004008a0178", false},
	} {
		b, err := hex.DecodeString(tc.hex)
		require.NoError(t, err)
		require.Equal(t, tc.ok, parseLDAPUpgrade(b) == nil, tc.hex)
	}
}

func TestRDPSelectedProtocol(t *testing.T) {
	for _, selection := range []byte{0, 1, 2, 3, 4, 8, 11} {
		response := []byte(upgradeFixtures()[7].responses[1])
		response[15] = selection
		err := upgradeTLS(&scriptedConn{input: bytes.NewReader(response)}, 3389)
		require.Equal(t, selection == 1 || selection == 2 || selection == 8, err == nil)
	}
}

func TestSMTPReplyWithoutText(t *testing.T) {
	r := &upgradeReader{r: bufio.NewReader(strings.NewReader("220\r\n"))}
	_, err := r.reply("220", false)
	require.NoError(t, err)
}
