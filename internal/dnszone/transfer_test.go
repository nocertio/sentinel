package dnszone

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/net/dns/dnsmessage"

	commonsentinel "nocert.io/common/pkg/api/sentinel"
)

// fakeServer accepts one connection, checks it carries an AXFR query and hands
// it to answer with the query ID.
func fakeServer(t *testing.T, answer func(conn net.Conn, id uint16)) netip.AddrPort {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer func() { _ = conn.Close() }()
		var size [2]byte
		if _, err := io.ReadFull(conn, size[:]); err != nil {
			return
		}
		query := make([]byte, binary.BigEndian.Uint16(size[:]))
		if _, err := io.ReadFull(conn, query); err != nil {
			return
		}
		var p dnsmessage.Parser
		h, err := p.Start(query)
		if err != nil {
			return
		}
		q, err := p.Question()
		if err != nil || q.Type != dnsmessage.TypeAXFR {
			return
		}
		answer(conn, h.ID)
	}()
	return netip.MustParseAddrPort(ln.Addr().String())
}

type rr struct {
	name string
	body dnsmessage.ResourceBody
}

func soa(zone string) rr {
	return rr{zone, &dnsmessage.SOAResource{NS: mustName("ns1." + zone), MBox: mustName("hostmaster." + zone), Serial: 1}}
}

func a(name, ip string) rr {
	return rr{name, &dnsmessage.AResource{A: netip.MustParseAddr(ip).As4()}}
}

func mustName(s string) dnsmessage.Name {
	return dnsmessage.MustNewName(s)
}

func writeMessage(t *testing.T, conn net.Conn, id uint16, rcode dnsmessage.RCode, records ...rr) {
	t.Helper()
	_, _ = conn.Write(buildMessage(t, id, rcode, records...))
}

// buildMessage returns one length-prefixed AXFR answer message.
func buildMessage(t testing.TB, id uint16, rcode dnsmessage.RCode, records ...rr) []byte {
	t.Helper()
	b := dnsmessage.NewBuilder(make([]byte, 2, 512), dnsmessage.Header{ID: id, Response: true, Authoritative: true, RCode: rcode})
	b.EnableCompression()
	require.NoError(t, b.StartAnswers())
	for _, r := range records {
		h := dnsmessage.ResourceHeader{Name: mustName(r.name), Class: dnsmessage.ClassINET, TTL: 300}
		var err error
		switch body := r.body.(type) {
		case *dnsmessage.SOAResource:
			err = b.SOAResource(h, *body)
		case *dnsmessage.AResource:
			err = b.AResource(h, *body)
		case *dnsmessage.AAAAResource:
			err = b.AAAAResource(h, *body)
		case *dnsmessage.CNAMEResource:
			err = b.CNAMEResource(h, *body)
		case *dnsmessage.TXTResource:
			err = b.TXTResource(h, *body)
		default:
			t.Fatalf("unsupported record %T", body)
		}
		require.NoError(t, err)
	}
	msg, err := b.Finish()
	require.NoError(t, err)
	binary.BigEndian.PutUint16(msg, uint16(len(msg)-2))
	return msg
}

func tlsSet(ips ...string) map[netip.Addr]bool {
	m := map[netip.Addr]bool{}
	for _, ip := range ips {
		m[netip.MustParseAddr(ip)] = true
	}
	return m
}

func run(t *testing.T, server netip.AddrPort, tls map[netip.Addr]bool) commonsentinel.DNSZoneResult {
	t.Helper()
	res := commonsentinel.DNSZoneResult{Name: "corp.lan", Server: server.Addr().String()}
	return transfer(context.Background(), res, "corp.lan", server, tls)
}

func TestTransferKeepsOnlyNamesPointingToTLSAddresses(t *testing.T) {
	server := fakeServer(t, func(conn net.Conn, id uint16) {
		writeMessage(t, conn, id, dnsmessage.RCodeSuccess,
			soa("corp.lan."),
			a("corp.lan.", "10.0.0.5"),
			a("WWW.corp.lan.", "10.0.0.5"),
			a("pc-jdupont.corp.lan.", "10.0.0.77"),
			rr{"app.corp.lan.", &dnsmessage.CNAMEResource{CNAME: mustName("www.corp.lan.")}},
			rr{"chain.corp.lan.", &dnsmessage.CNAMEResource{CNAME: mustName("app.corp.lan.")}},
			rr{"ext.corp.lan.", &dnsmessage.CNAMEResource{CNAME: mustName("cdn.example.net.")}},
			a("cdn.example.net.", "10.0.0.5"),
			rr{"loop.corp.lan.", &dnsmessage.CNAMEResource{CNAME: mustName("loop.corp.lan.")}},
			a("Kiosk.corp.lan.", "10.0.0.5"),
		)
		writeMessage(t, conn, id, dnsmessage.RCodeSuccess,
			rr{"v6.corp.lan.", &dnsmessage.AAAAResource{AAAA: netip.MustParseAddr("fd00::5").As16()}},
			a("*.wild.corp.lan.", "10.0.0.5"),
			rr{"txt.corp.lan.", &dnsmessage.TXTResource{TXT: []string{"v=spf1 -all"}}},
			soa("corp.lan."),
		)
	})

	// The out-of-zone A record anchors nothing and the Kelvin-sign label is not
	// folded into "kiosk".
	res := run(t, server, tlsSet("10.0.0.5", "fd00::5"))
	assert.Equal(t, commonsentinel.DNSZoneStatusOK, res.Status)
	assert.Equal(t, 14, res.Records)
	assert.Equal(t, []string{"app.corp.lan", "chain.corp.lan", "corp.lan", "v6.corp.lan", "www.corp.lan"}, res.Hostnames)
	assert.Equal(t, "127.0.0.1", res.SourceAddress)
}

func TestTransferStatuses(t *testing.T) {
	cases := map[string]struct {
		answer func(t *testing.T, conn net.Conn, id uint16)
		want   string
	}{
		"refused": {func(t *testing.T, conn net.Conn, id uint16) {
			writeMessage(t, conn, id, dnsmessage.RCodeRefused)
		}, commonsentinel.DNSZoneStatusRefused},
		"notauth": {func(t *testing.T, conn net.Conn, id uint16) {
			writeMessage(t, conn, id, dnsmessage.RCode(9))
		}, commonsentinel.DNSZoneStatusRefused},
		"hang up without answering": {func(t *testing.T, conn net.Conn, id uint16) {}, commonsentinel.DNSZoneStatusRefused},
		"server failure": {func(t *testing.T, conn net.Conn, id uint16) {
			writeMessage(t, conn, id, dnsmessage.RCodeServerFailure)
		}, commonsentinel.DNSZoneStatusFailed},
		"first record is not the zone SOA": {func(t *testing.T, conn net.Conn, id uint16) {
			writeMessage(t, conn, id, dnsmessage.RCodeSuccess, a("www.corp.lan.", "10.0.0.5"), soa("corp.lan."))
		}, commonsentinel.DNSZoneStatusFailed},
		"SOA of another zone": {func(t *testing.T, conn net.Conn, id uint16) {
			writeMessage(t, conn, id, dnsmessage.RCodeSuccess, soa("other.lan."), soa("other.lan."))
		}, commonsentinel.DNSZoneStatusFailed},
		"wrong query ID": {func(t *testing.T, conn net.Conn, id uint16) {
			writeMessage(t, conn, id+1, dnsmessage.RCodeSuccess, soa("corp.lan."), soa("corp.lan."))
		}, commonsentinel.DNSZoneStatusFailed},
		"cut before the closing SOA": {func(t *testing.T, conn net.Conn, id uint16) {
			writeMessage(t, conn, id, dnsmessage.RCodeSuccess, soa("corp.lan."), a("www.corp.lan.", "10.0.0.5"))
		}, commonsentinel.DNSZoneStatusFailed},
		"garbage": {func(t *testing.T, conn net.Conn, id uint16) {
			_, _ = conn.Write([]byte{0, 3, 1, 2, 3})
		}, commonsentinel.DNSZoneStatusFailed},
		"empty message": {func(t *testing.T, conn net.Conn, id uint16) {
			_, _ = conn.Write([]byte{0, 0})
		}, commonsentinel.DNSZoneStatusFailed},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			server := fakeServer(t, func(conn net.Conn, id uint16) { tc.answer(t, conn, id) })
			res := run(t, server, tlsSet("10.0.0.5"))
			assert.Equal(t, tc.want, res.Status)
			assert.Empty(t, res.Hostnames)
		})
	}
}

func TestTransferUnreachable(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	closed := netip.MustParseAddrPort(ln.Addr().String())
	require.NoError(t, ln.Close())
	assert.Equal(t, commonsentinel.DNSZoneStatusUnreachable, run(t, closed, nil).Status)

	silent := fakeServer(t, func(conn net.Conn, id uint16) { time.Sleep(2 * time.Second) })
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	res := transfer(ctx, commonsentinel.DNSZoneResult{}, "corp.lan", silent, nil)
	assert.Equal(t, commonsentinel.DNSZoneStatusUnreachable, res.Status)
}

func TestTransferCapsKeptNames(t *testing.T) {
	server := fakeServer(t, func(conn net.Conn, id uint16) {
		writeMessage(t, conn, id, dnsmessage.RCodeSuccess, soa("corp.lan."))
		batch := []rr{}
		for i := range maxHostnames + 1 {
			batch = append(batch, a(fmt.Sprintf("h%04d.corp.lan.", i), "10.0.0.5"))
			if len(batch) == 500 {
				writeMessage(t, conn, id, dnsmessage.RCodeSuccess, batch...)
				batch = batch[:0]
			}
		}
		writeMessage(t, conn, id, dnsmessage.RCodeSuccess, append(batch, soa("corp.lan."))...)
	})
	res := run(t, server, tlsSet("10.0.0.5"))
	assert.Equal(t, commonsentinel.DNSZoneStatusTooLarge, res.Status)
	assert.Len(t, res.Hostnames, maxHostnames)
	assert.Equal(t, "h0000.corp.lan", res.Hostnames[0])
}

func TestTransferCapsRecords(t *testing.T) {
	server := fakeServer(t, func(conn net.Conn, id uint16) {
		writeMessage(t, conn, id, dnsmessage.RCodeSuccess, soa("corp.lan."), a("www.corp.lan.", "10.0.0.5"))
		batch := []rr{}
		for i := range maxRecords {
			batch = append(batch, a(fmt.Sprintf("pc%06d.corp.lan.", i), "10.1.0.1"))
			if len(batch) == 2000 {
				writeMessage(t, conn, id, dnsmessage.RCodeSuccess, batch...)
				batch = batch[:0]
			}
		}
	})
	res := run(t, server, tlsSet("10.0.0.5"))
	assert.Equal(t, commonsentinel.DNSZoneStatusTooLarge, res.Status)
	assert.Equal(t, maxRecords, res.Records)
	assert.Equal(t, []string{"www.corp.lan"}, res.Hostnames)
}

func TestTransferRejectsBadConfiguration(t *testing.T) {
	for _, zone := range []commonsentinel.DNSZone{
		{Name: "*.corp.lan", Server: "10.0.0.10"},
		{Name: "corp.lan", Server: "dns.corp.lan"},
		{Name: "corp.lan", Server: "fe80::1%eth0"},
		{Name: "corp.lan", Server: "0.0.0.0"},
		{Name: "corp.lan", Server: "::"},
		{Name: "corp.lan", Server: "224.0.0.251"},
	} {
		res := Transfer(context.Background(), zone, nil)
		assert.Equal(t, commonsentinel.DNSZoneStatusFailed, res.Status, zone)
		assert.Equal(t, zone.Name, res.Name)
		assert.Equal(t, zone.Server, res.Server)
	}
}

func TestAXFRQueryShape(t *testing.T) {
	msg, err := axfrQuery(0x1234, "corp.lan")
	require.NoError(t, err)
	require.Equal(t, len(msg)-2, int(binary.BigEndian.Uint16(msg)))
	var p dnsmessage.Parser
	h, err := p.Start(msg[2:])
	require.NoError(t, err)
	assert.Equal(t, uint16(0x1234), h.ID)
	assert.False(t, h.Response)
	assert.False(t, h.RecursionDesired)
	q, err := p.Question()
	require.NoError(t, err)
	assert.Equal(t, "corp.lan.", q.Name.String())
	assert.Equal(t, dnsmessage.TypeAXFR, q.Type)
	assert.Equal(t, dnsmessage.ClassINET, q.Class)
}
