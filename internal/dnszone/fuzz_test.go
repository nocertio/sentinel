package dnszone

import (
	"bytes"
	"io"
	"slices"
	"strings"
	"testing"

	"golang.org/x/net/dns/dnsmessage"

	commonsentinel "nocert.io/common/pkg/api/sentinel"
)

type answerConn struct{ io.Reader }

func (answerConn) Write(p []byte) (int, error) { return len(p), nil }

const fuzzID = 0x1234

// FuzzTransferAnswer feeds arbitrary server answers to the AXFR reader: it must
// end on every input, stay within its caps and only ever keep in-zone names.
func FuzzTransferAnswer(f *testing.F) {
	valid := slices.Concat(
		buildMessage(f, fuzzID, dnsmessage.RCodeSuccess, soa("corp.lan."), a("www.corp.lan.", "10.0.0.5"),
			rr{"app.corp.lan.", &dnsmessage.CNAMEResource{CNAME: mustName("www.corp.lan.")}}),
		buildMessage(f, fuzzID, dnsmessage.RCodeSuccess, soa("corp.lan.")),
	)
	f.Add(valid)
	f.Add(buildMessage(f, fuzzID, dnsmessage.RCodeRefused))
	f.Add([]byte{0, 0})
	f.Fuzz(func(t *testing.T, answer []byte) {
		if len(answer) > 1<<20 {
			t.Skip()
		}
		c := collector{zone: "corp.lan", matched: map[string]bool{}, cname: map[string]string{}, tlsAddrs: tlsSet("10.0.0.5")}
		status := c.read(answerConn{bytes.NewReader(answer)}, fuzzID)
		switch status {
		case commonsentinel.DNSZoneStatusOK, commonsentinel.DNSZoneStatusRefused, commonsentinel.DNSZoneStatusUnreachable,
			commonsentinel.DNSZoneStatusTooLarge, commonsentinel.DNSZoneStatusFailed:
		default:
			t.Fatalf("status %q outside the wire enum", status)
		}
		if c.records > maxRecords {
			t.Fatalf("%d records read", c.records)
		}
		names, _ := c.hostnames()
		if len(names) > maxHostnames {
			t.Fatalf("%d names kept", len(names))
		}
		for _, n := range names {
			if _, ok := normalizeName(n); !ok || (n != "corp.lan" && !strings.HasSuffix(n, ".corp.lan")) {
				t.Fatalf("kept %q", n)
			}
		}
	})
}
