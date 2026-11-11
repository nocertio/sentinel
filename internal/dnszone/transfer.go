package dnszone

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"math/rand/v2"
	"net"
	"net/netip"
	"sort"
	"strings"
	"time"

	"golang.org/x/net/dns/dnsmessage"

	commonsentinel "nocert.io/common/pkg/api/sentinel"
)

// Limits of one zone transfer. The server is on the customer network, but its
// answer is still parsed as untrusted input.
const (
	dialTimeout      = 10 * time.Second
	transferTimeout  = 2 * time.Minute
	maxTransferBytes = 64 << 20
	maxRecords       = 100_000
	maxHostnames     = 1_000
	maxCNAMEHops     = 8
)

// Transfer reads zone.Name from zone.Server with a standard zone transfer
// (AXFR, RFC 5936) over TCP port 53. It returns only the names whose A or AAAA
// record, directly or through CNAMEs inside the zone, points to one of
// tlsAddrs. The rest of the zone is dropped here.
func Transfer(ctx context.Context, zone commonsentinel.DNSZone, tlsAddrs map[netip.Addr]bool) commonsentinel.DNSZoneResult {
	res := commonsentinel.DNSZoneResult{Name: zone.Name, Server: zone.Server, Status: commonsentinel.DNSZoneStatusFailed}
	name, ok := normalizeName(zone.Name)
	server, err := netip.ParseAddr(zone.Server)
	if !ok || err != nil || server.Zone() != "" || server.IsUnspecified() || server.IsMulticast() {
		return res
	}
	return transfer(ctx, res, name, netip.AddrPortFrom(server.Unmap(), 53), tlsAddrs)
}

func transfer(ctx context.Context, res commonsentinel.DNSZoneResult, name string, server netip.AddrPort, tlsAddrs map[netip.Addr]bool) commonsentinel.DNSZoneResult {
	ctx, cancel := context.WithTimeout(ctx, transferTimeout)
	defer cancel()
	dialer := net.Dialer{Timeout: dialTimeout}
	conn, err := dialer.DialContext(ctx, "tcp", server.String())
	if err != nil {
		res.Status = commonsentinel.DNSZoneStatusUnreachable
		return res
	}
	defer func() { _ = conn.Close() }()
	if local, ok := conn.LocalAddr().(*net.TCPAddr); ok {
		res.SourceAddress = local.AddrPort().Addr().Unmap().String()
	}
	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	}
	stop := context.AfterFunc(ctx, func() { _ = conn.SetDeadline(time.Unix(1, 0)) })
	defer stop()

	c := collector{zone: name, matched: map[string]bool{}, cname: map[string]string{}, tlsAddrs: tlsAddrs}
	res.Status = c.read(conn, uint16(rand.Uint32()))
	res.Records = c.records
	if res.Status == commonsentinel.DNSZoneStatusOK || res.Status == commonsentinel.DNSZoneStatusTooLarge {
		var truncated bool
		res.Hostnames, truncated = c.hostnames()
		if truncated {
			res.Status = commonsentinel.DNSZoneStatusTooLarge
		}
	}
	return res
}

type collector struct {
	zone     string
	tlsAddrs map[netip.Addr]bool
	records  int
	// matched holds owner names (with trailing dot) that have an address in
	// tlsAddrs; cname maps an owner name to its CNAME target.
	matched map[string]bool
	cname   map[string]string
}

// read sends the AXFR query with this ID and consumes answers until the
// closing SOA.
func (c *collector) read(conn io.ReadWriter, id uint16) string {
	query, err := axfrQuery(id, c.zone)
	if err != nil {
		return commonsentinel.DNSZoneStatusFailed
	}
	if _, err := conn.Write(query); err != nil {
		return commonsentinel.DNSZoneStatusUnreachable
	}

	apex := c.zone + "."
	buf := make([]byte, 65535)
	var size [2]byte
	total, messages := 0, 0
	for {
		if _, err := io.ReadFull(conn, size[:]); err != nil {
			return readFailure(err, messages)
		}
		n := int(binary.BigEndian.Uint16(size[:]))
		total += n + 2
		if total > maxTransferBytes {
			return commonsentinel.DNSZoneStatusTooLarge
		}
		if _, err := io.ReadFull(conn, buf[:n]); err != nil {
			return readFailure(err, messages)
		}
		messages++

		var p dnsmessage.Parser
		h, err := p.Start(buf[:n])
		if err != nil || h.ID != id || !h.Response {
			return commonsentinel.DNSZoneStatusFailed
		}
		switch h.RCode {
		case dnsmessage.RCodeSuccess:
		case dnsmessage.RCodeRefused, dnsmessage.RCodeNotImplemented, dnsmessage.RCode(9): // 9 = NOTAUTH, not named by dnsmessage
			return commonsentinel.DNSZoneStatusRefused
		default:
			return commonsentinel.DNSZoneStatusFailed
		}
		if err := p.SkipAllQuestions(); err != nil {
			return commonsentinel.DNSZoneStatusFailed
		}
		for {
			ah, err := p.AnswerHeader()
			if errors.Is(err, dnsmessage.ErrSectionDone) {
				break
			}
			if err != nil {
				return commonsentinel.DNSZoneStatusFailed
			}
			c.records++
			if c.records > maxRecords {
				c.records = maxRecords
				return commonsentinel.DNSZoneStatusTooLarge
			}
			owner := asciiLower(ah.Name.String())
			if c.records == 1 && (ah.Type != dnsmessage.TypeSOA || owner != apex) {
				return commonsentinel.DNSZoneStatusFailed
			}
			switch ah.Type {
			case dnsmessage.TypeSOA:
				if err := p.SkipAnswer(); err != nil {
					return commonsentinel.DNSZoneStatusFailed
				}
				if c.records > 1 {
					// The transfer ends with the zone's SOA record repeated.
					return commonsentinel.DNSZoneStatusOK
				}
			case dnsmessage.TypeA:
				r, err := p.AResource()
				if err != nil {
					return commonsentinel.DNSZoneStatusFailed
				}
				c.address(owner, netip.AddrFrom4(r.A))
			case dnsmessage.TypeAAAA:
				r, err := p.AAAAResource()
				if err != nil {
					return commonsentinel.DNSZoneStatusFailed
				}
				c.address(owner, netip.AddrFrom16(r.AAAA).Unmap())
			case dnsmessage.TypeCNAME:
				r, err := p.CNAMEResource()
				if err != nil {
					return commonsentinel.DNSZoneStatusFailed
				}
				c.cname[owner] = asciiLower(r.CNAME.String())
			default:
				if err := p.SkipAnswer(); err != nil {
					return commonsentinel.DNSZoneStatusFailed
				}
			}
		}
	}
}

// address records an in-zone owner pointing to a TLS address. Out-of-zone
// records, which only a misbehaving server sends, never anchor a CNAME chain.
func (c *collector) address(owner string, addr netip.Addr) {
	if c.tlsAddrs[addr] && (owner == c.zone+"." || strings.HasSuffix(owner, "."+c.zone+".")) {
		c.matched[owner] = true
	}
}

// hostnames returns the kept names inside the zone, sorted, at most
// maxHostnames; truncated reports that some were cut.
func (c *collector) hostnames() (names []string, truncated bool) {
	keep := map[string]bool{}
	for owner := range c.matched {
		keep[owner] = true
	}
	for owner, target := range c.cname {
		for range maxCNAMEHops {
			if c.matched[target] {
				keep[owner] = true
				break
			}
			next, ok := c.cname[target]
			if !ok {
				break
			}
			target = next
		}
	}
	names = []string{}
	for owner := range keep {
		name, ok := normalizeName(owner)
		if ok && (name == c.zone || strings.HasSuffix(name, "."+c.zone)) {
			names = append(names, name)
		}
	}
	sort.Strings(names)
	if len(names) > maxHostnames {
		return names[:maxHostnames], true
	}
	return names, false
}

func axfrQuery(id uint16, zone string) ([]byte, error) {
	qname, err := dnsmessage.NewName(zone + ".")
	if err != nil {
		return nil, err
	}
	// The first two bytes are the TCP length prefix, filled in below.
	b := dnsmessage.NewBuilder(make([]byte, 2, 512), dnsmessage.Header{ID: id})
	if err := b.StartQuestions(); err != nil {
		return nil, err
	}
	if err := b.Question(dnsmessage.Question{Name: qname, Type: dnsmessage.TypeAXFR, Class: dnsmessage.ClassINET}); err != nil {
		return nil, err
	}
	msg, err := b.Finish()
	if err != nil {
		return nil, err
	}
	binary.BigEndian.PutUint16(msg, uint16(len(msg)-2))
	return msg, nil
}

// readFailure classifies a connection that ended before the closing SOA. A
// server that hangs up on the query without answering is refusing the
// transfer; one that goes silent never answered at all.
func readFailure(err error, messages int) string {
	if messages > 0 {
		return commonsentinel.DNSZoneStatusFailed
	}
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return commonsentinel.DNSZoneStatusUnreachable
	}
	return commonsentinel.DNSZoneStatusRefused
}
