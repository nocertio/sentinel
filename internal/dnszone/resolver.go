// Package dnszone reads internal DNS zones for the dns_zone_transfer task: the
// host's resolver settings (a local file, no DNS query) and standard zone
// transfers (AXFR) from the servers the operator configured in NoCert.
package dnszone

import (
	"bufio"
	"io"
	"net/netip"
	"os"
	"regexp"
	"strings"

	commonsentinel "nocert.io/common/pkg/api/sentinel"
)

// systemd-resolved points /etc/resolv.conf at its 127.0.0.53 stub and lists
// the upstream servers in this file instead.
const resolvedConf = "/run/systemd/resolve/resolv.conf"

const (
	maxResolverFileBytes = 64 << 10
	maxResolverEntries   = 8
)

var nameRE = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*$`)

// normalizeName lowercases a DNS name, drops its trailing dot and accepts only
// letters, digits and hyphens, which also rules out wildcards and service
// labels such as _ldap.
func normalizeName(raw string) (string, bool) {
	name := strings.TrimSuffix(asciiLower(raw), ".")
	if name == "" || len(name) > 253 || !nameRE.MatchString(name) {
		return "", false
	}
	return name, true
}

// asciiLower folds A-Z only: strings.ToLower would turn the Kelvin sign into
// "k" and let a non-ASCII label pass the check above.
func asciiLower(s string) string {
	b := []byte(s)
	for i, c := range b {
		if 'A' <= c && c <= 'Z' {
			b[i] = c + 'a' - 'A'
		}
	}
	return string(b)
}

// ReadResolver lists the DNS servers and search domains of this host. It reads
// the resolver configuration file and sends no DNS query.
func ReadResolver() commonsentinel.DNSResolver {
	for _, path := range []string{resolvedConf, "/etc/resolv.conf"} {
		f, err := os.Open(path)
		if err != nil {
			continue
		}
		r := parseResolvConf(io.LimitReader(f, maxResolverFileBytes))
		_ = f.Close()
		return r
	}
	return commonsentinel.DNSResolver{Servers: []string{}, SearchDomains: []string{}}
}

func parseResolvConf(r io.Reader) commonsentinel.DNSResolver {
	out := commonsentinel.DNSResolver{Servers: []string{}, SearchDomains: []string{}}
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) < 2 {
			continue
		}
		switch fields[0] {
		case "nameserver":
			addr, err := netip.ParseAddr(fields[1])
			if err != nil || addr.Zone() != "" || addr.IsLoopback() || addr.IsUnspecified() {
				continue
			}
			out.Servers = appendUnique(out.Servers, addr.Unmap().String())
		case "search", "domain":
			for _, d := range fields[1:] {
				if name, ok := normalizeName(d); ok {
					out.SearchDomains = appendUnique(out.SearchDomains, name)
				}
			}
		}
	}
	return out
}

func appendUnique(list []string, v string) []string {
	if len(list) >= maxResolverEntries {
		return list
	}
	for _, x := range list {
		if x == v {
			return list
		}
	}
	return append(list, v)
}
