package certinfo

import (
	"crypto/x509"
	"net"
	"strings"
)

// CollectSANs merges all Subject Alternative Names into one sanitized,
// MaxSANCount-capped list in stable order: DNS, IP, email, URI.
func CollectSANs(cert *x509.Certificate) []string {
	sans := make([]string, 0, min(MaxSANCount, len(cert.DNSNames)+len(cert.IPAddresses)+len(cert.EmailAddresses)+len(cert.URIs)))
	sans = append(sans, cert.DNSNames[:min(len(cert.DNSNames), MaxSANCount)]...)
	for _, ip := range cert.IPAddresses {
		if len(sans) == MaxSANCount {
			break
		}
		sans = append(sans, ip.String())
	}
	sans = append(sans, cert.EmailAddresses[:min(len(cert.EmailAddresses), MaxSANCount-len(sans))]...)
	for _, u := range cert.URIs {
		if len(sans) == MaxSANCount {
			break
		}
		sans = append(sans, u.String())
	}
	if len(sans) == 0 {
		return nil
	}
	return SanitizeFields(sans)
}

// collectIPAddressSANs returns the iPAddress Subject Alternative Names as
// canonical strings. The IP subset is duplicated out of the mixed SANs field
// on purpose: keeping it type-separate lets the UI flag IP SANs distinctly and
// lets them be queried as Elasticsearch `ip` values (which the SAN strings
// can't be).
func collectIPAddressSANs(ips []net.IP) []string {
	if len(ips) == 0 {
		return nil
	}
	out := make([]string, 0, min(len(ips), MaxSANCount))
	for _, ip := range ips {
		if ip == nil {
			continue
		}
		out = append(out, ip.String())
		if len(out) >= MaxSANCount {
			break
		}
	}
	if len(out) == 0 {
		return nil
	}
	return SanitizeFields(out)
}

// collectAIAURLs caps count + per-URL size and sanitizes control bytes
// (Trojan Source / log injection defense - RFC 3986 forbids these bytes
// in URIs anyway, so SanitizeField strips nothing legitimate).
// Returns nil on nil/empty input so json:omitempty triggers.
func collectAIAURLs(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	if len(in) > MaxAIAURLCount {
		in = in[:MaxAIAURLCount]
	}
	out := make([]string, len(in))
	for i, u := range in {
		out[i] = SanitizeField(truncateString(u, MaxAIAURLSize))
	}
	return out
}

// crlSchemes are the URI schemes we keep for CRL distribution points. CRLs
// are published over HTTP(S) or LDAP; anything else (or a non-URL string) is
// omitted. Compared against the lowercased, sanitized value.
var crlSchemes = []string{"http://", "https://", "ldap://"}

// collectCRLDistributionPoints sanitizes and bounds the CRL distribution
// point URIs, keeping only the crlSchemes. Mirrors collectAIAURLs (per-URL
// truncation + control-byte sanitization) with an added scheme allow-list.
// Returns nil on empty/all-dropped input so json:omitempty triggers.
func collectCRLDistributionPoints(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	var out []string
	for _, u := range in {
		clean := SanitizeField(truncateString(u, MaxAIAURLSize))
		lower := strings.ToLower(clean)
		ok := false
		for _, s := range crlSchemes {
			if strings.HasPrefix(lower, s) {
				ok = true
				break
			}
		}
		if !ok {
			continue
		}
		out = append(out, clean)
		if len(out) >= MaxCRLDistributionPoints {
			break
		}
	}
	return out
}

// unknownExtKeyUsageOIDs returns the dotted-string OIDs of extended key usages
// Go's crypto/x509 did not map to a known x509.ExtKeyUsage constant (they land
// in cert.UnknownExtKeyUsage). extKeyUsageStrings only covers the known enum,
// so these would otherwise be invisible. Deduped before truncation so repeated
// OIDs cannot push distinct usages out of the capped display list.
func unknownExtKeyUsageOIDs(cert *x509.Certificate) []string {
	if len(cert.UnknownExtKeyUsage) == 0 {
		return nil
	}
	out := make([]string, 0, min(len(cert.UnknownExtKeyUsage), MaxUnknownExtKeyUsageOIDs))
	seen := make(map[string]struct{}, min(len(cert.UnknownExtKeyUsage), MaxUnknownExtKeyUsageOIDs))
	for _, oid := range cert.UnknownExtKeyUsage {
		dotted := oid.String()
		if _, ok := seen[dotted]; ok {
			continue
		}
		seen[dotted] = struct{}{}
		out = append(out, dotted)
		if len(out) == MaxUnknownExtKeyUsageOIDs {
			break
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}
