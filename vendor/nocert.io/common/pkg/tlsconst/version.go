package tlsconst

import (
	"fmt"
	"strings"
)

// Canonical TLS version strings. These are the only format nocert stores and compares.
const (
	VersionSSL20 = "SSLv2"
	VersionSSL30 = "SSLv3"
	VersionTLS10 = "TLSv1.0"
	VersionTLS11 = "TLSv1.1"
	VersionTLS12 = "TLSv1.2"
	VersionTLS13 = "TLSv1.3"
)

// Protocol wire values (RFC 8446 §5.1, RFC 5246 §6.2.1, RFC 6101).
// SSLv2's 0x0200 is display-only (nocert never speaks SSLv2).
const (
	wireSSL20 uint16 = 0x0200
	wireSSL30 uint16 = 0x0300
	wireTLS10 uint16 = 0x0301
	wireTLS11 uint16 = 0x0302
	wireTLS12 uint16 = 0x0303
	wireTLS13 uint16 = 0x0304
)

var wireToCanonical = map[uint16]string{
	wireSSL20: VersionSSL20,
	wireSSL30: VersionSSL30,
	wireTLS10: VersionTLS10,
	wireTLS11: VersionTLS11,
	wireTLS12: VersionTLS12,
	wireTLS13: VersionTLS13,
}

// parseMap maps every known string variant to its canonical form.
var parseMap = map[string]string{
	// Canonical
	"SSLv2": VersionSSL20, "SSLv3": VersionSSL30,
	"TLSv1.0": VersionTLS10, "TLSv1.1": VersionTLS11,
	"TLSv1.2": VersionTLS12, "TLSv1.3": VersionTLS13,
	// Space-separated (baselines, legacy)
	"SSL 2.0": VersionSSL20, "SSL 3.0": VersionSSL30,
	"TLS 1.0": VersionTLS10, "TLS 1.1": VersionTLS11,
	"TLS 1.2": VersionTLS12, "TLS 1.3": VersionTLS13,
	// Short form
	"TLSv1": VersionTLS10,
	// Bare version numbers (used by frontend dropdown values)
	"1.0": VersionTLS10, "1.1": VersionTLS11,
	"1.2": VersionTLS12, "1.3": VersionTLS13,
}

// parseLower is a lowercase version of parseMap for case-insensitive fallback.
var parseLower map[string]string

func init() {
	parseLower = make(map[string]string, len(parseMap))
	for k, v := range parseMap {
		parseLower[strings.ToLower(k)] = v
	}
}

var versionOrder = map[string]int{
	VersionSSL20: 0,
	VersionSSL30: 1,
	VersionTLS10: 2,
	VersionTLS11: 3,
	VersionTLS12: 4,
	VersionTLS13: 5,
}

var deprecatedVersions = map[string]bool{
	VersionSSL20: true,
	VersionSSL30: true,
	VersionTLS10: true,
	VersionTLS11: true,
}

// VersionString maps a TLS protocol uint16 to its canonical string.
// Returns "Unknown(0xNNNN)" for unrecognized values.
func VersionString(v uint16) string {
	if s, ok := wireToCanonical[v]; ok {
		return s
	}
	return fmt.Sprintf("Unknown(0x%04X)", v)
}

// ParseVersion normalizes any known TLS version string to canonical format.
// Case-insensitive to match the old compareTLS/EqualFold behavior.
// Returns ("", false) for unrecognized input.
func ParseVersion(s string) (string, bool) {
	// Try exact match first (fast path for canonical inputs).
	if c, ok := parseMap[s]; ok {
		return c, true
	}
	// Fallback: case-insensitive lookup.
	lower := strings.ToLower(s)
	c, ok := parseLower[lower]
	return c, ok
}

// CompareVersions returns -1, 0, or +1 comparing two canonical version strings.
// Unknown versions are treated as order -1 (below SSLv2).
func CompareVersions(a, b string) int {
	oa := versionOrder[a]
	ob := versionOrder[b]
	_, aKnown := versionOrder[a]
	_, bKnown := versionOrder[b]
	if !aKnown {
		oa = -1
	}
	if !bKnown {
		ob = -1
	}
	if oa < ob {
		return -1
	}
	if oa > ob {
		return 1
	}
	return 0
}

// IsDeprecated returns true for SSLv2, SSLv3, TLSv1.0, TLSv1.1.
func IsDeprecated(version string) bool {
	return deprecatedVersions[version]
}
