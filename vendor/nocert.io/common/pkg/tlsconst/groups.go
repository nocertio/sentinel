package tlsconst

import "crypto/tls"

// GroupString returns a stable, lowercase, dash-free string representation
// of a TLS 1.3 named group. Empty string on unknown / RSA key exchange
// (state.CurveID == 0 in crypto/tls).
//
// Naming follows the IANA registry "Description" column lowercased, with
// dashes removed: "X25519MLKEM768" -> "x25519mlkem768". The string form is
// consumed by Elasticsearch keyword fields, frontend display, and the
// IsPostQuantumGroup classifier.
func GroupString(id tls.CurveID) string {
	switch id {
	case tls.X25519:
		return "x25519"
	case tls.CurveP256:
		return "secp256r1"
	case tls.CurveP384:
		return "secp384r1"
	case tls.CurveP521:
		return "secp521r1"
	case tls.X25519MLKEM768:
		return "x25519mlkem768"
	case tls.SecP256r1MLKEM768:
		return "secp256r1mlkem768"
	case tls.SecP384r1MLKEM1024:
		return "secp384r1mlkem1024"
	}
	return ""
}

// IsPostQuantumGroup returns true if name is a hybrid post-quantum named
// group as exposed by Go 1.26 crypto/tls. Match exact (no substring).
// Extend manually as new hybrids land.
func IsPostQuantumGroup(name string) bool {
	switch name {
	case "x25519mlkem768", "secp256r1mlkem768", "secp384r1mlkem1024":
		return true
	}
	return false
}

// IsKnownGroupString returns true if name is one of the canonical strings
// produced by GroupString. Used by ingesters as a whitelist filter on a
// negotiated_group string sent by an agent (defends against a compromised
// agent injecting arbitrary strings into Elasticsearch).
func IsKnownGroupString(name string) bool {
	switch name {
	case "x25519", "secp256r1", "secp384r1", "secp521r1",
		"x25519mlkem768", "secp256r1mlkem768", "secp384r1mlkem1024":
		return true
	}
	return false
}

const MaxGroupNameLength = 32

// SanitizeGroupName returns name if it's a known canonical group string
// (whitelist) of at most MaxGroupNameLength bytes. Otherwise returns "".
func SanitizeGroupName(name string) string {
	if len(name) > MaxGroupNameLength || !IsKnownGroupString(name) {
		return ""
	}
	return name
}
