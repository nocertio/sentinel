package tlsconst

import (
	"crypto/tls"
	"fmt"
)

// namedGroups keeps wire identity, stable labels and classification together.
var namedGroups = [...]struct {
	id          tls.CurveID
	name        string
	postQuantum bool
}{
	{tls.CurveP256, "secp256r1", false},
	{tls.CurveP384, "secp384r1", false},
	{tls.CurveP521, "secp521r1", false},
	{tls.X25519, "x25519", false},
	{514, "mlkem1024", true},
	{tls.SecP256r1MLKEM768, "secp256r1mlkem768", true},
	{tls.X25519MLKEM768, "x25519mlkem768", true},
	{tls.SecP384r1MLKEM1024, "secp384r1mlkem1024", true},
}

// GroupString returns the local label for a TLS named group. Zero means no
// observed group; unknown IDs retain their wire value as Unknown(0xNNNN).
func GroupString(id tls.CurveID) string {
	for _, group := range namedGroups {
		if group.id == id {
			return group.name
		}
	}
	if id == 0 {
		return ""
	}
	return fmt.Sprintf("Unknown(0x%04X)", uint16(id))
}

// IsPostQuantumGroup recognizes the catalogue's hybrid and standalone ML-KEM groups.
func IsPostQuantumGroup(name string) bool {
	for _, group := range namedGroups {
		if group.name == name {
			return group.postQuantum
		}
	}
	return false
}

// IsKnownGroupString reports whether name is a canonical label in the catalogue.
func IsKnownGroupString(name string) bool {
	for _, group := range namedGroups {
		if group.name == name {
			return true
		}
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
