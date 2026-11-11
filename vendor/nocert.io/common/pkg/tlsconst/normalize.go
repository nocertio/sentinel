package tlsconst

import (
	"crypto/tls"
	"fmt"
	"strconv"
)

// Wire IDs, when provided, are authoritative. Legacy labels are accepted only
// from the local registry or the exact bounded unknown-ID spelling. Agent text
// never becomes an unchecked keyword in storage.
func NormalizeVersion(name string, id *uint16) (string, *uint16) {
	if id != nil {
		v := *id
		return VersionString(v), &v
	}
	if len(name) > 16 {
		return "", nil
	}
	if v, ok := ParseVersion(name); ok {
		if v == VersionSSL20 {
			id := uint16(0x0002)
			return v, &id
		}
		for id, label := range wireToCanonical {
			if label == v {
				return v, &id
			}
		}
	}
	if id, ok := unknownID(name); ok {
		return VersionString(id), &id
	}
	return "", nil
}

func NormalizeCipher(name string, id *uint16) (string, *uint16) {
	if id != nil {
		v := *id
		return CipherName(v), &v
	}
	if len(name) > 128 {
		return "", nil
	}
	if c, ok := LookupCipherByName(name); ok {
		return c.Name, &c.ID
	}
	if id, ok := unknownID(name); ok {
		return CipherName(id), &id
	}
	return "", nil
}

func NormalizeGroup(name string, id *uint16) (string, *uint16) {
	if id != nil {
		v := *id
		return GroupString(tls.CurveID(v)), &v
	}
	for _, group := range namedGroups {
		if name == group.name {
			id := uint16(group.id)
			return name, &id
		}
	}
	if len(name) > 32 {
		return "", nil
	}
	if id, ok := unknownID(name); ok {
		return GroupString(tls.CurveID(id)), &id
	}
	return "", nil
}

func unknownID(name string) (uint16, bool) {
	if len(name) != 15 || name[:10] != "Unknown(0x" || name[14] != ')' {
		return 0, false
	}
	n, err := strconv.ParseUint(name[10:14], 16, 16)
	if err != nil {
		return 0, false
	}
	// Use one spelling, including uppercase hex, for both old and new agents.
	id := uint16(n)
	return id, fmt.Sprintf("Unknown(0x%04X)", id) == name
}
