package tlsconst

import "fmt"

// CipherInfo describes a TLS cipher suite's properties.
type CipherInfo struct {
	ID     uint16 // IANA-assigned identifier
	Name   string // IANA canonical name
	IsWeak bool   // RC4, DES, 3DES, NULL, EXPORT, MD5-based
	HasPFS bool   // ECDHE or DHE key exchange
	// IsECDHE is derived from the suite name and is false for TLS 1.3 suites,
	// whose key exchange is negotiated separately. It is not a reliable "the
	// handshake used ECDHE" signal - use HasPFS for that.
	IsECDHE bool
	IsAEAD  bool // GCM, CCM, or CHACHA20-POLY1305
	Unknown bool // true if ID was not in the registry
}

func cipher(id uint16, name string, weak, pfs, ecdhe, aead bool) CipherInfo {
	return CipherInfo{ID: id, Name: name, IsWeak: weak, HasPFS: pfs, IsECDHE: ecdhe, IsAEAD: aead}
}

var registry map[uint16]CipherInfo
var nameIndex map[string]CipherInfo

func init() {
	all := []CipherInfo{
		// TLS 1.3 (key exchange negotiated separately, IsECDHE=false).
		// The CCM variants are negotiated by neither Go nor the enumerator
		// (TLS 1.3 is out of enum scope) but are registered so a stored
		// observation carrying them survives normalization: SP 800-52r2
		// §3.3.1.2 and BSI Table 13 reference them.
		cipher(0x1301, "TLS_AES_128_GCM_SHA256", false, true, false, true),
		cipher(0x1302, "TLS_AES_256_GCM_SHA384", false, true, false, true),
		cipher(0x1303, "TLS_CHACHA20_POLY1305_SHA256", false, true, false, true),
		cipher(0x1304, "TLS_AES_128_CCM_SHA256", false, true, false, true),
		cipher(0x1305, "TLS_AES_128_CCM_8_SHA256", false, true, false, true),

		// ECDHE_ECDSA
		cipher(0xC009, "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA", false, true, true, false),
		cipher(0xC00A, "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA", false, true, true, false),
		cipher(0xC023, "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256", false, true, true, false),
		cipher(0xC024, "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384", false, true, true, false),
		cipher(0xC02B, "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256", false, true, true, true),
		cipher(0xC02C, "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384", false, true, true, true),
		cipher(0xCCA9, "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256", false, true, true, true),
		// CCM/CCM_8 family (SP 800-52r2 §3.3.1.1.1, BSI Table 3): registered so
		// the enumerator can offer them and a server accepting them is observed.
		cipher(0xC0AC, "TLS_ECDHE_ECDSA_WITH_AES_128_CCM", false, true, true, true),
		cipher(0xC0AD, "TLS_ECDHE_ECDSA_WITH_AES_256_CCM", false, true, true, true),
		cipher(0xC0AE, "TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8", false, true, true, true),
		cipher(0xC0AF, "TLS_ECDHE_ECDSA_WITH_AES_256_CCM_8", false, true, true, true),

		// ECDHE_RSA
		cipher(0xC013, "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA", false, true, true, false),
		cipher(0xC014, "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA", false, true, true, false),
		cipher(0xC027, "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256", false, true, true, false),
		cipher(0xC028, "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384", false, true, true, false),
		cipher(0xC02F, "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", false, true, true, true),
		cipher(0xC030, "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384", false, true, true, true),
		cipher(0xCCA8, "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256", false, true, true, true),

		// RSA key exchange - no PFS
		cipher(0x002F, "TLS_RSA_WITH_AES_128_CBC_SHA", false, false, false, false),
		cipher(0x0035, "TLS_RSA_WITH_AES_256_CBC_SHA", false, false, false, false),
		cipher(0x003C, "TLS_RSA_WITH_AES_128_CBC_SHA256", false, false, false, false),
		cipher(0x003D, "TLS_RSA_WITH_AES_256_CBC_SHA256", false, false, false, false),
		cipher(0x009C, "TLS_RSA_WITH_AES_128_GCM_SHA256", false, false, false, true),
		cipher(0x009D, "TLS_RSA_WITH_AES_256_GCM_SHA384", false, false, false, true),

		// Weak suites negotiable by Go (RC4, 3DES)
		cipher(0x0005, "TLS_RSA_WITH_RC4_128_SHA", true, false, false, false),
		cipher(0x000A, "TLS_RSA_WITH_3DES_EDE_CBC_SHA", true, false, false, false),
		cipher(0xC007, "TLS_ECDHE_ECDSA_WITH_RC4_128_SHA", true, true, true, false),
		cipher(0xC011, "TLS_ECDHE_RSA_WITH_RC4_128_SHA", true, true, true, false),
		cipher(0xC012, "TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA", true, true, true, false),

		// Legacy weak - NULL
		cipher(0x0000, "TLS_NULL_WITH_NULL_NULL", true, false, false, false),
		cipher(0x0001, "TLS_RSA_WITH_NULL_MD5", true, false, false, false),
		cipher(0x0002, "TLS_RSA_WITH_NULL_SHA", true, false, false, false),
		cipher(0x003B, "TLS_RSA_WITH_NULL_SHA256", true, false, false, false),

		// Legacy weak - RC4 + MD5
		cipher(0x0004, "TLS_RSA_WITH_RC4_128_MD5", true, false, false, false),

		// Legacy weak - DES
		cipher(0x0009, "TLS_RSA_WITH_DES_CBC_SHA", true, false, false, false),
		cipher(0x0012, "TLS_DHE_DSS_WITH_DES_CBC_SHA", true, true, false, false),
		cipher(0x0015, "TLS_DHE_RSA_WITH_DES_CBC_SHA", true, true, false, false),

		// Legacy weak - 3DES
		cipher(0x000D, "TLS_DH_DSS_WITH_3DES_EDE_CBC_SHA", true, false, false, false),
		cipher(0x0010, "TLS_DH_RSA_WITH_3DES_EDE_CBC_SHA", true, false, false, false),
		cipher(0x0013, "TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA", true, true, false, false),
		cipher(0x0016, "TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA", true, true, false, false),

		// Legacy weak - EXPORT
		cipher(0x0003, "TLS_RSA_EXPORT_WITH_RC4_40_MD5", true, false, false, false),
		cipher(0x0006, "TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5", true, false, false, false),
		cipher(0x0008, "TLS_RSA_EXPORT_WITH_DES40_CBC_SHA", true, false, false, false),
		cipher(0x000B, "TLS_DH_DSS_EXPORT_WITH_DES40_CBC_SHA", true, false, false, false),
		cipher(0x000E, "TLS_DH_RSA_EXPORT_WITH_DES40_CBC_SHA", true, false, false, false),
		cipher(0x0011, "TLS_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA", true, true, false, false),
		cipher(0x0014, "TLS_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA", true, true, false, false),

		// DHE_RSA modern AEAD (PFS, AEAD)
		cipher(0x009E, "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256", false, true, false, true),
		cipher(0x009F, "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384", false, true, false, true),
		cipher(0xCCAA, "TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256", false, true, false, true),
		cipher(0xC09E, "TLS_DHE_RSA_WITH_AES_128_CCM", false, true, false, true),
		cipher(0xC09F, "TLS_DHE_RSA_WITH_AES_256_CCM", false, true, false, true),
		cipher(0xC0A2, "TLS_DHE_RSA_WITH_AES_128_CCM_8", false, true, false, true),
		cipher(0xC0A3, "TLS_DHE_RSA_WITH_AES_256_CCM_8", false, true, false, true),

		// RSA key-transport CCM/CCM_8 (SP 800-52r2 Appendix D): registered for
		// DETECTION - RSA key transport (PKCS#1 v1.5) is disallowed after 2023
		// by SP 800-131Ar2 Table 5, so observing a server accepting these is a
		// compliance signal, not an endorsement.
		cipher(0xC09C, "TLS_RSA_WITH_AES_128_CCM", false, false, false, true),
		cipher(0xC09D, "TLS_RSA_WITH_AES_256_CCM", false, false, false, true),
		cipher(0xC0A0, "TLS_RSA_WITH_AES_128_CCM_8", false, false, false, true),
		cipher(0xC0A1, "TLS_RSA_WITH_AES_256_CCM_8", false, false, false, true),

		// DHE_RSA CBC (PFS but no AEAD - common on legacy nginx/Apache)
		cipher(0x0033, "TLS_DHE_RSA_WITH_AES_128_CBC_SHA", false, true, false, false),
		cipher(0x0039, "TLS_DHE_RSA_WITH_AES_256_CBC_SHA", false, true, false, false),
		cipher(0x0067, "TLS_DHE_RSA_WITH_AES_128_CBC_SHA256", false, true, false, false),
		cipher(0x006B, "TLS_DHE_RSA_WITH_AES_256_CBC_SHA256", false, true, false, false),

		// DH_anon - no authentication; weak by definition for compliance
		// (HasPFS=false because anonymity destroys the auth that real-world
		// PFS depends on; IsWeak=true is the dominant compliance signal).
		cipher(0x0018, "TLS_DH_anon_WITH_RC4_128_MD5", true, false, false, false),
		cipher(0x001B, "TLS_DH_anon_WITH_3DES_EDE_CBC_SHA", true, false, false, false),
		cipher(0x0034, "TLS_DH_anon_WITH_AES_128_CBC_SHA", true, false, false, false),
		cipher(0x003A, "TLS_DH_anon_WITH_AES_256_CBC_SHA", true, false, false, false),
	}

	registry = make(map[uint16]CipherInfo, len(all))
	nameIndex = make(map[string]CipherInfo, len(all))
	for _, c := range all {
		registry[c.ID] = c
		nameIndex[c.Name] = c
	}
}

func LookupCipher(id uint16) CipherInfo {
	if c, ok := registry[id]; ok {
		return c
	}
	return CipherInfo{
		ID:      id,
		Name:    fmt.Sprintf("Unknown(0x%04X)", id),
		Unknown: true,
	}
}

func LookupCipherByName(name string) (CipherInfo, bool) {
	c, ok := nameIndex[name]
	return c, ok
}

func CipherName(id uint16) string {
	return LookupCipher(id).Name
}

// AllCiphers returns a snapshot of every CipherInfo in the registry, in
// unspecified order. Intended for callers that need to enumerate the cipher
// set (e.g. tlsenum's offer list builder).
func AllCiphers() []CipherInfo {
	out := make([]CipherInfo, 0, len(registry))
	for _, c := range registry {
		out = append(out, c)
	}
	return out
}
