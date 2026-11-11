package tlsconst

import (
	"cmp"
	"fmt"
	"slices"
)

// CipherInfo describes a TLS cipher suite's properties.
type CipherInfo struct {
	ID     uint16 // IANA-assigned identifier
	Name   string // IANA canonical name
	IsWeak bool   // RC4, RC2, DES, 3DES, IDEA, NULL, EXPORT, MD5 or anonymous
	HasPFS bool   // ECDHE or DHE key exchange
	// Key exchange is independent of the cipher suite in TLS 1.3: HasPFS
	// and IsECDHE are false there. Inspect the negotiated group instead.
	IsECDHE    bool
	IsAEAD     bool   // GCM, CCM, or CHACHA20-POLY1305
	Unknown    bool   // true if ID was not in the registry
	MinVersion uint16 // wire version; zero means not negotiable
	MaxVersion uint16
}

func cipher(id uint16, name string, weak, pfs, ecdhe, aead bool, minVersion, maxVersion uint16) CipherInfo {
	return CipherInfo{ID: id, Name: name, IsWeak: weak, HasPFS: pfs, IsECDHE: ecdhe, IsAEAD: aead, MinVersion: minVersion, MaxVersion: maxVersion}
}

var registry map[uint16]CipherInfo
var nameIndex map[string]CipherInfo

// Reviewed IANA TLS Cipher Suites snapshot, 2026-10-17:
// https://www.iana.org/assignments/tls-parameters/tls-parameters-4.csv
// Certificate-based RSA/DH/ECDH families, anonymous legacy detection, and
// named TLS 1.3 suites. PSK, SRP, Kerberos and national credential schemes
// are outside this catalogue. Weak suites are retained for detection.
var cipherRegistry = []CipherInfo{
	cipher(0x0000, "TLS_NULL_WITH_NULL_NULL", true, false, false, false, 0, 0),
	cipher(0x0001, "TLS_RSA_WITH_NULL_MD5", true, false, false, false, 0x0301, 0x0303),
	cipher(0x0002, "TLS_RSA_WITH_NULL_SHA", true, false, false, false, 0x0301, 0x0303),
	cipher(0x0003, "TLS_RSA_EXPORT_WITH_RC4_40_MD5", true, false, false, false, 0x0301, 0x0303),
	cipher(0x0004, "TLS_RSA_WITH_RC4_128_MD5", true, false, false, false, 0x0301, 0x0303),
	cipher(0x0005, "TLS_RSA_WITH_RC4_128_SHA", true, false, false, false, 0x0301, 0x0303),
	cipher(0x0006, "TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5", true, false, false, false, 0x0301, 0x0303),
	cipher(0x0007, "TLS_RSA_WITH_IDEA_CBC_SHA", true, false, false, false, 0x0301, 0x0303),
	cipher(0x0008, "TLS_RSA_EXPORT_WITH_DES40_CBC_SHA", true, false, false, false, 0x0301, 0x0303),
	cipher(0x0009, "TLS_RSA_WITH_DES_CBC_SHA", true, false, false, false, 0x0301, 0x0303),
	cipher(0x000A, "TLS_RSA_WITH_3DES_EDE_CBC_SHA", true, false, false, false, 0x0301, 0x0303),
	cipher(0x000B, "TLS_DH_DSS_EXPORT_WITH_DES40_CBC_SHA", true, false, false, false, 0x0301, 0x0303),
	cipher(0x000C, "TLS_DH_DSS_WITH_DES_CBC_SHA", true, false, false, false, 0x0301, 0x0303),
	cipher(0x000D, "TLS_DH_DSS_WITH_3DES_EDE_CBC_SHA", true, false, false, false, 0x0301, 0x0303),
	cipher(0x000E, "TLS_DH_RSA_EXPORT_WITH_DES40_CBC_SHA", true, false, false, false, 0x0301, 0x0303),
	cipher(0x000F, "TLS_DH_RSA_WITH_DES_CBC_SHA", true, false, false, false, 0x0301, 0x0303),
	cipher(0x0010, "TLS_DH_RSA_WITH_3DES_EDE_CBC_SHA", true, false, false, false, 0x0301, 0x0303),
	cipher(0x0011, "TLS_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA", true, true, false, false, 0x0301, 0x0303),
	cipher(0x0012, "TLS_DHE_DSS_WITH_DES_CBC_SHA", true, true, false, false, 0x0301, 0x0303),
	cipher(0x0013, "TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA", true, true, false, false, 0x0301, 0x0303),
	cipher(0x0014, "TLS_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA", true, true, false, false, 0x0301, 0x0303),
	cipher(0x0015, "TLS_DHE_RSA_WITH_DES_CBC_SHA", true, true, false, false, 0x0301, 0x0303),
	cipher(0x0016, "TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA", true, true, false, false, 0x0301, 0x0303),
	cipher(0x0017, "TLS_DH_anon_EXPORT_WITH_RC4_40_MD5", true, false, false, false, 0x0301, 0x0303),
	cipher(0x0018, "TLS_DH_anon_WITH_RC4_128_MD5", true, false, false, false, 0x0301, 0x0303),
	cipher(0x0019, "TLS_DH_anon_EXPORT_WITH_DES40_CBC_SHA", true, false, false, false, 0x0301, 0x0303),
	cipher(0x001A, "TLS_DH_anon_WITH_DES_CBC_SHA", true, false, false, false, 0x0301, 0x0303),
	cipher(0x001B, "TLS_DH_anon_WITH_3DES_EDE_CBC_SHA", true, false, false, false, 0x0301, 0x0303),
	cipher(0x002F, "TLS_RSA_WITH_AES_128_CBC_SHA", false, false, false, false, 0x0301, 0x0303),
	cipher(0x0030, "TLS_DH_DSS_WITH_AES_128_CBC_SHA", false, false, false, false, 0x0301, 0x0303),
	cipher(0x0031, "TLS_DH_RSA_WITH_AES_128_CBC_SHA", false, false, false, false, 0x0301, 0x0303),
	cipher(0x0032, "TLS_DHE_DSS_WITH_AES_128_CBC_SHA", false, true, false, false, 0x0301, 0x0303),
	cipher(0x0033, "TLS_DHE_RSA_WITH_AES_128_CBC_SHA", false, true, false, false, 0x0301, 0x0303),
	cipher(0x0034, "TLS_DH_anon_WITH_AES_128_CBC_SHA", true, false, false, false, 0x0301, 0x0303),
	cipher(0x0035, "TLS_RSA_WITH_AES_256_CBC_SHA", false, false, false, false, 0x0301, 0x0303),
	cipher(0x0036, "TLS_DH_DSS_WITH_AES_256_CBC_SHA", false, false, false, false, 0x0301, 0x0303),
	cipher(0x0037, "TLS_DH_RSA_WITH_AES_256_CBC_SHA", false, false, false, false, 0x0301, 0x0303),
	cipher(0x0038, "TLS_DHE_DSS_WITH_AES_256_CBC_SHA", false, true, false, false, 0x0301, 0x0303),
	cipher(0x0039, "TLS_DHE_RSA_WITH_AES_256_CBC_SHA", false, true, false, false, 0x0301, 0x0303),
	cipher(0x003A, "TLS_DH_anon_WITH_AES_256_CBC_SHA", true, false, false, false, 0x0301, 0x0303),
	cipher(0x003B, "TLS_RSA_WITH_NULL_SHA256", true, false, false, false, 0x0303, 0x0303),
	cipher(0x003C, "TLS_RSA_WITH_AES_128_CBC_SHA256", false, false, false, false, 0x0303, 0x0303),
	cipher(0x003D, "TLS_RSA_WITH_AES_256_CBC_SHA256", false, false, false, false, 0x0303, 0x0303),
	cipher(0x003E, "TLS_DH_DSS_WITH_AES_128_CBC_SHA256", false, false, false, false, 0x0303, 0x0303),
	cipher(0x003F, "TLS_DH_RSA_WITH_AES_128_CBC_SHA256", false, false, false, false, 0x0303, 0x0303),
	cipher(0x0040, "TLS_DHE_DSS_WITH_AES_128_CBC_SHA256", false, true, false, false, 0x0303, 0x0303),
	cipher(0x0041, "TLS_RSA_WITH_CAMELLIA_128_CBC_SHA", false, false, false, false, 0x0301, 0x0303),
	cipher(0x0042, "TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA", false, false, false, false, 0x0301, 0x0303),
	cipher(0x0043, "TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA", false, false, false, false, 0x0301, 0x0303),
	cipher(0x0044, "TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA", false, true, false, false, 0x0301, 0x0303),
	cipher(0x0045, "TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA", false, true, false, false, 0x0301, 0x0303),
	cipher(0x0046, "TLS_DH_anon_WITH_CAMELLIA_128_CBC_SHA", true, false, false, false, 0x0301, 0x0303),
	cipher(0x0067, "TLS_DHE_RSA_WITH_AES_128_CBC_SHA256", false, true, false, false, 0x0303, 0x0303),
	cipher(0x0068, "TLS_DH_DSS_WITH_AES_256_CBC_SHA256", false, false, false, false, 0x0303, 0x0303),
	cipher(0x0069, "TLS_DH_RSA_WITH_AES_256_CBC_SHA256", false, false, false, false, 0x0303, 0x0303),
	cipher(0x006A, "TLS_DHE_DSS_WITH_AES_256_CBC_SHA256", false, true, false, false, 0x0303, 0x0303),
	cipher(0x006B, "TLS_DHE_RSA_WITH_AES_256_CBC_SHA256", false, true, false, false, 0x0303, 0x0303),
	cipher(0x006C, "TLS_DH_anon_WITH_AES_128_CBC_SHA256", true, false, false, false, 0x0303, 0x0303),
	cipher(0x006D, "TLS_DH_anon_WITH_AES_256_CBC_SHA256", true, false, false, false, 0x0303, 0x0303),
	cipher(0x0084, "TLS_RSA_WITH_CAMELLIA_256_CBC_SHA", false, false, false, false, 0x0301, 0x0303),
	cipher(0x0085, "TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA", false, false, false, false, 0x0301, 0x0303),
	cipher(0x0086, "TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA", false, false, false, false, 0x0301, 0x0303),
	cipher(0x0087, "TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA", false, true, false, false, 0x0301, 0x0303),
	cipher(0x0088, "TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA", false, true, false, false, 0x0301, 0x0303),
	cipher(0x0089, "TLS_DH_anon_WITH_CAMELLIA_256_CBC_SHA", true, false, false, false, 0x0301, 0x0303),
	cipher(0x0096, "TLS_RSA_WITH_SEED_CBC_SHA", false, false, false, false, 0x0301, 0x0303),
	cipher(0x0097, "TLS_DH_DSS_WITH_SEED_CBC_SHA", false, false, false, false, 0x0301, 0x0303),
	cipher(0x0098, "TLS_DH_RSA_WITH_SEED_CBC_SHA", false, false, false, false, 0x0301, 0x0303),
	cipher(0x0099, "TLS_DHE_DSS_WITH_SEED_CBC_SHA", false, true, false, false, 0x0301, 0x0303),
	cipher(0x009A, "TLS_DHE_RSA_WITH_SEED_CBC_SHA", false, true, false, false, 0x0301, 0x0303),
	cipher(0x009B, "TLS_DH_anon_WITH_SEED_CBC_SHA", true, false, false, false, 0x0301, 0x0303),
	cipher(0x009C, "TLS_RSA_WITH_AES_128_GCM_SHA256", false, false, false, true, 0x0303, 0x0303),
	cipher(0x009D, "TLS_RSA_WITH_AES_256_GCM_SHA384", false, false, false, true, 0x0303, 0x0303),
	cipher(0x009E, "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256", false, true, false, true, 0x0303, 0x0303),
	cipher(0x009F, "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384", false, true, false, true, 0x0303, 0x0303),
	cipher(0x00A0, "TLS_DH_RSA_WITH_AES_128_GCM_SHA256", false, false, false, true, 0x0303, 0x0303),
	cipher(0x00A1, "TLS_DH_RSA_WITH_AES_256_GCM_SHA384", false, false, false, true, 0x0303, 0x0303),
	cipher(0x00A2, "TLS_DHE_DSS_WITH_AES_128_GCM_SHA256", false, true, false, true, 0x0303, 0x0303),
	cipher(0x00A3, "TLS_DHE_DSS_WITH_AES_256_GCM_SHA384", false, true, false, true, 0x0303, 0x0303),
	cipher(0x00A4, "TLS_DH_DSS_WITH_AES_128_GCM_SHA256", false, false, false, true, 0x0303, 0x0303),
	cipher(0x00A5, "TLS_DH_DSS_WITH_AES_256_GCM_SHA384", false, false, false, true, 0x0303, 0x0303),
	cipher(0x00A6, "TLS_DH_anon_WITH_AES_128_GCM_SHA256", true, false, false, true, 0x0303, 0x0303),
	cipher(0x00A7, "TLS_DH_anon_WITH_AES_256_GCM_SHA384", true, false, false, true, 0x0303, 0x0303),
	cipher(0x00BA, "TLS_RSA_WITH_CAMELLIA_128_CBC_SHA256", false, false, false, false, 0x0303, 0x0303),
	cipher(0x00BB, "TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA256", false, false, false, false, 0x0303, 0x0303),
	cipher(0x00BC, "TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA256", false, false, false, false, 0x0303, 0x0303),
	cipher(0x00BD, "TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA256", false, true, false, false, 0x0303, 0x0303),
	cipher(0x00BE, "TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA256", false, true, false, false, 0x0303, 0x0303),
	cipher(0x00BF, "TLS_DH_anon_WITH_CAMELLIA_128_CBC_SHA256", true, false, false, false, 0x0303, 0x0303),
	cipher(0x00C0, "TLS_RSA_WITH_CAMELLIA_256_CBC_SHA256", false, false, false, false, 0x0303, 0x0303),
	cipher(0x00C1, "TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA256", false, false, false, false, 0x0303, 0x0303),
	cipher(0x00C2, "TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA256", false, false, false, false, 0x0303, 0x0303),
	cipher(0x00C3, "TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA256", false, true, false, false, 0x0303, 0x0303),
	cipher(0x00C4, "TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA256", false, true, false, false, 0x0303, 0x0303),
	cipher(0x00C5, "TLS_DH_anon_WITH_CAMELLIA_256_CBC_SHA256", true, false, false, false, 0x0303, 0x0303),
	cipher(0x00C6, "TLS_SM4_GCM_SM3", false, false, false, true, 0x0304, 0x0304),
	cipher(0x00C7, "TLS_SM4_CCM_SM3", false, false, false, true, 0x0304, 0x0304),
	cipher(0x1301, "TLS_AES_128_GCM_SHA256", false, false, false, true, 0x0304, 0x0304),
	cipher(0x1302, "TLS_AES_256_GCM_SHA384", false, false, false, true, 0x0304, 0x0304),
	cipher(0x1303, "TLS_CHACHA20_POLY1305_SHA256", false, false, false, true, 0x0304, 0x0304),
	cipher(0x1304, "TLS_AES_128_CCM_SHA256", false, false, false, true, 0x0304, 0x0304),
	cipher(0x1305, "TLS_AES_128_CCM_8_SHA256", false, false, false, true, 0x0304, 0x0304),
	cipher(0xC001, "TLS_ECDH_ECDSA_WITH_NULL_SHA", true, false, false, false, 0x0301, 0x0303),
	cipher(0xC002, "TLS_ECDH_ECDSA_WITH_RC4_128_SHA", true, false, false, false, 0x0301, 0x0303),
	cipher(0xC003, "TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA", true, false, false, false, 0x0301, 0x0303),
	cipher(0xC004, "TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA", false, false, false, false, 0x0301, 0x0303),
	cipher(0xC005, "TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA", false, false, false, false, 0x0301, 0x0303),
	cipher(0xC006, "TLS_ECDHE_ECDSA_WITH_NULL_SHA", true, true, true, false, 0x0301, 0x0303),
	cipher(0xC007, "TLS_ECDHE_ECDSA_WITH_RC4_128_SHA", true, true, true, false, 0x0301, 0x0303),
	cipher(0xC008, "TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA", true, true, true, false, 0x0301, 0x0303),
	cipher(0xC009, "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA", false, true, true, false, 0x0301, 0x0303),
	cipher(0xC00A, "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA", false, true, true, false, 0x0301, 0x0303),
	cipher(0xC00B, "TLS_ECDH_RSA_WITH_NULL_SHA", true, false, false, false, 0x0301, 0x0303),
	cipher(0xC00C, "TLS_ECDH_RSA_WITH_RC4_128_SHA", true, false, false, false, 0x0301, 0x0303),
	cipher(0xC00D, "TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA", true, false, false, false, 0x0301, 0x0303),
	cipher(0xC00E, "TLS_ECDH_RSA_WITH_AES_128_CBC_SHA", false, false, false, false, 0x0301, 0x0303),
	cipher(0xC00F, "TLS_ECDH_RSA_WITH_AES_256_CBC_SHA", false, false, false, false, 0x0301, 0x0303),
	cipher(0xC010, "TLS_ECDHE_RSA_WITH_NULL_SHA", true, true, true, false, 0x0301, 0x0303),
	cipher(0xC011, "TLS_ECDHE_RSA_WITH_RC4_128_SHA", true, true, true, false, 0x0301, 0x0303),
	cipher(0xC012, "TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA", true, true, true, false, 0x0301, 0x0303),
	cipher(0xC013, "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA", false, true, true, false, 0x0301, 0x0303),
	cipher(0xC014, "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA", false, true, true, false, 0x0301, 0x0303),
	cipher(0xC015, "TLS_ECDH_anon_WITH_NULL_SHA", true, false, false, false, 0x0301, 0x0303),
	cipher(0xC016, "TLS_ECDH_anon_WITH_RC4_128_SHA", true, false, false, false, 0x0301, 0x0303),
	cipher(0xC017, "TLS_ECDH_anon_WITH_3DES_EDE_CBC_SHA", true, false, false, false, 0x0301, 0x0303),
	cipher(0xC018, "TLS_ECDH_anon_WITH_AES_128_CBC_SHA", true, false, false, false, 0x0301, 0x0303),
	cipher(0xC019, "TLS_ECDH_anon_WITH_AES_256_CBC_SHA", true, false, false, false, 0x0301, 0x0303),
	cipher(0xC023, "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256", false, true, true, false, 0x0303, 0x0303),
	cipher(0xC024, "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384", false, true, true, false, 0x0303, 0x0303),
	cipher(0xC025, "TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256", false, false, false, false, 0x0303, 0x0303),
	cipher(0xC026, "TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384", false, false, false, false, 0x0303, 0x0303),
	cipher(0xC027, "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256", false, true, true, false, 0x0303, 0x0303),
	cipher(0xC028, "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384", false, true, true, false, 0x0303, 0x0303),
	cipher(0xC029, "TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256", false, false, false, false, 0x0303, 0x0303),
	cipher(0xC02A, "TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384", false, false, false, false, 0x0303, 0x0303),
	cipher(0xC02B, "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256", false, true, true, true, 0x0303, 0x0303),
	cipher(0xC02C, "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384", false, true, true, true, 0x0303, 0x0303),
	cipher(0xC02D, "TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256", false, false, false, true, 0x0303, 0x0303),
	cipher(0xC02E, "TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384", false, false, false, true, 0x0303, 0x0303),
	cipher(0xC02F, "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", false, true, true, true, 0x0303, 0x0303),
	cipher(0xC030, "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384", false, true, true, true, 0x0303, 0x0303),
	cipher(0xC031, "TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256", false, false, false, true, 0x0303, 0x0303),
	cipher(0xC032, "TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384", false, false, false, true, 0x0303, 0x0303),
	cipher(0xC03C, "TLS_RSA_WITH_ARIA_128_CBC_SHA256", false, false, false, false, 0x0303, 0x0303),
	cipher(0xC03D, "TLS_RSA_WITH_ARIA_256_CBC_SHA384", false, false, false, false, 0x0303, 0x0303),
	cipher(0xC03E, "TLS_DH_DSS_WITH_ARIA_128_CBC_SHA256", false, false, false, false, 0x0303, 0x0303),
	cipher(0xC03F, "TLS_DH_DSS_WITH_ARIA_256_CBC_SHA384", false, false, false, false, 0x0303, 0x0303),
	cipher(0xC040, "TLS_DH_RSA_WITH_ARIA_128_CBC_SHA256", false, false, false, false, 0x0303, 0x0303),
	cipher(0xC041, "TLS_DH_RSA_WITH_ARIA_256_CBC_SHA384", false, false, false, false, 0x0303, 0x0303),
	cipher(0xC042, "TLS_DHE_DSS_WITH_ARIA_128_CBC_SHA256", false, true, false, false, 0x0303, 0x0303),
	cipher(0xC043, "TLS_DHE_DSS_WITH_ARIA_256_CBC_SHA384", false, true, false, false, 0x0303, 0x0303),
	cipher(0xC044, "TLS_DHE_RSA_WITH_ARIA_128_CBC_SHA256", false, true, false, false, 0x0303, 0x0303),
	cipher(0xC045, "TLS_DHE_RSA_WITH_ARIA_256_CBC_SHA384", false, true, false, false, 0x0303, 0x0303),
	cipher(0xC046, "TLS_DH_anon_WITH_ARIA_128_CBC_SHA256", true, false, false, false, 0x0303, 0x0303),
	cipher(0xC047, "TLS_DH_anon_WITH_ARIA_256_CBC_SHA384", true, false, false, false, 0x0303, 0x0303),
	cipher(0xC048, "TLS_ECDHE_ECDSA_WITH_ARIA_128_CBC_SHA256", false, true, true, false, 0x0303, 0x0303),
	cipher(0xC049, "TLS_ECDHE_ECDSA_WITH_ARIA_256_CBC_SHA384", false, true, true, false, 0x0303, 0x0303),
	cipher(0xC04A, "TLS_ECDH_ECDSA_WITH_ARIA_128_CBC_SHA256", false, false, false, false, 0x0303, 0x0303),
	cipher(0xC04B, "TLS_ECDH_ECDSA_WITH_ARIA_256_CBC_SHA384", false, false, false, false, 0x0303, 0x0303),
	cipher(0xC04C, "TLS_ECDHE_RSA_WITH_ARIA_128_CBC_SHA256", false, true, true, false, 0x0303, 0x0303),
	cipher(0xC04D, "TLS_ECDHE_RSA_WITH_ARIA_256_CBC_SHA384", false, true, true, false, 0x0303, 0x0303),
	cipher(0xC04E, "TLS_ECDH_RSA_WITH_ARIA_128_CBC_SHA256", false, false, false, false, 0x0303, 0x0303),
	cipher(0xC04F, "TLS_ECDH_RSA_WITH_ARIA_256_CBC_SHA384", false, false, false, false, 0x0303, 0x0303),
	cipher(0xC050, "TLS_RSA_WITH_ARIA_128_GCM_SHA256", false, false, false, true, 0x0303, 0x0303),
	cipher(0xC051, "TLS_RSA_WITH_ARIA_256_GCM_SHA384", false, false, false, true, 0x0303, 0x0303),
	cipher(0xC052, "TLS_DHE_RSA_WITH_ARIA_128_GCM_SHA256", false, true, false, true, 0x0303, 0x0303),
	cipher(0xC053, "TLS_DHE_RSA_WITH_ARIA_256_GCM_SHA384", false, true, false, true, 0x0303, 0x0303),
	cipher(0xC054, "TLS_DH_RSA_WITH_ARIA_128_GCM_SHA256", false, false, false, true, 0x0303, 0x0303),
	cipher(0xC055, "TLS_DH_RSA_WITH_ARIA_256_GCM_SHA384", false, false, false, true, 0x0303, 0x0303),
	cipher(0xC056, "TLS_DHE_DSS_WITH_ARIA_128_GCM_SHA256", false, true, false, true, 0x0303, 0x0303),
	cipher(0xC057, "TLS_DHE_DSS_WITH_ARIA_256_GCM_SHA384", false, true, false, true, 0x0303, 0x0303),
	cipher(0xC058, "TLS_DH_DSS_WITH_ARIA_128_GCM_SHA256", false, false, false, true, 0x0303, 0x0303),
	cipher(0xC059, "TLS_DH_DSS_WITH_ARIA_256_GCM_SHA384", false, false, false, true, 0x0303, 0x0303),
	cipher(0xC05A, "TLS_DH_anon_WITH_ARIA_128_GCM_SHA256", true, false, false, true, 0x0303, 0x0303),
	cipher(0xC05B, "TLS_DH_anon_WITH_ARIA_256_GCM_SHA384", true, false, false, true, 0x0303, 0x0303),
	cipher(0xC05C, "TLS_ECDHE_ECDSA_WITH_ARIA_128_GCM_SHA256", false, true, true, true, 0x0303, 0x0303),
	cipher(0xC05D, "TLS_ECDHE_ECDSA_WITH_ARIA_256_GCM_SHA384", false, true, true, true, 0x0303, 0x0303),
	cipher(0xC05E, "TLS_ECDH_ECDSA_WITH_ARIA_128_GCM_SHA256", false, false, false, true, 0x0303, 0x0303),
	cipher(0xC05F, "TLS_ECDH_ECDSA_WITH_ARIA_256_GCM_SHA384", false, false, false, true, 0x0303, 0x0303),
	cipher(0xC060, "TLS_ECDHE_RSA_WITH_ARIA_128_GCM_SHA256", false, true, true, true, 0x0303, 0x0303),
	cipher(0xC061, "TLS_ECDHE_RSA_WITH_ARIA_256_GCM_SHA384", false, true, true, true, 0x0303, 0x0303),
	cipher(0xC062, "TLS_ECDH_RSA_WITH_ARIA_128_GCM_SHA256", false, false, false, true, 0x0303, 0x0303),
	cipher(0xC063, "TLS_ECDH_RSA_WITH_ARIA_256_GCM_SHA384", false, false, false, true, 0x0303, 0x0303),
	cipher(0xC072, "TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_CBC_SHA256", false, true, true, false, 0x0303, 0x0303),
	cipher(0xC073, "TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_CBC_SHA384", false, true, true, false, 0x0303, 0x0303),
	cipher(0xC074, "TLS_ECDH_ECDSA_WITH_CAMELLIA_128_CBC_SHA256", false, false, false, false, 0x0303, 0x0303),
	cipher(0xC075, "TLS_ECDH_ECDSA_WITH_CAMELLIA_256_CBC_SHA384", false, false, false, false, 0x0303, 0x0303),
	cipher(0xC076, "TLS_ECDHE_RSA_WITH_CAMELLIA_128_CBC_SHA256", false, true, true, false, 0x0303, 0x0303),
	cipher(0xC077, "TLS_ECDHE_RSA_WITH_CAMELLIA_256_CBC_SHA384", false, true, true, false, 0x0303, 0x0303),
	cipher(0xC078, "TLS_ECDH_RSA_WITH_CAMELLIA_128_CBC_SHA256", false, false, false, false, 0x0303, 0x0303),
	cipher(0xC079, "TLS_ECDH_RSA_WITH_CAMELLIA_256_CBC_SHA384", false, false, false, false, 0x0303, 0x0303),
	cipher(0xC07A, "TLS_RSA_WITH_CAMELLIA_128_GCM_SHA256", false, false, false, true, 0x0303, 0x0303),
	cipher(0xC07B, "TLS_RSA_WITH_CAMELLIA_256_GCM_SHA384", false, false, false, true, 0x0303, 0x0303),
	cipher(0xC07C, "TLS_DHE_RSA_WITH_CAMELLIA_128_GCM_SHA256", false, true, false, true, 0x0303, 0x0303),
	cipher(0xC07D, "TLS_DHE_RSA_WITH_CAMELLIA_256_GCM_SHA384", false, true, false, true, 0x0303, 0x0303),
	cipher(0xC07E, "TLS_DH_RSA_WITH_CAMELLIA_128_GCM_SHA256", false, false, false, true, 0x0303, 0x0303),
	cipher(0xC07F, "TLS_DH_RSA_WITH_CAMELLIA_256_GCM_SHA384", false, false, false, true, 0x0303, 0x0303),
	cipher(0xC080, "TLS_DHE_DSS_WITH_CAMELLIA_128_GCM_SHA256", false, true, false, true, 0x0303, 0x0303),
	cipher(0xC081, "TLS_DHE_DSS_WITH_CAMELLIA_256_GCM_SHA384", false, true, false, true, 0x0303, 0x0303),
	cipher(0xC082, "TLS_DH_DSS_WITH_CAMELLIA_128_GCM_SHA256", false, false, false, true, 0x0303, 0x0303),
	cipher(0xC083, "TLS_DH_DSS_WITH_CAMELLIA_256_GCM_SHA384", false, false, false, true, 0x0303, 0x0303),
	cipher(0xC084, "TLS_DH_anon_WITH_CAMELLIA_128_GCM_SHA256", true, false, false, true, 0x0303, 0x0303),
	cipher(0xC085, "TLS_DH_anon_WITH_CAMELLIA_256_GCM_SHA384", true, false, false, true, 0x0303, 0x0303),
	cipher(0xC086, "TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_GCM_SHA256", false, true, true, true, 0x0303, 0x0303),
	cipher(0xC087, "TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_GCM_SHA384", false, true, true, true, 0x0303, 0x0303),
	cipher(0xC088, "TLS_ECDH_ECDSA_WITH_CAMELLIA_128_GCM_SHA256", false, false, false, true, 0x0303, 0x0303),
	cipher(0xC089, "TLS_ECDH_ECDSA_WITH_CAMELLIA_256_GCM_SHA384", false, false, false, true, 0x0303, 0x0303),
	cipher(0xC08A, "TLS_ECDHE_RSA_WITH_CAMELLIA_128_GCM_SHA256", false, true, true, true, 0x0303, 0x0303),
	cipher(0xC08B, "TLS_ECDHE_RSA_WITH_CAMELLIA_256_GCM_SHA384", false, true, true, true, 0x0303, 0x0303),
	cipher(0xC08C, "TLS_ECDH_RSA_WITH_CAMELLIA_128_GCM_SHA256", false, false, false, true, 0x0303, 0x0303),
	cipher(0xC08D, "TLS_ECDH_RSA_WITH_CAMELLIA_256_GCM_SHA384", false, false, false, true, 0x0303, 0x0303),
	cipher(0xC09C, "TLS_RSA_WITH_AES_128_CCM", false, false, false, true, 0x0303, 0x0303),
	cipher(0xC09D, "TLS_RSA_WITH_AES_256_CCM", false, false, false, true, 0x0303, 0x0303),
	cipher(0xC09E, "TLS_DHE_RSA_WITH_AES_128_CCM", false, true, false, true, 0x0303, 0x0303),
	cipher(0xC09F, "TLS_DHE_RSA_WITH_AES_256_CCM", false, true, false, true, 0x0303, 0x0303),
	cipher(0xC0A0, "TLS_RSA_WITH_AES_128_CCM_8", false, false, false, true, 0x0303, 0x0303),
	cipher(0xC0A1, "TLS_RSA_WITH_AES_256_CCM_8", false, false, false, true, 0x0303, 0x0303),
	cipher(0xC0A2, "TLS_DHE_RSA_WITH_AES_128_CCM_8", false, true, false, true, 0x0303, 0x0303),
	cipher(0xC0A3, "TLS_DHE_RSA_WITH_AES_256_CCM_8", false, true, false, true, 0x0303, 0x0303),
	cipher(0xC0AC, "TLS_ECDHE_ECDSA_WITH_AES_128_CCM", false, true, true, true, 0x0303, 0x0303),
	cipher(0xC0AD, "TLS_ECDHE_ECDSA_WITH_AES_256_CCM", false, true, true, true, 0x0303, 0x0303),
	cipher(0xC0AE, "TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8", false, true, true, true, 0x0303, 0x0303),
	cipher(0xC0AF, "TLS_ECDHE_ECDSA_WITH_AES_256_CCM_8", false, true, true, true, 0x0303, 0x0303),
	cipher(0xCCA8, "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256", false, true, true, true, 0x0303, 0x0303),
	cipher(0xCCA9, "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256", false, true, true, true, 0x0303, 0x0303),
	cipher(0xCCAA, "TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256", false, true, false, true, 0x0303, 0x0303),
}

func init() {
	registry, nameIndex = indexCiphers(cipherRegistry)
}

func indexCiphers(all []CipherInfo) (map[uint16]CipherInfo, map[string]CipherInfo) {
	ids := make(map[uint16]CipherInfo, len(all))
	names := make(map[string]CipherInfo, len(all))
	for _, c := range all {
		if _, exists := ids[c.ID]; exists {
			panic("tlsconst: duplicate cipher ID")
		}
		if _, exists := names[c.Name]; exists {
			panic("tlsconst: duplicate cipher name")
		}
		ids[c.ID], names[c.Name] = c, c
	}
	return ids, names
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
// ascending ID order. Intended for callers that need to enumerate the cipher
// set (e.g. tlsenum's offer list builder).
func AllCiphers() []CipherInfo {
	out := make([]CipherInfo, 0, len(registry))
	for _, c := range registry {
		out = append(out, c)
	}
	slices.SortFunc(out, func(a, b CipherInfo) int { return cmp.Compare(a.ID, b.ID) })
	return out
}

// SupportsVersion describes protocol applicability, not a security endorsement.
func (c CipherInfo) SupportsVersion(version uint16) bool {
	return c.MinVersion != 0 && version >= c.MinVersion && version <= c.MaxVersion
}

// EnumerationProfile identifies a fixed bounded offer, not all possible server
// configurations. Bump it when changing the suite, signature or group offers.
const EnumerationProfile = "tls-cert-v1"

// FiniteFieldDHE identifies ServerKeyExchange layouts by IANA cipher ID.
func FiniteFieldDHE(id uint16) (dhe, signed bool) {
	switch id {
	case 0x0011, 0x0012, 0x0013, 0x0014, 0x0015, 0x0016, 0x0032, 0x0033,
		0x0038, 0x0039, 0x0040, 0x0044, 0x0045, 0x0067, 0x006A, 0x006B,
		0x0087, 0x0088, 0x0099, 0x009A, 0x009E, 0x009F, 0x00A2, 0x00A3,
		0x00BD, 0x00BE, 0x00C3, 0x00C4, 0xC042, 0xC043, 0xC044, 0xC045,
		0xC052, 0xC053, 0xC056, 0xC057, 0xC07C, 0xC07D, 0xC080, 0xC081,
		0xC09E, 0xC09F, 0xC0A2, 0xC0A3, 0xCCAA:
		return true, true
	case 0x0017, 0x0018, 0x0019, 0x001A, 0x001B, 0x0034, 0x003A, 0x0046,
		0x006C, 0x006D, 0x0089, 0x009B, 0x00A6, 0x00A7, 0x00BF, 0x00C5,
		0xC046, 0xC047, 0xC05A, 0xC05B, 0xC084, 0xC085:
		return true, false
	default:
		return false, false
	}
}
