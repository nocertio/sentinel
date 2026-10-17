package certinfo

import (
	"crypto/x509"
	"encoding/asn1"

	"golang.org/x/crypto/cryptobyte"
)

// sctEmbeddedOID is the OID of the X.509 extension carrying the list of
// SCTs embedded in a certificate (RFC 6962 §3.3).
var sctEmbeddedOID = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 11129, 2, 4, 2}

// maxSCTExtensionSize is a defense-in-depth cap. A single SCT is a few
// hundred bytes; 64 KB largely covers the worst legitimate case. Beyond
// that we return 0 without parsing.
const maxSCTExtensionSize = 65536

// asn1OctetStringTag is the ASN.1 tag of an OCTET STRING.
const asn1OctetStringTag = 0x04

// countEmbeddedSCTs returns the number of SignedCertificateTimestamps
// embedded in the certificate (RFC 6962 §3.3 extension). 0 if the
// extension is absent, the payload is invalid, or the size is above
// the cap. We do not cryptographically validate the SCTs (would
// duplicate browser work and require bundling CT log keys).
func countEmbeddedSCTs(cert *x509.Certificate) int {
	for _, ext := range cert.Extensions {
		if !ext.Id.Equal(sctEmbeddedOID) {
			continue
		}
		if len(ext.Value) > maxSCTExtensionSize {
			return 0
		}
		return parseSCTListCount(ext.Value)
	}
	return 0
}

// parseSCTListCount parses the SCT extension payload (RFC 6962 §3.3):
//  1. ext.Value is already the OCTET STRING unwrapped by crypto/x509.
//  2. Its content is another OCTET STRING (RFC 6962 re-wrapping).
//  3. That 2nd OCTET STRING contains a SignedCertificateTimestampList:
//     uint16 total_length + a sequence of SCTs, each uint16 length-prefixed.
//
// Returns 0 on any malformation. O(1) in memory (no intermediate SCT
// slice).
func parseSCTListCount(extValue []byte) int {
	outer := cryptobyte.String(extValue)
	var inner cryptobyte.String
	if !outer.ReadASN1(&inner, asn1OctetStringTag) {
		return 0
	}

	var sctList cryptobyte.String
	if !inner.ReadUint16LengthPrefixed(&sctList) {
		return 0
	}

	count := 0
	for !sctList.Empty() {
		var sct cryptobyte.String
		if !sctList.ReadUint16LengthPrefixed(&sct) {
			return 0
		}
		// A SerializedSCT always carries at least version+log_id+timestamp+
		// signature (RFC 6962 §3.2), so a zero-length entry is malformed. Treat
		// the whole list as malformed rather than letting empty entries pad the
		// count toward the >=2 baseline.
		if len(sct) == 0 {
			return 0
		}
		count++
	}
	return count
}
