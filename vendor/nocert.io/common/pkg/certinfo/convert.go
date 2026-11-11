package certinfo

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"fmt"
	"strings"
)

// FormatFingerprint formats a SHA-256 hash as colon-separated uppercase hex.
func FormatFingerprint(raw [32]byte) string {
	parts := make([]string, 32)
	for i, b := range raw {
		parts[i] = fmt.Sprintf("%02X", b)
	}
	return strings.Join(parts, ":")
}

// MaxSANCount caps the number of SANs to prevent memory exhaustion.
const MaxSANCount = 1000

// MaxPolicyOIDs caps the exported certificate-policy list.
const MaxPolicyOIDs = 100

// MaxExtKeyUsages caps the number of extended-key-usage entries we expose.
// Real certs use <= 10; the cap is generous insurance against pathological
// extensions.
const MaxExtKeyUsages = 32

// MaxSubjectDNSize and MaxIssuerDNSize cap the RFC 2253 string form of
// the Subject and Issuer distinguished names. Certparser checks the raw DN
// before conversion; keep these caps at least as high as its accepted limit.
// Truncation remains defense in depth for callers outside certparser.
const MaxSubjectDNSize = 2048
const MaxIssuerDNSize = 2048

// MaxSerialNumberSize caps the decimal string representation of the
// certificate serial number. RFC 5280 §4.1.2.2 limits the encoded serial
// to 20 octets, which is at most ~50 decimal characters; 64 leaves a
// safety margin without permitting attacker-controlled bloat.
const MaxSerialNumberSize = 64

// MaxAIAURLCount caps the number of URLs we expose per AIA list (OCSP
// responder, CA issuers). Real CAs publish a handful; 100 is generous.
const MaxAIAURLCount = 100

// MaxAIAURLSize caps the per-URL byte length. Real AIA URLs are <200
// chars; 2048 leaves headroom without DoS exposure.
const MaxAIAURLSize = 2048

// MaxUnknownExtKeyUsageOIDs caps the dotted-OID list of extended key usages
// Go's crypto/x509 did not recognize. Real certs carry a handful.
const MaxUnknownExtKeyUsageOIDs = 16

// MaxCRLDistributionPoints caps the number of CRL distribution point URIs.
// Real certs publish 1-2; the cap bounds adversarial bloat.
const MaxCRLDistributionPoints = 16

// MaxUnhandledCriticalExtensions caps the number of critical-but-unknown
// extension OIDs surfaced on the cert. Legitimate certs carry zero; a
// malformed or adversarial cert carrying dozens is still flagged via the
// warning (length > 0 is the signal), and truncating keeps the stored
// payload bounded.
const MaxUnhandledCriticalExtensions = 16

var tlsFeatureOID = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 1, 24}

const tlsFeatureStatusRequest = 5

// hasOCSPMustStaple returns true when the TLS Feature extension contains
// status_request (feature 5), commonly called OCSP Must-Staple. Malformed
// extension values are treated as absent; validation policy lives downstream.
func hasOCSPMustStaple(cert *x509.Certificate) bool {
	for _, ext := range cert.Extensions {
		if !ext.Id.Equal(tlsFeatureOID) {
			continue
		}
		var features []int
		rest, err := asn1.Unmarshal(ext.Value, &features)
		if err != nil || len(rest) != 0 {
			return false
		}
		for _, feature := range features {
			if feature == tlsFeatureStatusRequest {
				return true
			}
		}
		return false
	}
	return false
}

// FromX509 converts a non-nil, parsed certificate to bounded metadata.
// It does not validate trust. RawDER shares the certificate's backing bytes;
// callers must treat them as immutable.
func FromX509(cert *x509.Certificate) *CertificateInfo {
	hash := sha256.Sum256(cert.Raw)

	info := &CertificateInfo{
		Fingerprint:                 FormatFingerprint(hash),
		Version:                     cert.Version,
		SerialNumber:                truncateString(cert.SerialNumber.String(), MaxSerialNumberSize),
		SubjectCN:                   SanitizeField(cert.Subject.CommonName),
		SubjectOrg:                  SanitizeField(firstOrEmpty(cert.Subject.Organization)),
		SubjectCountry:              SanitizeField(firstOrEmpty(cert.Subject.Country)),
		IssuerCN:                    SanitizeField(cert.Issuer.CommonName),
		IssuerOrg:                   SanitizeField(firstOrEmpty(cert.Issuer.Organization)),
		IssuerCountry:               SanitizeField(firstOrEmpty(cert.Issuer.Country)),
		SANs:                        CollectSANs(cert),
		NotBefore:                   cert.NotBefore,
		NotAfter:                    cert.NotAfter,
		KeyAlgorithm:                publicKeyAlgName(cert),
		KeySize:                     publicKeySize(cert),
		SignatureAlgorithm:          signatureAlgorithmName(cert.SignatureAlgorithm),
		KeyUsages:                   keyUsageStrings(cert.KeyUsage),
		ExtendedKeyUsages:           extKeyUsageStrings(cert.ExtKeyUsage),
		PolicyOIDs:                  policyOIDStrings(cert),
		IsCA:                        cert.IsCA,
		SelfSigned:                  isSelfSigned(cert),
		PreQuantum:                  isClassicalAlgorithm(cert),
		EmbeddedSCTCount:            countEmbeddedSCTs(cert),
		AKI:                         formatHexColon(cert.AuthorityKeyId),
		SKI:                         formatHexColon(cert.SubjectKeyId),
		RawDER:                      cert.Raw,
		SubjectDN:                   truncateString(SanitizeField(cert.Subject.String()), MaxSubjectDNSize),
		SubjectDNHash:               dnHashHex(cert.RawSubject),
		IssuerDN:                    truncateString(SanitizeField(cert.Issuer.String()), MaxIssuerDNSize),
		IssuerDNHash:                dnHashHex(cert.RawIssuer),
		OCSPServers:                 collectAIAURLs(cert.OCSPServer),
		OCSPMustStaple:              hasOCSPMustStaple(cert),
		IssuingCertificateURLs:      collectAIAURLs(cert.IssuingCertificateURL),
		IPAddressSANs:               collectIPAddressSANs(cert.IPAddresses),
		IsPrecertificate:            hasPoisonExtension(cert),
		UnhandledCriticalExtensions: unhandledCriticalExtensions(cert),
		UnknownExtKeyUsageOIDs:      unknownExtKeyUsageOIDs(cert),
		CRLDistributionPoints:       collectCRLDistributionPoints(cert.CRLDistributionPoints),
		ValidationLevel:             validationLevel(cert),
		RSAExponent:                 rsaExponent(cert),
		BasicConstraintsCritical:    basicConstraintsCritical(cert),
	}

	return info
}

// ChainFromX509 converts a chain of x509.Certificates to ChainEntry slices.
func ChainFromX509(certs []*x509.Certificate) []ChainEntry {
	if len(certs) == 0 {
		return nil
	}
	entries := make([]ChainEntry, len(certs))
	for i, c := range certs {
		hash := sha256.Sum256(c.Raw)
		entries[i] = ChainEntry{
			SubjectCN:         SanitizeField(c.Subject.CommonName),
			IssuerCN:          SanitizeField(c.Issuer.CommonName),
			NotBefore:         c.NotBefore,
			NotAfter:          c.NotAfter,
			FingerprintSHA256: FormatFingerprint(hash),
			RawDER:            c.Raw,
		}
	}
	return entries
}

// isSelfSigned checks if a certificate is self-signed using AuthorityKeyIdentifier
// matching and raw signature self-verification.
func isSelfSigned(cert *x509.Certificate) bool {
	if len(cert.AuthorityKeyId) > 0 && len(cert.SubjectKeyId) > 0 {
		if !bytes.Equal(cert.AuthorityKeyId, cert.SubjectKeyId) {
			return false
		}
	}
	return cert.CheckSignature(cert.SignatureAlgorithm, cert.RawTBSCertificate, cert.Signature) == nil
}

// isClassicalAlgorithm returns true for RSA, ECDSA and Ed25519 - all broken by
// Shor's algorithm. This describes the subject key only, not the issuer's
// signature or the quantum resistance of the entire chain.
func isClassicalAlgorithm(cert *x509.Certificate) bool {
	switch cert.PublicKey.(type) {
	case *rsa.PublicKey, *ecdsa.PublicKey, ed25519.PublicKey:
		return true
	default:
		return false
	}
}

func publicKeyAlgName(cert *x509.Certificate) string {
	switch cert.PublicKey.(type) {
	case *rsa.PublicKey:
		return "RSA"
	case *ecdsa.PublicKey:
		return "ECDSA"
	case ed25519.PublicKey:
		return "Ed25519"
	default:
		return extendedPublicKeyName(cert)
	}
}

func publicKeySize(cert *x509.Certificate) int {
	switch pub := cert.PublicKey.(type) {
	case *rsa.PublicKey:
		return pub.N.BitLen()
	case *ecdsa.PublicKey:
		return pub.Curve.Params().BitSize
	case ed25519.PublicKey:
		return 256
	default:
		return 0
	}
}

func firstOrEmpty(s []string) string {
	if len(s) > 0 {
		return s[0]
	}
	return ""
}

// dnHashHex returns the hex-encoded SHA-256 of the raw ASN.1 DN bytes.
// This is a byte-level identity, not a normalized X.509 name comparison.
// The display string can lose ASN.1 string-type and ordering information.
//
// Returns "" when rawDN is the empty SEQUENCE (`30 00`, 2 bytes) or
// shorter - malformed/empty DNs would otherwise collide on a single
// fixed hash and cause false matches in the chain walker.
func dnHashHex(rawDN []byte) string {
	if len(rawDN) <= 2 {
		return ""
	}
	h := sha256.Sum256(rawDN)
	return fmt.Sprintf("%x", h)
}

func formatHexColon(data []byte) string {
	if len(data) == 0 {
		return ""
	}
	parts := make([]string, len(data))
	for i, b := range data {
		parts[i] = fmt.Sprintf("%02X", b)
	}
	return strings.Join(parts, ":")
}

// truncateString returns s if len(s) <= max, else s[:max]. A cut may split a
// multi-byte UTF-8 rune, leaving a benign replacement char downstream; callers
// sanitize before or after truncation, so no control byte survives.
func truncateString(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max]
}

// poisonExtensionOID is the precertificate poison extension (RFC 6962 §3.1).
// Its presence on a TLS-served cert is a misconfiguration IOC. Absence does
// not prove non-precert (an attacker can strip the extension before serving).
var poisonExtensionOID = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 11129, 2, 4, 3}

// hasPoisonExtension returns true iff the cert carries the precertificate
// poison extension. Criticality is not checked - RFC 6962 mandates
// critical:true but presence alone is the signal we expose.
func hasPoisonExtension(cert *x509.Certificate) bool {
	for _, ext := range cert.Extensions {
		if ext.Id.Equal(poisonExtensionOID) {
			return true
		}
	}
	return false
}

// rsaExponent returns the RSA public exponent (e), or 0 for non-RSA keys.
func rsaExponent(cert *x509.Certificate) int {
	if pub, ok := cert.PublicKey.(*rsa.PublicKey); ok {
		return pub.E
	}
	return 0
}

// basicConstraintsOID is the basicConstraints extension (RFC 5280 §4.2.1.9).
var basicConstraintsOID = asn1.ObjectIdentifier{2, 5, 29, 19}

// basicConstraintsCritical reports whether the basicConstraints extension is
// present AND marked critical. RFC 5280 requires critical:true on CA certs;
// buildWarnings flags a CA where this is false.
func basicConstraintsCritical(cert *x509.Certificate) bool {
	for _, ext := range cert.Extensions {
		if ext.Id.Equal(basicConstraintsOID) {
			return ext.Critical
		}
	}
	return false
}

// unhandledCriticalExtensions returns the OIDs (dotted string form) of
// extensions marked critical in the cert but not processed by Go's
// crypto/x509. Truncated to MaxUnhandledCriticalExtensions.
func unhandledCriticalExtensions(cert *x509.Certificate) []string {
	if len(cert.UnhandledCriticalExtensions) == 0 {
		return nil
	}
	n := len(cert.UnhandledCriticalExtensions)
	if n > MaxUnhandledCriticalExtensions {
		n = MaxUnhandledCriticalExtensions
	}
	out := make([]string, n)
	for i := 0; i < n; i++ {
		out[i] = cert.UnhandledCriticalExtensions[i].String()
	}
	return out
}
