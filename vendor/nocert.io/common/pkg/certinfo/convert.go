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
	"net"
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

// MaxPolicyOIDs caps the number of certificate-policy OIDs we expose.
// Real certs use <= 50; anything beyond 100 is junk or an OID-bomb attempt
// (see CVE-2025-61729 / CVE-2026-32281 - quadratic policy-mapping work in
// Go's crypto/x509 chain validation).
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

// CollectSANs merges all Subject Alternative Names into one sanitized,
// MaxSANCount-capped list in stable order: DNS, IP, email, URI.
func CollectSANs(cert *x509.Certificate) []string {
	var sans []string
	sans = append(sans, cert.DNSNames...)
	for _, ip := range cert.IPAddresses {
		sans = append(sans, ip.String())
	}
	sans = append(sans, cert.EmailAddresses...)
	for _, u := range cert.URIs {
		sans = append(sans, u.String())
	}
	if len(sans) > MaxSANCount {
		sans = sans[:MaxSANCount]
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
	out := make([]string, 0, len(ips))
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
// dropped as junk. Compared against the lowercased, sanitized value.
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
	seen := make(map[string]struct{}, len(cert.UnknownExtKeyUsage))
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

// FromX509 converts a stdlib x509.Certificate to a CertificateInfo.
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
		SignatureAlgorithm:          cert.SignatureAlgorithm.String(),
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
// Hashing the DER (not the RFC 2253 string) matches X509_NAME_cmp:
// stringification is lossy across ASN.1 string types and attribute order.
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

func keyUsageStrings(ku x509.KeyUsage) []string {
	var usages []string
	mapping := []struct {
		bit  x509.KeyUsage
		name string
	}{
		{x509.KeyUsageDigitalSignature, "digital_signature"},
		{x509.KeyUsageContentCommitment, "content_commitment"},
		{x509.KeyUsageKeyEncipherment, "key_encipherment"},
		{x509.KeyUsageDataEncipherment, "data_encipherment"},
		{x509.KeyUsageKeyAgreement, "key_agreement"},
		{x509.KeyUsageCertSign, "cert_sign"},
		{x509.KeyUsageCRLSign, "crl_sign"},
		{x509.KeyUsageEncipherOnly, "encipher_only"},
		{x509.KeyUsageDecipherOnly, "decipher_only"},
	}
	for _, m := range mapping {
		if ku&m.bit != 0 {
			usages = append(usages, m.name)
		}
	}
	return usages
}

func extKeyUsageStrings(ekus []x509.ExtKeyUsage) []string {
	if len(ekus) == 0 {
		return nil
	}
	// crypto/x509 appends EKUs in cert order without deduplicating, so a cert
	// can repeat a usage arbitrarily. Dedup before the cap: otherwise a flood
	// of duplicates could push a load-bearing usage (server_auth/client_auth/
	// any) past MaxExtKeyUsages and out of the list the warning signals read
	// from, silently suppressing eku_any / dual_eku_deprecated. The cap stays
	// as a belt-and-suspenders bound on the deduped (already small) set.
	seen := make(map[x509.ExtKeyUsage]struct{}, len(ekus))
	deduped := make([]x509.ExtKeyUsage, 0, len(ekus))
	for _, eku := range ekus {
		if _, dup := seen[eku]; dup {
			continue
		}
		seen[eku] = struct{}{}
		deduped = append(deduped, eku)
	}
	ekus = deduped
	if len(ekus) > MaxExtKeyUsages {
		ekus = ekus[:MaxExtKeyUsages]
	}
	mapping := map[x509.ExtKeyUsage]string{
		x509.ExtKeyUsageAny:                            "any",
		x509.ExtKeyUsageServerAuth:                     "server_auth",
		x509.ExtKeyUsageClientAuth:                     "client_auth",
		x509.ExtKeyUsageCodeSigning:                    "code_signing",
		x509.ExtKeyUsageEmailProtection:                "email_protection",
		x509.ExtKeyUsageTimeStamping:                   "time_stamping",
		x509.ExtKeyUsageOCSPSigning:                    "ocsp_signing",
		x509.ExtKeyUsageMicrosoftServerGatedCrypto:     "ms_sgc",
		x509.ExtKeyUsageNetscapeServerGatedCrypto:      "ns_sgc",
		x509.ExtKeyUsageMicrosoftCommercialCodeSigning: "ms_code_signing",
		x509.ExtKeyUsageMicrosoftKernelCodeSigning:     "ms_kernel_code_signing",
	}
	var usages []string
	for _, eku := range ekus {
		if name, ok := mapping[eku]; ok {
			usages = append(usages, name)
		} else {
			usages = append(usages, fmt.Sprintf("unknown_%d", int(eku)))
		}
	}
	return usages
}

// policyOIDStrings collects certificate-policy OIDs from both the modern
// cert.Policies field (x509.OID, added in Go 1.22) and the legacy
// PolicyIdentifiers field (asn1.ObjectIdentifier, deprecated).
//
// Reading only PolicyIdentifiers was a silent bug: since Go 1.24, policy
// OIDs with arcs exceeding int32 are exposed ONLY via cert.Policies, and
// such certs had their policy_oids field missing from /parse responses.
// We read both, dedupe on string form, and preserve first-seen order.
func policyOIDStrings(cert *x509.Certificate) []string {
	total := len(cert.Policies) + len(cert.PolicyIdentifiers)
	if total == 0 {
		return nil
	}
	oids := make([]string, 0, total)
	seen := make(map[string]struct{}, total)
	add := func(s string) bool {
		if _, dup := seen[s]; dup {
			return true
		}
		seen[s] = struct{}{}
		oids = append(oids, s)
		return len(oids) < MaxPolicyOIDs
	}
	for _, oid := range cert.Policies {
		if !add(oid.String()) {
			return oids
		}
	}
	for _, oid := range cert.PolicyIdentifiers {
		if !add(oid.String()) {
			return oids
		}
	}
	return oids
}

// CA/Browser Forum reserved certificate-policy OIDs identifying a leaf's
// validation tier (CABF Object Registry). Mandatory on publicly-trusted TLS
// leaves since 2023-09-15 (ballot SC62v2); a well-formed leaf asserts exactly
// one. EV lives on a separate arc from DV/OV/IV.
const (
	oidValidationEV = "2.23.140.1.1"
	oidValidationDV = "2.23.140.1.2.1"
	oidValidationOV = "2.23.140.1.2.2"
	oidValidationIV = "2.23.140.1.2.3"
)

// validationLevel maps a leaf's reserved policy OID to "EV"/"OV"/"IV"/"DV".
// Returns "" (Unknown) for CA/intermediate certs, certs with no reserved OID
// (private CA, pre-2023 public), and the BR-forbidden case of two different
// reserved tiers - absence is never inferred as DV, and we never guess.
func validationLevel(cert *x509.Certificate) string {
	if cert.IsCA {
		return ""
	}
	levels := make(map[string]struct{}, 1)
	for _, oid := range policyOIDStrings(cert) {
		switch oid {
		case oidValidationEV:
			levels["EV"] = struct{}{}
		case oidValidationOV:
			levels["OV"] = struct{}{}
		case oidValidationIV:
			levels["IV"] = struct{}{}
		case oidValidationDV:
			levels["DV"] = struct{}{}
		}
	}
	if len(levels) != 1 {
		return ""
	}
	for l := range levels {
		return l
	}
	return ""
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
