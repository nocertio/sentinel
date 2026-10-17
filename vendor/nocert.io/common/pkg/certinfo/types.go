package certinfo

import "time"

// CertificateInfo holds extracted metadata from a leaf certificate.
// Field names and JSON tags form a stable contract consumed by downstream
// tooling; reorder or rename carefully. KeySize is the RSA modulus / EC size
// in bits (256 for Ed25519), or zero when not comparable (ML-DSA). ML-DSA
// parameter sets are included in KeyAlgorithm, e.g. "ML-DSA-44".
type CertificateInfo struct {
	Fingerprint            string    `json:"fingerprint"`
	Version                int       `json:"version"`
	SerialNumber           string    `json:"serial_number"`
	SubjectCN              string    `json:"subject_cn"`
	SubjectOrg             string    `json:"subject_org"`
	SubjectCountry         string    `json:"subject_country"`
	IssuerCN               string    `json:"issuer_cn"`
	IssuerOrg              string    `json:"issuer_org"`
	IssuerCountry          string    `json:"issuer_country"`
	SANs                   []string  `json:"sans"`
	NotBefore              time.Time `json:"not_before"`
	NotAfter               time.Time `json:"not_after"`
	KeyAlgorithm           string    `json:"key_algorithm"`
	KeySize                int       `json:"key_size"`
	SignatureAlgorithm     string    `json:"signature_algorithm"`
	KeyUsages              []string  `json:"key_usages"`
	ExtendedKeyUsages      []string  `json:"extended_key_usages"`
	PolicyOIDs             []string  `json:"policy_oids,omitempty"`
	IsCA                   bool      `json:"is_ca"`
	SelfSigned             bool      `json:"self_signed"`
	PreQuantum             bool      `json:"pre_quantum"`
	AKI                    string    `json:"aki"`
	SKI                    string    `json:"ski"`
	RawDER                 []byte    `json:"raw_der,omitempty"`
	SubjectDN              string    `json:"subject_dn"`
	SubjectDNHash          string    `json:"subject_dn_hash"` // "" when DN is the empty SEQUENCE
	IssuerDN               string    `json:"issuer_dn"`
	IssuerDNHash           string    `json:"issuer_dn_hash"` // "" when DN is the empty SEQUENCE
	EmbeddedSCTCount       int       `json:"embedded_sct_count,omitempty"`
	OCSPServers            []string  `json:"ocsp_servers,omitempty"`
	OCSPMustStaple         bool      `json:"ocsp_must_staple,omitempty"`
	IssuingCertificateURLs []string  `json:"issuing_certificate_urls,omitempty"`
	IPAddressSANs          []string  `json:"ip_address_sans,omitempty"`
	IsPrecertificate       bool      `json:"is_precertificate,omitempty"`
	// UnhandledCriticalExtensions are the OIDs (dotted string form) of
	// extensions the cert marks `critical: true` but Go's crypto/x509
	// did not process. RFC 5280 mandates a relying party reject such a
	// cert; Go's ParseCertificate accepts it and stashes the OIDs here.
	// nocert surfaces them so the backend can warn and so /verify can
	// hard-fail the chain (Go's Verify historically did not - see
	// golang/go#22260).
	UnhandledCriticalExtensions []string `json:"unhandled_critical_extensions,omitempty"`
	// UnknownExtKeyUsageOIDs holds extended-key-usage OIDs (dotted form) Go's
	// crypto/x509 did not map to a known x509.ExtKeyUsage constant -
	// MS Smart Card Logon, Apple/Adobe usages, etc. ExtendedKeyUsages only
	// covers the known enum, so these would otherwise be invisible.
	UnknownExtKeyUsageOIDs []string `json:"unknown_ext_key_usage_oids,omitempty"`
	// CRLDistributionPoints holds the CRL distribution point URIs
	// (http/https/ldap). Increasingly the only revocation channel since
	// Let's Encrypt stopped serving OCSP (2025).
	CRLDistributionPoints []string `json:"crl_distribution_points,omitempty"`
	// ValidationLevel classifies a leaf's CA/Browser Forum tier from its
	// reserved policy OID: "EV", "OV", "IV", or "DV". Empty when the cert
	// carries no recognized reserved OID (private CA, pre-2023 public cert,
	// or a CA/intermediate) - absence is NOT inferred as DV.
	ValidationLevel string `json:"validation_level,omitempty"`
	// RSAExponent is the RSA public exponent (e); 0 for non-RSA keys. The
	// near-universal value is 65537. Surfaced for display only - e=3 is
	// CABF-compliant so it carries no warning.
	RSAExponent int `json:"rsa_exponent,omitempty"`
	// BasicConstraintsCritical is true iff the basicConstraints extension is
	// present AND marked critical. RFC 5280 §4.2.1.9 requires it critical on
	// CA certs; buildWarnings flags a non-self-signed CA where this is false.
	// Parse-time signal only - not persisted on the cert doc, so it reads back
	// false after a re-read; the derived warning is what survives.
	BasicConstraintsCritical bool `json:"basic_constraints_critical,omitempty"`
}

// ChainEntry holds metadata for one certificate in the chain.
type ChainEntry struct {
	SubjectCN         string    `json:"subject_cn"`
	IssuerCN          string    `json:"issuer_cn"`
	NotBefore         time.Time `json:"not_before"`
	NotAfter          time.Time `json:"not_after"`
	FingerprintSHA256 string    `json:"fingerprint"`
	RawDER            []byte    `json:"raw_der,omitempty"`
}

// CipherFinding is one (TLS version, cipher suite) pair the server advertised.
// This is the backend-internal type: IsWeak is derived from the IANA registry
// on the backend, never trusted from an agent. The agent-input counterpart
// (no IsWeak) is pkg/api/sentinel.CipherFinding.
type CipherFinding struct {
	Version string `json:"version"`
	Cipher  string `json:"cipher"`
	IsWeak  bool   `json:"is_weak"`
}

// TLSObservation holds TLS connection metadata. JSON tags form a stable
// contract consumed by downstream tooling.
type TLSObservation struct {
	HandshakeComplete  *bool           `json:"handshake_complete,omitempty"`
	HSTSChecked        *bool           `json:"hsts_checked,omitempty"`
	TLSVersion         string          `json:"tls_version"`
	SupportedProtocols []string        `json:"supported_protocols,omitempty"`
	CipherSuite        string          `json:"cipher_suite"`
	NegotiatedGroup    string          `json:"negotiated_group,omitempty"`
	OCSPStapling       bool            `json:"ocsp_stapling"`
	HSTSEnabled        bool            `json:"hsts_enabled"`
	HSTSMaxAge         int             `json:"hsts_max_age,omitempty"`
	CipherEnumeration  []CipherFinding `json:"cipher_enumeration,omitempty"`
}

// Target represents an FQDN with ports to scan.
type Target struct {
	FQDN  string `json:"fqdn"`
	Ports []int  `json:"ports"`
	// Priority >= 100 runs outside the worker pool; 0 is the normal path.
	Priority int `json:"priority"`
	// DeepEnum requests cipher enumeration after the fast probe.
	DeepEnum bool `json:"deep_enum,omitempty"`
	// IP, when set, pins the fast probe and enum dial to this exact peer
	// (SNI stays FQDN). Empty resolves FQDN via the stdlib resolver as before.
	IP string `json:"ip,omitempty"`
}
