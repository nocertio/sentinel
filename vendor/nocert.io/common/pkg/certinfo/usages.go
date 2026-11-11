package certinfo

import (
	"crypto/x509"
	"fmt"
)

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
	// Deduplicate before applying the limit so repetitions do not hide other usages.
	seen := make(map[x509.ExtKeyUsage]struct{}, min(len(ekus), MaxExtKeyUsages))
	deduped := make([]x509.ExtKeyUsage, 0, min(len(ekus), MaxExtKeyUsages))
	for _, eku := range ekus {
		if _, dup := seen[eku]; dup {
			continue
		}
		seen[eku] = struct{}{}
		deduped = append(deduped, eku)
		if len(deduped) == MaxExtKeyUsages {
			break
		}
	}
	ekus = deduped
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

// policyOIDStrings merges modern and legacy policy fields in first-seen order.
// Policies includes OID arcs too large for the legacy PolicyIdentifiers field.
// The returned display list is capped; classification uses the complete input.
func policyOIDStrings(cert *x509.Certificate) []string {
	total := len(cert.Policies) + len(cert.PolicyIdentifiers)
	if total == 0 {
		return nil
	}
	oids := make([]string, 0, min(total, MaxPolicyOIDs))
	seen := make(map[string]struct{}, min(total, MaxPolicyOIDs))
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
	add := func(oid string) {
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
	for _, oid := range cert.Policies {
		add(oid.String())
	}
	for _, oid := range cert.PolicyIdentifiers {
		add(oid.String())
	}
	if len(levels) != 1 {
		return ""
	}
	for l := range levels {
		return l
	}
	return ""
}
