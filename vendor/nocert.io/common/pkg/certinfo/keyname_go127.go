//go:build go1.27

package certinfo

import (
	"crypto/mldsa"
	"crypto/x509"
)

// extendedPublicKeyName preserves the ML-DSA parameter set, which the generic
// x509.PublicKeyAlgorithm name does not distinguish. Keep this version-gated
// while consumers of common still support Go 1.26.
func extendedPublicKeyName(cert *x509.Certificate) string {
	if key, ok := cert.PublicKey.(*mldsa.PublicKey); ok {
		switch key.Parameters() {
		case mldsa.MLDSA44():
			return "ML-DSA-44"
		case mldsa.MLDSA65():
			return "ML-DSA-65"
		case mldsa.MLDSA87():
			return "ML-DSA-87"
		}
		return "unknown"
	}
	return classicalPublicKeyName(cert.PublicKeyAlgorithm)
}

func extendedSignatureName(alg x509.SignatureAlgorithm) string {
	switch alg {
	case x509.MLDSA44:
		return "ML-DSA-44"
	case x509.MLDSA65:
		return "ML-DSA-65"
	case x509.MLDSA87:
		return "ML-DSA-87"
	default:
		return "unknown"
	}
}
