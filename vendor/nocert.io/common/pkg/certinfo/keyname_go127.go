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
		return key.Parameters().String()
	}
	return cert.PublicKeyAlgorithm.String()
}
