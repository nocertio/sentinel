//go:build !go1.27

package certinfo

import "crypto/x509"

func extendedPublicKeyName(cert *x509.Certificate) string {
	return classicalPublicKeyName(cert.PublicKeyAlgorithm)
}

func extendedSignatureName(_ x509.SignatureAlgorithm) string { return "unknown" }
