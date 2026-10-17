//go:build !go1.27

package certinfo

import "crypto/x509"

func extendedPublicKeyName(cert *x509.Certificate) string {
	return cert.PublicKeyAlgorithm.String()
}
