package certinfo

import "crypto/x509"

// Local labels form a persisted contract, independent of Go String methods.
func signatureAlgorithmName(alg x509.SignatureAlgorithm) string {
	switch alg {
	case x509.MD2WithRSA:
		return "MD2-RSA"
	case x509.MD5WithRSA:
		return "MD5-RSA"
	case x509.SHA1WithRSA:
		return "SHA1-RSA"
	case x509.SHA256WithRSA:
		return "SHA256-RSA"
	case x509.SHA384WithRSA:
		return "SHA384-RSA"
	case x509.SHA512WithRSA:
		return "SHA512-RSA"
	case x509.DSAWithSHA1:
		return "DSA-SHA1"
	case x509.DSAWithSHA256:
		return "DSA-SHA256"
	case x509.ECDSAWithSHA1:
		return "ECDSA-SHA1"
	case x509.ECDSAWithSHA256:
		return "ECDSA-SHA256"
	case x509.ECDSAWithSHA384:
		return "ECDSA-SHA384"
	case x509.ECDSAWithSHA512:
		return "ECDSA-SHA512"
	case x509.SHA256WithRSAPSS:
		return "SHA256-RSAPSS"
	case x509.SHA384WithRSAPSS:
		return "SHA384-RSAPSS"
	case x509.SHA512WithRSAPSS:
		return "SHA512-RSAPSS"
	case x509.PureEd25519:
		return "Ed25519"
	default:
		return extendedSignatureName(alg)
	}
}

func classicalPublicKeyName(alg x509.PublicKeyAlgorithm) string {
	switch alg {
	case x509.RSA:
		return "RSA"
	case x509.DSA:
		return "DSA"
	case x509.ECDSA:
		return "ECDSA"
	case x509.Ed25519:
		return "Ed25519"
	default:
		return "unknown"
	}
}
