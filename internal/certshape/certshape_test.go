package certshape

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"
)

// crypto/x509 is used HERE (tests only) to fabricate realistic fixtures. The
// production gate in certshape.go never imports it.

func selfSignedRSACertDER(tb testing.TB) []byte {
	tb.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		tb.Fatal(err)
	}
	return certDER(tb, priv, &priv.PublicKey, 1)
}

func selfSignedECCertDER(tb testing.TB) []byte {
	tb.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		tb.Fatal(err)
	}
	return certDER(tb, priv, &priv.PublicKey, 2)
}

func certDER(tb testing.TB, signer any, pub any, serial int64) []byte {
	tb.Helper()
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(serial),
		Subject:      pkix.Name{CommonName: "shape.test"},
		NotBefore:    time.Unix(0, 0),
		NotAfter:     time.Unix(1<<31, 0),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, pub, signer)
	if err != nil {
		tb.Fatal(err)
	}
	return der
}

func rsaPKCS1DER(tb testing.TB) []byte {
	tb.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		tb.Fatal(err)
	}
	return x509.MarshalPKCS1PrivateKey(priv)
}

func pkcs8DER(tb testing.TB, key any) []byte {
	tb.Helper()
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		tb.Fatal(err)
	}
	return der
}

func rsaPKCS8DER(tb testing.TB) []byte {
	tb.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		tb.Fatal(err)
	}
	return pkcs8DER(tb, priv)
}

func ecPKCS8DER(tb testing.TB) []byte {
	tb.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		tb.Fatal(err)
	}
	return pkcs8DER(tb, priv)
}

func ecSEC1DER(tb testing.TB) []byte {
	tb.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		tb.Fatal(err)
	}
	der, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		tb.Fatal(err)
	}
	return der
}

func ed25519PKCS8DER(tb testing.TB) []byte {
	tb.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		tb.Fatal(err)
	}
	return pkcs8DER(tb, priv)
}

func TestAcceptsRealCertificates(t *testing.T) {
	for _, der := range [][]byte{selfSignedRSACertDER(t), selfSignedECCertDER(t)} {
		if !LooksLikeCertificateDER(der) {
			t.Fatalf("real certificate DER rejected")
		}
	}
}

func TestRejectsPrivateKeys(t *testing.T) {
	keys := map[string][]byte{
		"PKCS#1 RSA":     rsaPKCS1DER(t),
		"PKCS#8 RSA":     rsaPKCS8DER(t),
		"PKCS#8 EC":      ecPKCS8DER(t),
		"SEC1 EC":        ecSEC1DER(t),
		"PKCS#8 ed25519": ed25519PKCS8DER(t),
	}
	for name, der := range keys {
		if len(der) == 0 || der[0] != tagSequence {
			t.Fatalf("%s: fixture should start with a SEQUENCE tag to be a meaningful test", name)
		}
		if LooksLikeCertificateDER(der) {
			t.Fatalf("%s: private key DER accepted as certificate", name)
		}
	}
}

func TestRejectsMalformed(t *testing.T) {
	cert := selfSignedRSACertDER(t)
	cases := map[string][]byte{
		"nil":                  nil,
		"empty":                {},
		"not a sequence":       {0x02, 0x01, 0x00},
		"truncated header":     {0x30},
		"truncated length":     {0x30, 0x82, 0x01},
		"length beyond buffer": {0x30, 0x82, 0xff, 0xff, 0x00},
		"indefinite length":    {0x30, 0x80, 0x00, 0x00},
		"non-minimal length":   {0x30, 0x81, 0x01, 0x00},
		"trailing bytes":       append(append([]byte{}, cert...), 0x00),
		"high tag number":      {0x1f, 0x01, 0x00},
		"empty outer sequence": {0x30, 0x00},
	}
	for name, der := range cases {
		if LooksLikeCertificateDER(der) {
			t.Fatalf("%s: malformed input accepted", name)
		}
	}
	if LooksLikeCertificateDER(cert[:len(cert)-1]) {
		t.Fatalf("truncated certificate accepted")
	}
}

func TestNoPanicAndBounded(t *testing.T) {
	// A giant declared length must never trigger a large allocation or panic:
	// the gate only ever reads within the provided slice.
	evil := []byte{0x30, 0x84, 0x7f, 0xff, 0xff, 0xff} // declares ~2 GiB, buffer is 6 bytes
	if LooksLikeCertificateDER(evil) {
		t.Fatalf("oversized declared length accepted")
	}
}

// FuzzLooksLikeCertificateDER asserts the gate never panics or over-allocates
// on arbitrary input, and that anything it accepts at least starts with an
// outer SEQUENCE tag.
func FuzzLooksLikeCertificateDER(f *testing.F) {
	f.Add(selfSignedRSACertDER(f))
	f.Add(rsaPKCS8DER(f))
	f.Add([]byte{0x30, 0x00})
	f.Add([]byte(nil))
	f.Fuzz(func(t *testing.T, der []byte) {
		if LooksLikeCertificateDER(der) && (len(der) == 0 || der[0] != tagSequence) {
			t.Fatalf("accepted a blob that is not an outer SEQUENCE")
		}
	})
}
