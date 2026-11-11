// Package testutil builds disposable certificates for discovery tests.
package testutil

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"net"
	"testing"
	"time"
)

type CertificateCase struct {
	Name        string
	Certificate tls.Certificate
	Parseable   bool
}

// Certificate generates a self-signed leaf. No private keys are kept on disk.
func Certificate(t testing.TB, configure func(*x509.Certificate)) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "fixture.invalid"},
		DNSNames:              []string{"fixture.invalid"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().AddDate(8, 0, 0),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	if configure != nil {
		configure(template)
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}
}

func UnusualCertificates(t testing.TB) []CertificateCase {
	t.Helper()
	var cases []CertificateCase
	for _, tc := range []struct {
		name      string
		configure func(*x509.Certificate)
	}{
		{"self_signed_eight_years", nil},
		{"year_9999", func(c *x509.Certificate) { c.NotAfter = time.Date(9999, 12, 31, 23, 59, 59, 0, time.UTC) }},
		{"cn_only", func(c *x509.Certificate) { c.DNSNames = nil }},
		{"ip_san", func(c *x509.Certificate) {
			c.DNSNames = nil
			c.IPAddresses = []net.IP{net.ParseIP("192.0.2.1"), net.ParseIP("2001:db8::1")}
		}},
		{"unicode_name", func(c *x509.Certificate) { c.Subject.CommonName = "équipement.invalid" }},
		{"missing_issuer", func(c *x509.Certificate) { c.AuthorityKeyId = []byte{1, 2, 3}; c.SubjectKeyId = []byte{4, 5, 6} }},
	} {
		cert := Certificate(t, tc.configure)
		if tc.name == "missing_issuer" {
			ca := Certificate(t, func(c *x509.Certificate) {
				c.IsCA = true
				c.KeyUsage = x509.KeyUsageCertSign
				c.Subject.CommonName = "Missing CA"
			})
			der, err := x509.CreateCertificate(rand.Reader, cert.Leaf, ca.Leaf, cert.PrivateKey.(*ecdsa.PrivateKey).Public(), ca.PrivateKey)
			if err != nil {
				t.Fatal(err)
			}
			cert.Certificate[0] = der
			cert.Leaf, err = x509.ParseCertificate(der)
			if err != nil {
				t.Fatal(err)
			}
			if err := cert.Leaf.CheckSignatureFrom(ca.Leaf); err != nil {
				t.Fatal(err)
			}
		}
		cases = append(cases, CertificateCase{tc.name, cert, true})
	}
	invalidName := marshal(t, pkix.RDNSequence{{{Type: asn1.ObjectIdentifier{2, 5, 4, 3}, Value: asn1.RawValue{Tag: asn1.TagUTF8String, Bytes: []byte{'x', 0xff}}}}})
	for _, tc := range []struct {
		name  string
		field int
		value []byte
	}{
		{"negative_serial", 1, []byte{2, 1, 0x80}},
		{"nonminimal_serial", 1, []byte{2, 2, 0, 1}},
		{"invalid_utf8_name", 5, invalidName},
	} {
		cert := Certificate(t, nil)
		// Leaf keeps the valid public key so a test TLS server can send the
		// malformed DER without parsing it itself.
		cert.Certificate[0] = replaceTBSField(t, cert.Certificate[0], tc.field, tc.value)
		cases = append(cases, CertificateCase{tc.name, cert, false})
	}
	return cases
}

func marshal(t testing.TB, value any) []byte {
	t.Helper()
	b, err := asn1.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func replaceTBSField(t testing.TB, der []byte, index int, replacement []byte) []byte {
	t.Helper()
	var outer, tbs asn1.RawValue
	if rest, err := asn1.Unmarshal(der, &outer); err != nil || len(rest) != 0 {
		t.Fatalf("certificate fixture: %v", err)
	}
	tail, err := asn1.Unmarshal(outer.Bytes, &tbs)
	if err != nil {
		t.Fatal(err)
	}
	var fields []byte
	for i, rest := 0, tbs.Bytes; len(rest) > 0; i++ {
		var field asn1.RawValue
		rest, err = asn1.Unmarshal(rest, &field)
		if err != nil {
			t.Fatal(err)
		}
		if i == index {
			fields = append(fields, replacement...)
		} else {
			fields = append(fields, field.FullBytes...)
		}
	}
	sequence := func(b []byte) []byte {
		return marshal(t, asn1.RawValue{Tag: asn1.TagSequence, IsCompound: true, Bytes: b})
	}
	return sequence(append(sequence(fields), tail...))
}
