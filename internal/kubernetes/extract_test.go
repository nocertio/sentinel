package kubernetes

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// shapedCert builds a minimal DER blob that passes the certshape gate
// (SEQUENCE{SEQUENCE, SEQUENCE, BIT STRING}) and embeds label so distinct
// labels yield distinct bytes while equal labels yield equal bytes (dedup and
// fingerprint tests rely on both). It is NOT a real certificate: these tests
// exercise extraction and sweep logic, not X.509 parsing (which lives in the
// backend). The label sits only in the tbsCertificate, so the DER size tracks
// len(label) - the byte-budget test depends on that.
func shapedCert(label string) []byte {
	tbs := derTLV(0x30, []byte(label)) // tbsCertificate SEQUENCE carrying the label
	sigAlg := derTLV(0x30, nil)        // signatureAlgorithm: empty SEQUENCE
	sig := derTLV(0x03, []byte{0x00})  // signatureValue: BIT STRING, 0 unused bits
	body := append(append(tbs, sigAlg...), sig...)
	return derTLV(0x30, body)
}

// derTLV encodes one definite-length DER TLV with a minimal length.
func derTLV(tag byte, content []byte) []byte {
	return append(append([]byte{tag}, derLen(len(content))...), content...)
}

func derLen(n int) []byte {
	if n < 0x80 {
		return []byte{byte(n)}
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte(n & 0xff)}, b...)
		n >>= 8
	}
	return append([]byte{byte(0x80 | len(b))}, b...)
}

// pemCert wraps a shaped cert in a CERTIFICATE PEM block for tests.
func pemCert(label string) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: shapedCert(label)})
}

func TestExtractPublicMaterialNeverReadsPrivateKeys(t *testing.T) {
	data := map[string][]byte{
		"tls.crt": pemCert("LEAF"),
		"ca.crt":  pemCert("CA"),
		"tls.key": []byte("-----BEGIN PRIVATE KEY-----\nSECRET\n-----END PRIVATE KEY-----\n"),
		"extra":   []byte("password123"),
	}
	got := extractPublicMaterial(data, tlsSecretPublicKeys)
	require.Len(t, got, 2)
	for _, ec := range got {
		assert.NotEqual(t, "tls.key", ec.dataKey)
		assert.NotContains(t, string(ec.der), "SECRET")
	}
}

func TestExtractPublicMaterialFullchainOrderPreserved(t *testing.T) {
	full := append(pemCert("LEAF"), pemCert("INTERMEDIATE")...)
	got := extractPublicMaterial(map[string][]byte{"tls.crt": full}, []string{"tls.crt"})
	require.Len(t, got, 2)
	assert.Equal(t, shapedCert("LEAF"), got[0].der)
	assert.Equal(t, shapedCert("INTERMEDIATE"), got[1].der)
}

func TestExtractPublicMaterialSkipsOversizedAndNonCert(t *testing.T) {
	// Shape-valid but over the 64 KiB wire cap -> dropped by the size guard.
	oversized := shapedCert(strings.Repeat("A", 65*1024))
	require.Greater(t, len(oversized), maxDERBytes)
	got := extractPublicMaterial(map[string][]byte{
		"tls.crt": oversized,
		"ca.crt":  []byte("not a certificate at all"),
	}, tlsSecretPublicKeys)
	assert.Empty(t, got)
}

func TestExtractPublicMaterialRejectsPrivateKeyMaterial(t *testing.T) {
	// A private key must never be forwarded as a certificate, whether it is a
	// raw key DER placed under tls.crt or key bytes mislabelled inside a
	// CERTIFICATE PEM block. The backend is the sole parser; this
	// gate keeps key material from ever reaching it.
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	require.NoError(t, err)
	require.Equal(t, byte(0x30), keyDER[0], "a PKCS#8 key opens with a SEQUENCE tag")

	rawKey := extractPublicMaterial(map[string][]byte{"tls.crt": keyDER}, tlsSecretPublicKeys)
	assert.Empty(t, rawKey, "raw private-key DER under tls.crt must not be extracted")

	disguised := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: keyDER})
	disguisedGot := extractPublicMaterial(map[string][]byte{"ca.crt": disguised}, tlsSecretPublicKeys)
	assert.Empty(t, disguisedGot, "a private key disguised in a CERTIFICATE PEM must not be extracted")

	// Control: a real (shape-valid) certificate alongside is still extracted,
	// proving the gate is discriminating, not rejecting everything.
	ok := extractPublicMaterial(map[string][]byte{"tls.crt": pemCert("REAL")}, tlsSecretPublicKeys)
	require.Len(t, ok, 1)
}

func TestExtractPublicMaterialCapsCertsAtWireLimit(t *testing.T) {
	// A hostile Secret packing many CERTIFICATE blocks into one data key must not
	// exceed observed_chain_fingerprints maxItems (16) in the wire contract.
	var full []byte
	for i := 0; i < 40; i++ {
		full = append(full, pemCert(fmt.Sprintf("C%d", i))...)
	}
	got := extractPublicMaterial(map[string][]byte{"tls.crt": full}, []string{"tls.crt"})
	assert.Equal(t, 16, maxCertsPerValue)
	assert.Len(t, got, maxCertsPerValue)
}

func TestWellKnownTargetsNeverAllowlistKeyMaterial(t *testing.T) {
	for _, target := range wellKnownTargets {
		for _, k := range target.Keys {
			assert.NotContains(t, strings.ToLower(k), "key", "allowlist %s/%s must never include a private-key data key", target.Namespace, target.Name)
		}
	}
}
