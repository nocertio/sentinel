//go:build linux

package filesystem

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"nocert.io/common/pkg/api/sentinel"
)

func TestSearchPaths(t *testing.T) {
	paths := SearchPaths()
	assert.Contains(t, paths, "/etc/letsencrypt/live/")
	assert.Contains(t, paths, "/etc/docker/certs.d/")
	// The system trust store is deliberately NOT walked (public CAs, not the
	// host's own certs) - the sentinel no longer parses to filter them out.
	assert.NotContains(t, paths, "/etc/ssl/certs/")
	assert.NotContains(t, paths, "/etc/pki/tls/certs/")
}

func TestIsExcluded(t *testing.T) {
	assert.True(t, IsExcluded("/etc/ssl/certs/ca-certificates.crt"))
	assert.True(t, IsExcluded("/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem"))
	assert.True(t, IsExcluded("/usr/share/ca-certificates/mozilla/DigiCert.crt"))
	assert.False(t, IsExcluded("/etc/ssl/certs/myapp.crt"))
	assert.False(t, IsExcluded("/etc/letsencrypt/live/example.com/fullchain.pem"))
}

// --- Test helpers ---

func generateCA(t *testing.T) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
		SubjectKeyId:          []byte{1, 2, 3, 4},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	return cert, key
}

func generateLeaf(t *testing.T, ca *x509.Certificate, caKey *ecdsa.PrivateKey) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(2),
		Subject:               pkix.Name{CommonName: "leaf.example.com"},
		DNSNames:              []string{"leaf.example.com"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		BasicConstraintsValid: true,
		AuthorityKeyId:        ca.SubjectKeyId,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca, &key.PublicKey, caKey)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	return cert, key
}

func certToPEM(cert *x509.Certificate) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
}

func TestExtractCertDER_PEMLeafAndCA(t *testing.T) {
	ca, caKey := generateCA(t)
	leaf, _ := generateLeaf(t, ca, caKey)

	// fullchain.pem order (leaf then CA). BOTH are extracted as raw DER - the
	// sentinel ships everything; the backend classifies leaf vs CA.
	data := append(certToPEM(leaf), certToPEM(ca)...)

	ders := extractCertDERForTest(t, data)
	require.Len(t, ders, 2)
	assert.Equal(t, leaf.Raw, ders[0])
	assert.Equal(t, ca.Raw, ders[1])
}

func TestExtractCertDER_OnlyCA(t *testing.T) {
	ca, _ := generateCA(t)

	ders := extractCertDERForTest(t, certToPEM(ca))
	require.Len(t, ders, 1, "a CA is shipped raw; the backend drops it from findings")
	assert.Equal(t, ca.Raw, ders[0])
}

func TestExtractCertDER_DER(t *testing.T) {
	ca, caKey := generateCA(t)
	leaf, _ := generateLeaf(t, ca, caKey)

	ders := extractCertDERForTest(t, leaf.Raw)
	require.Len(t, ders, 1)
	assert.Equal(t, leaf.Raw, ders[0])
}

func TestExtractCertDER_NonCert(t *testing.T) {
	// No X.509 parsing happens, so nothing can panic. Non-cert input yields
	// nothing, and a malformed or non-certificate ASN.1 SEQUENCE is dropped
	// locally by the structural gate rather than shipped for the backend to
	// reject (a private key must never leave the host).
	assert.Nil(t, extractCertDERForTest(t, nil))
	assert.Nil(t, extractCertDERForTest(t, []byte("not a certificate at all")))
	assert.Nil(t, extractCertDERForTest(t, []byte{0x30, 0x82, 0x00, 0x01}), "malformed SEQUENCE is not certificate-shaped")
}

func TestExtractCertDER_RejectsPrivateKeys(t *testing.T) {
	// A private key must never be shipped as a certificate: not as raw key DER
	// carrying a cert extension, nor as key bytes mislabelled inside a
	// CERTIFICATE PEM block.
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	if keyDER[0] != 0x30 {
		t.Fatal("a PKCS#8 key should open with a SEQUENCE tag for this test to be meaningful")
	}
	assert.Nil(t, extractCertDERForTest(t, keyDER), "raw private-key DER must not be extracted")

	disguised := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: keyDER})
	assert.Nil(t, extractCertDERForTest(t, disguised), "a private key disguised in a CERTIFICATE PEM must not be extracted")
}

func TestDiscoverAggregatesByFingerprint(t *testing.T) {
	ca, caKey := generateCA(t)
	leaf, _ := generateLeaf(t, ca, caKey)
	leafPEM := certToPEM(leaf) // []byte

	certDir := t.TempDir()
	etcDir := t.TempDir()
	if err := os.WriteFile(certDir+"/live.pem", leafPEM, 0o644); err != nil {
		t.Fatal(err)
	}
	// Strategy 2: a config file referencing the SAME cert by absolute path.
	if err := os.WriteFile(etcDir+"/app.conf",
		[]byte("ssl_certificate "+certDir+"/live.pem;"), 0o644); err != nil {
		t.Fatal(err)
	}

	res := NewScanner().Discover(context.Background(), []string{certDir}, etcDir)
	if !res.Complete {
		t.Fatal("expected Complete=true")
	}
	if len(res.Certificates) != 1 || len(res.Observations) != 1 {
		t.Fatalf("got %d certs / %d obs, want 1/1", len(res.Certificates), len(res.Observations))
	}
	// Strategy 1 and Strategy 2 resolve to the SAME path -> deduped to one.
	if len(res.Observations[0].FilePaths) != 1 {
		t.Fatalf("expected 1 deduped path, got %v", res.Observations[0].FilePaths)
	}
}

func TestDiscover_FindsCertsInTempDir(t *testing.T) {
	ca, caKey := generateCA(t)
	leaf, _ := generateLeaf(t, ca, caKey)
	data := append(certToPEM(leaf), certToPEM(ca)...)

	dir := t.TempDir()
	certPath := filepath.Join(dir, "fullchain.pem")
	require.NoError(t, os.WriteFile(certPath, data, 0644))

	s := NewScanner()
	result := s.Discover(context.Background(), []string{dir}, t.TempDir())

	require.True(t, result.Complete)
	require.Len(t, result.Certificates, 2, "fullchain ships both the leaf and the CA as raw DER")
	require.Len(t, result.Observations, 2)
	for _, obs := range result.Observations {
		assert.Equal(t, []string{certPath}, obs.FilePaths)
	}
	assert.NotEmpty(t, result.Certificates[0].FingerprintSHA256)
	assert.NotEmpty(t, result.Certificates[0].DER)
}

// TestDiscover_MissingCertDirIsComplete locks the invariant that an absent
// well-known dir (ENOENT) is a normal, COMPLETE "nothing here" - most hosts lack
// any given distro's cert layout. If absence flipped Complete=false, no host with
// a missing dir would ever reconcile.
func TestDiscover_MissingCertDirIsComplete(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "does-not-exist")
	result := NewScanner().Discover(context.Background(), []string{missing}, t.TempDir())
	require.True(t, result.Complete, "a missing cert dir must not mark the sweep incomplete")
}

// TestDiscover_UnreadableSubdirIsIncomplete verifies an EACCES on a subdir marks
// the sweep incomplete, so the backend won't reconcile-delete findings we simply
// could not survey. Guards the silent-deletion path.
func TestDiscover_UnreadableSubdirIsIncomplete(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("permission checks do not apply to root")
	}
	ca, caKey := generateCA(t)
	leaf, _ := generateLeaf(t, ca, caKey)

	dir := t.TempDir()
	sub := filepath.Join(dir, "locked")
	if err := os.Mkdir(sub, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(sub, "leaf.pem"), certToPEM(leaf), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(sub, 0o000); err != nil {
		t.Fatal(err)
	}
	// Restore perms BEFORE t.TempDir's cleanup so RemoveAll can descend.
	t.Cleanup(func() { _ = os.Chmod(sub, 0o755) })

	result := NewScanner().Discover(context.Background(), []string{dir}, t.TempDir())
	assert.False(t, result.Complete, "an unreadable subdir must mark the sweep incomplete")
}

// TestDiscover_UnreadableCertFileIsIncomplete covers the per-file read path: an
// EACCES/EIO on a cert file (not the dir) must also mark the sweep incomplete.
func TestDiscover_UnreadableCertFileIsIncomplete(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("permission checks do not apply to root")
	}
	ca, caKey := generateCA(t)
	leaf, _ := generateLeaf(t, ca, caKey)

	dir := t.TempDir()
	p := filepath.Join(dir, "leaf.pem")
	if err := os.WriteFile(p, certToPEM(leaf), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(p, 0o000); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(p, 0o644) })

	result := NewScanner().Discover(context.Background(), []string{dir}, t.TempDir())
	assert.False(t, result.Complete, "an unreadable cert file must mark the sweep incomplete")
}

// TestDiscover_SkipsExcludedPaths verifies that IsExcluded paths are skipped
// and that non-cert extensions (.key, .csr) are not parsed.
func TestDiscover_SkipsExcludedPaths(t *testing.T) {
	ca, caKey := generateCA(t)
	leaf, _ := generateLeaf(t, ca, caKey)

	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "myapp.crt"), certToPEM(leaf), 0644))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "myapp.key"), []byte("private key data"), 0600))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "request.csr"), []byte("csr data"), 0644))

	s := NewScanner()
	result := s.Discover(context.Background(), []string{dir}, t.TempDir())

	// Only myapp.crt is a cert extension; .key and .csr are ignored.
	require.Len(t, result.Observations, 1, "should only find .crt, not .key or .csr")
}

// TestDiscover_SkipsZeroAndOversizedFiles verifies that zero-byte and too-large
// files are skipped entirely.
func TestDiscover_SkipsZeroAndOversizedFiles(t *testing.T) {
	dir := t.TempDir()
	// Create a file larger than maxFileSize
	large := make([]byte, maxFileSize+1)
	require.NoError(t, os.WriteFile(filepath.Join(dir, "huge.pem"), large, 0644))
	// Create a zero-byte file
	require.NoError(t, os.WriteFile(filepath.Join(dir, "empty.pem"), []byte{}, 0644))

	s := NewScanner()
	result := s.Discover(context.Background(), []string{dir}, t.TempDir())

	assert.Empty(t, result.Observations, "oversized and zero-byte files must be skipped")
	assert.False(t, result.Complete)
}

// TestDiscover_ContextCancellation verifies that a pre-cancelled context results
// in Complete=false and no observations.
func TestDiscover_ContextCancellation(t *testing.T) {
	dir := t.TempDir()
	ca, caKey := generateCA(t)
	leaf, _ := generateLeaf(t, ca, caKey)

	for i := range 5 {
		require.NoError(t, os.WriteFile(filepath.Join(dir, fmt.Sprintf("cert%d.pem", i)), certToPEM(leaf), 0644))
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel immediately

	s := NewScanner()
	result := s.Discover(ctx, []string{dir}, t.TempDir())

	assert.False(t, result.Complete, "cancelled sweep must not be marked complete")
	assert.Empty(t, result.Observations, "should not scan any files when context is cancelled")
}

// TestDiscover_MaxDepth verifies that files beyond maxDepth are skipped.
func TestDiscover_MaxDepth(t *testing.T) {
	ca, caKey := generateCA(t)
	leaf, _ := generateLeaf(t, ca, caKey)

	dir := t.TempDir()
	// Create a deeply nested file beyond maxDepth
	deep := dir
	for range maxDepth + 2 {
		deep = filepath.Join(deep, "sub")
	}
	require.NoError(t, os.MkdirAll(deep, 0755))
	require.NoError(t, os.WriteFile(filepath.Join(deep, "deep.pem"), certToPEM(leaf), 0644))

	s := NewScanner()
	result := s.Discover(context.Background(), []string{dir}, t.TempDir())

	assert.Empty(t, result.Observations, "should not descend beyond maxDepth")
	assert.False(t, result.Complete)
}

// TestDiscover_SymlinkLoop verifies that symlink loops do not hang the scanner.
func TestDiscover_SymlinkLoop(t *testing.T) {
	ca, caKey := generateCA(t)
	leaf, _ := generateLeaf(t, ca, caKey)

	dir := t.TempDir()
	sub := filepath.Join(dir, "real")
	require.NoError(t, os.MkdirAll(sub, 0755))
	require.NoError(t, os.WriteFile(filepath.Join(sub, "leaf.pem"), certToPEM(leaf), 0644))
	// Create a symlink loop: real/loop -> real
	require.NoError(t, os.Symlink(sub, filepath.Join(sub, "loop")))

	s := NewScanner()
	// Must complete without hanging.
	result := s.Discover(context.Background(), []string{dir}, t.TempDir())

	// The real cert is found; the loop is skipped.
	require.Len(t, result.Observations, 1)
}

// TestDiscover_DERFile verifies that single-DER cert files are parsed correctly.
func TestDiscover_DERFile(t *testing.T) {
	ca, caKey := generateCA(t)
	leaf, _ := generateLeaf(t, ca, caKey)

	dir := t.TempDir()
	// Write raw DER (not PEM) with a .der extension
	require.NoError(t, os.WriteFile(filepath.Join(dir, "leaf.der"), leaf.Raw, 0644))

	s := NewScanner()
	result := s.Discover(context.Background(), []string{dir}, t.TempDir())

	require.Len(t, result.Certificates, 1)
	require.Len(t, result.Observations, 1)
	_ = caKey // referenced to satisfy the compiler
}

// TestDiscover_SameCertTwoFilesAggregated verifies that the same cert found in
// two different files produces one observation with two FilePaths.
func TestDiscover_SameCertTwoFilesAggregated(t *testing.T) {
	ca, caKey := generateCA(t)
	leaf, _ := generateLeaf(t, ca, caKey)
	pemData := certToPEM(leaf)

	dir := t.TempDir()
	pathA := filepath.Join(dir, "a.pem")
	pathB := filepath.Join(dir, "b.pem")
	require.NoError(t, os.WriteFile(pathA, pemData, 0644))
	require.NoError(t, os.WriteFile(pathB, pemData, 0644))

	s := NewScanner()
	result := s.Discover(context.Background(), []string{dir}, t.TempDir())

	require.Len(t, result.Certificates, 1, "same cert fingerprint must be deduplicated")
	require.Len(t, result.Observations, 1)
	assert.Len(t, result.Observations[0].FilePaths, 2, "both file paths must appear in one observation")
}

// TestDiscover_InsecurePrivateKeyWarning verifies that an insecure sibling key
// triggers the expected warning on the observation.
func TestDiscover_InsecurePrivateKeyWarning(t *testing.T) {
	ca, caKey := generateCA(t)
	leaf, _ := generateLeaf(t, ca, caKey)

	dir := t.TempDir()
	certPath := filepath.Join(dir, "myapp.crt")
	keyPath := filepath.Join(dir, "myapp.key")
	require.NoError(t, os.WriteFile(certPath, certToPEM(leaf), 0o644))
	// Sibling key with insecure permissions (group/world readable).
	require.NoError(t, os.WriteFile(keyPath, []byte("KEY"), 0o644))

	s := NewScanner()
	result := s.Discover(context.Background(), []string{dir}, t.TempDir())

	require.Len(t, result.Observations, 1)
	assert.Contains(t, result.Observations[0].Warnings, sentinel.FilesystemWarningInsecurePrivateKeyPermissions)
}

// TestDiscover_NoInsecurePrivateKeyWarningWhenSecure verifies that a secure
// sibling key (mode 0o600) does not produce a warning.
func TestDiscover_NoInsecurePrivateKeyWarningWhenSecure(t *testing.T) {
	ca, caKey := generateCA(t)
	leaf, _ := generateLeaf(t, ca, caKey)

	dir := t.TempDir()
	certPath := filepath.Join(dir, "myapp.crt")
	keyPath := filepath.Join(dir, "myapp.key")
	require.NoError(t, os.WriteFile(certPath, certToPEM(leaf), 0o644))
	require.NoError(t, os.WriteFile(keyPath, []byte("KEY"), 0o600))

	s := NewScanner()
	result := s.Discover(context.Background(), []string{dir}, t.TempDir())

	require.Len(t, result.Observations, 1)
	assert.Empty(t, result.Observations[0].Warnings)
}

// fsDERTLV/fsBigShapedCert build a large, certshape-valid DER blob (a real cert
// would need a huge extension; this is simpler and deterministic). The label is
// embedded so distinct labels yield distinct fingerprints.
func fsDERLen(n int) []byte {
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

func fsDERTLV(tag byte, content []byte) []byte {
	return append(append([]byte{tag}, fsDERLen(len(content))...), content...)
}

func fsBigShapedCert(label string, size int) []byte {
	pad := make([]byte, size)
	copy(pad, label)
	tbs := fsDERTLV(0x30, pad)
	sigAlg := fsDERTLV(0x30, nil)
	sig := fsDERTLV(0x03, []byte{0x00})
	body := append(append(tbs, sigAlg...), sig...)
	return fsDERTLV(0x30, body)
}

func TestDiscoverBoundsCumulativeDERBytes(t *testing.T) {
	certDir := t.TempDir()
	// Individually valid sizes whose combined DER exceeds the sweep budget.
	const per = 60 * 1024
	for i := 0; i < 40; i++ {
		der := fsBigShapedCert(fmt.Sprintf("big-%d", i), per)
		if err := os.WriteFile(filepath.Join(certDir, fmt.Sprintf("c%d.der", i)), der, 0o644); err != nil {
			t.Fatal(err)
		}
	}

	res := NewScanner().Discover(context.Background(), []string{certDir}, t.TempDir())

	if !res.Truncated {
		t.Fatal("expected Truncated=true once the DER byte cap is hit")
	}
	if res.Complete {
		t.Fatal("a byte-capped sweep must report Complete=false (no reconciliation)")
	}
	total := 0
	for _, c := range res.Certificates {
		total += len(c.DER)
	}
	if total > maxCertBytesPerSweep {
		t.Fatalf("retained DER %d exceeds the byte cap %d", total, maxCertBytesPerSweep)
	}
	if len(res.Certificates) == 0 {
		t.Fatal("some certs should be retained before the cap trips")
	}
}

func TestDiscoverBoundsCumulativePathBytes(t *testing.T) {
	certDir := t.TempDir()
	// One small cert copied into many files with long names: a single
	// fingerprint whose observation accumulates thousands of paths. Enough
	// (path length x count) to exceed the 1.5 MiB path cap while staying well
	// under the file-count and fingerprint caps.
	der := fsBigShapedCert("x", 32)
	n := (maxPathBytesPerSweep / 260) + 500 // each path ~260+ bytes
	for i := 0; i < n; i++ {
		name := fmt.Sprintf("%0250d.der", i) // 254-char filename
		if err := os.WriteFile(filepath.Join(certDir, name), der, 0o644); err != nil {
			t.Fatal(err)
		}
	}

	res := NewScanner().Discover(context.Background(), []string{certDir}, t.TempDir())

	if !res.Truncated {
		t.Fatal("expected Truncated=true once the path byte cap is hit")
	}
	if res.Complete {
		t.Fatal("a path-capped sweep must report Complete=false")
	}
	pathBytes := 0
	for _, o := range res.Observations {
		for _, p := range o.FilePaths {
			pathBytes += len(p)
		}
	}
	if pathBytes > maxPathBytesPerSweep {
		t.Fatalf("retained path bytes %d exceed the cap %d", pathBytes, maxPathBytesPerSweep)
	}
	if pathBytes == 0 {
		t.Fatal("some paths should be retained before the cap trips")
	}
}

func extractCertDERForTest(t *testing.T, data []byte) [][]byte {
	t.Helper()
	ders, complete := extractCertDER(data)
	require.True(t, complete)
	return ders
}
