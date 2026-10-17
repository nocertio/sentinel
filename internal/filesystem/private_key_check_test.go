//go:build linux

package filesystem

import (
	"os"
	"path/filepath"
	"testing"
)

func TestCheckSiblingPrivateKey_NoSibling(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "example.com.crt")
	if err := os.WriteFile(certPath, []byte("CERT"), 0o644); err != nil {
		t.Fatal(err)
	}
	insecure, err := CheckSiblingPrivateKey(certPath)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if insecure {
		t.Errorf("expected no warning when no sibling key exists")
	}
}

func TestCheckSiblingPrivateKey_EncryptedPEM(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "server.pem")
	if err := os.WriteFile(path, []byte("-----BEGIN ENCRYPTED PRIVATE KEY-----\n"), 0644); err != nil {
		t.Fatal(err)
	}
	insecure, err := CheckSiblingPrivateKey(filepath.Join(dir, "server.crt"))
	if err != nil || !insecure {
		t.Fatalf("insecure=%v, err=%v", insecure, err)
	}
}

func TestCheckSiblingPrivateKey_SecureSiblingKey(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "example.com.crt")
	keyPath := filepath.Join(dir, "example.com.key")
	if err := os.WriteFile(certPath, []byte("CERT"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, []byte("KEY"), 0o600); err != nil {
		t.Fatal(err)
	}
	insecure, err := CheckSiblingPrivateKey(certPath)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if insecure {
		t.Errorf("expected no warning for 0600 key, got insecure=true")
	}
}

func TestCheckSiblingPrivateKey_InsecureSiblingKey(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "example.com.crt")
	keyPath := filepath.Join(dir, "example.com.key")
	if err := os.WriteFile(certPath, []byte("CERT"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, []byte("KEY"), 0o644); err != nil {
		t.Fatal(err)
	}
	insecure, err := CheckSiblingPrivateKey(certPath)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if !insecure {
		t.Errorf("expected insecure=true for 0644 .key file")
	}
}

func TestCheckSiblingPrivateKey_GroupReadableKey(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "example.com.crt")
	keyPath := filepath.Join(dir, "example.com.key")
	if err := os.WriteFile(certPath, []byte("CERT"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, []byte("KEY"), 0o640); err != nil {
		t.Fatal(err)
	}
	insecure, err := CheckSiblingPrivateKey(certPath)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if !insecure {
		t.Errorf("expected insecure=true for 0640 .key file (group-readable)")
	}
}

func TestCheckSiblingPrivateKey_PrivateSubdirKey(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "example.com.crt")
	if err := os.MkdirAll(filepath.Join(dir, "private"), 0o755); err != nil {
		t.Fatal(err)
	}
	keyPath := filepath.Join(dir, "private", "example.com.key")
	if err := os.WriteFile(certPath, []byte("CERT"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, []byte("KEY"), 0o644); err != nil {
		t.Fatal(err)
	}
	insecure, err := CheckSiblingPrivateKey(certPath)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if !insecure {
		t.Errorf("expected insecure=true for 0644 key in private/ subdir")
	}
}

func TestCheckSiblingPrivateKey_PEMWithKeyMarker(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "example.com.crt")
	pemPath := filepath.Join(dir, "example.com.pem")
	if err := os.WriteFile(certPath, []byte("CERT"), 0o644); err != nil {
		t.Fatal(err)
	}
	pemContent := "-----BEGIN PRIVATE KEY-----\nABCD\n-----END PRIVATE KEY-----"
	if err := os.WriteFile(pemPath, []byte(pemContent), 0o644); err != nil {
		t.Fatal(err)
	}
	insecure, err := CheckSiblingPrivateKey(certPath)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if !insecure {
		t.Errorf("expected insecure=true for 0644 .pem with PRIVATE KEY marker")
	}
}

func TestCheckSiblingPrivateKey_PEMWithoutKeyMarker(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "example.com.crt")
	pemPath := filepath.Join(dir, "example.com.pem")
	if err := os.WriteFile(certPath, []byte("CERT"), 0o644); err != nil {
		t.Fatal(err)
	}
	pemContent := "-----BEGIN CERTIFICATE-----\nABCD\n-----END CERTIFICATE-----"
	if err := os.WriteFile(pemPath, []byte(pemContent), 0o644); err != nil {
		t.Fatal(err)
	}
	insecure, err := CheckSiblingPrivateKey(certPath)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if insecure {
		t.Errorf("expected no warning for cert-only .pem")
	}
}
