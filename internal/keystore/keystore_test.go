package keystore

import (
	"crypto/ed25519"
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestGenerateKeyPair(t *testing.T) {
	privB64, pubB64, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}

	seed, err := base64.StdEncoding.DecodeString(privB64)
	if err != nil {
		t.Fatalf("decode private key: %v", err)
	}
	if len(seed) != ed25519.SeedSize {
		t.Fatalf("seed size = %d, want %d", len(seed), ed25519.SeedSize)
	}

	pub, err := base64.StdEncoding.DecodeString(pubB64)
	if err != nil {
		t.Fatalf("decode public key: %v", err)
	}
	if len(pub) != ed25519.PublicKeySize {
		t.Fatalf("public key size = %d, want %d", len(pub), ed25519.PublicKeySize)
	}

	// Verify the key pair is consistent.
	priv := ed25519.NewKeyFromSeed(seed)
	msg := []byte("test message")
	sig := ed25519.Sign(priv, msg)
	if !ed25519.Verify(ed25519.PublicKey(pub), msg, sig) {
		t.Fatal("generated key pair is inconsistent")
	}
}

func TestStoreRoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sentinel-key.json")
	store := NewStore(path)

	if store.Exists() {
		t.Fatal("store should not exist yet")
	}

	privB64, pubB64, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}

	kf := &KeyFile{
		SentinelID:       "test-sentinel-id",
		KeyID:            "abcdef1234567890abcdef1234567890",
		PrivateKey:       privB64,
		PublicKey:        pubB64,
		KeyExpiresAt:     time.Now().Add(30 * 24 * time.Hour),
		SigningPublicKey: pubB64, // reuse for test
	}

	if err := store.Save(kf); err != nil {
		t.Fatalf("Save: %v", err)
	}

	if !store.Exists() {
		t.Fatal("store should exist after save")
	}

	// Check file permissions.
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0600 {
		t.Fatalf("file permissions = %o, want 0600", perm)
	}

	loaded, err := store.Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	if loaded.SentinelID != kf.SentinelID {
		t.Errorf("SentinelID = %q, want %q", loaded.SentinelID, kf.SentinelID)
	}
	if loaded.KeyID != kf.KeyID {
		t.Errorf("KeyID = %q, want %q", loaded.KeyID, kf.KeyID)
	}
	if loaded.PrivateKey != kf.PrivateKey {
		t.Error("PrivateKey mismatch")
	}
	if loaded.PublicKey != kf.PublicKey {
		t.Error("PublicKey mismatch")
	}
	if loaded.SigningPublicKey != kf.SigningPublicKey {
		t.Error("SigningPublicKey mismatch")
	}
}

func TestAtomicWrite(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sentinel-key.json")
	store := NewStore(path)

	privB64, pubB64, _ := GenerateKeyPair()
	kf := &KeyFile{
		SentinelID:   "sentinel-1",
		KeyID:        "key-1",
		PrivateKey:   privB64,
		PublicKey:    pubB64,
		KeyExpiresAt: time.Now().Add(30 * 24 * time.Hour),
	}

	if err := store.Save(kf); err != nil {
		t.Fatalf("first Save: %v", err)
	}

	// Overwrite with new data.
	kf.SentinelID = "sentinel-2"
	if err := store.Save(kf); err != nil {
		t.Fatalf("second Save: %v", err)
	}

	loaded, err := store.Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if loaded.SentinelID != "sentinel-2" {
		t.Errorf("SentinelID = %q, want %q", loaded.SentinelID, "sentinel-2")
	}

	// No .tmp file should remain.
	tmp := path + ".tmp"
	if _, err := os.Stat(tmp); err == nil {
		t.Error("temporary file should not exist after successful save")
	}
}

func TestNeedsRotation(t *testing.T) {
	tests := []struct {
		name     string
		expiry   time.Duration
		expected bool
	}{
		{"expires in 30 days", 30 * 24 * time.Hour, false},
		{"expires in 6 days", 6 * 24 * time.Hour, false},
		{"expires in 4 days", 4 * 24 * time.Hour, true},
		{"expires in 1 day", 24 * time.Hour, true},
		{"already expired", -1 * time.Hour, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			kf := &KeyFile{
				KeyExpiresAt: time.Now().Add(tt.expiry),
			}
			margin := 5 * 24 * time.Hour
			if got := kf.NeedsRotation(margin); got != tt.expected {
				t.Errorf("NeedsRotation(%v) = %v, want %v", margin, got, tt.expected)
			}
		})
	}
}

func TestLoadCorrupt(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sentinel-key.json")

	cases := []struct {
		name string
		data string
	}{
		{"garbage", "this is not json"},
		{"truncated", `{"sentinel_id":"x","private_key":"AAA`},
		{"empty", ""},
		{"wrong type", `{"key_expires_at":12345}`},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if err := os.WriteFile(path, []byte(c.data), 0600); err != nil {
				t.Fatalf("write: %v", err)
			}
			store := NewStore(path)
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("Load panicked: %v", r)
				}
			}()
			if _, err := store.Load(); err == nil {
				t.Fatal("expected error loading corrupt key file")
			}
		})
	}
}

func TestSavePreservesPerms(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sentinel-key.json")

	// Pre-create the file with lax perms; Save must land on 0600 regardless.
	if err := os.WriteFile(path, []byte("stale"), 0644); err != nil {
		t.Fatalf("pre-create: %v", err)
	}
	if err := os.Chmod(dir, 0777); err != nil {
		t.Fatalf("chmod dir: %v", err)
	}

	privB64, pubB64, _ := GenerateKeyPair()
	kf := &KeyFile{
		SentinelID:   "sentinel-1",
		PrivateKey:   privB64,
		PublicKey:    pubB64,
		KeyExpiresAt: time.Now().Add(30 * 24 * time.Hour),
	}
	store := NewStore(path)
	if err := store.Save(kf); err != nil {
		t.Fatalf("Save: %v", err)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat file: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0600 {
		t.Fatalf("file perms = %o, want 0600", perm)
	}

	dinfo, err := os.Stat(dir)
	if err != nil {
		t.Fatalf("stat dir: %v", err)
	}
	if perm := dinfo.Mode().Perm(); perm != 0700 {
		t.Fatalf("dir perms = %o, want 0700", perm)
	}
}

func TestNeedsRotationBoundary(t *testing.T) {
	margin := 5 * 24 * time.Hour

	// NeedsRotation uses a strict "<": remaining life at or beyond the margin
	// must NOT rotate; strictly inside must. time.Until == margin exactly is
	// unhittable with a wall-clock expiry, so pin the two sides of the edge.
	beyond := &KeyFile{KeyExpiresAt: time.Now().Add(margin + time.Second)}
	if beyond.NeedsRotation(margin) {
		t.Error("key just beyond margin should not need rotation")
	}
	inside := &KeyFile{KeyExpiresAt: time.Now().Add(margin - time.Second)}
	if !inside.NeedsRotation(margin) {
		t.Error("key just inside margin should need rotation")
	}
}

func TestSaveLoadErrorNeverLeaksKey(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sentinel-key.json")
	store := NewStore(path)

	privB64, pubB64, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	kf := &KeyFile{
		SentinelID:   "sentinel-1",
		PrivateKey:   privB64,
		PublicKey:    pubB64,
		KeyExpiresAt: time.Now().Add(30 * 24 * time.Hour),
	}

	assertNoKey := func(err error) {
		if err == nil {
			return
		}
		if strings.Contains(err.Error(), privB64) {
			t.Fatalf("error string leaks private key material: %v", err)
		}
		rawSeed, _ := base64.StdEncoding.DecodeString(privB64)
		if len(rawSeed) > 0 && strings.Contains(err.Error(), string(rawSeed)) {
			t.Fatalf("error string leaks raw seed bytes: %v", err)
		}
	}

	// Force Save failure: a file where MkdirAll expects a directory.
	fileAsDir := filepath.Join(dir, "notadir")
	if err := os.WriteFile(fileAsDir, []byte("x"), 0600); err != nil {
		t.Fatalf("write blocker: %v", err)
	}
	badStore := NewStore(filepath.Join(fileAsDir, "key.json"))
	assertNoKey(badStore.Save(kf))

	// Force Load failure on corrupt content.
	if err := os.WriteFile(path, []byte(`{"private_key":`+privB64), 0600); err != nil {
		t.Fatalf("write corrupt: %v", err)
	}
	_, loadErr := store.Load()
	assertNoKey(loadErr)

	// Decode failures must not echo the key either.
	bad := &KeyFile{PrivateKey: privB64 + "!!!not-base64"}
	_, decErr := bad.PrivateKeyBytes()
	assertNoKey(decErr)
}

func TestKeyFileDecodeKeys(t *testing.T) {
	privB64, pubB64, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}

	kf := &KeyFile{
		PrivateKey:       privB64,
		PublicKey:        pubB64,
		SigningPublicKey: pubB64,
	}

	priv, err := kf.PrivateKeyBytes()
	if err != nil {
		t.Fatalf("PrivateKeyBytes: %v", err)
	}

	pub, err := kf.PublicKeyBytes()
	if err != nil {
		t.Fatalf("PublicKeyBytes: %v", err)
	}

	serverPub, err := kf.SigningPublicKeyBytes()
	if err != nil {
		t.Fatalf("SigningPublicKeyBytes: %v", err)
	}

	// Sign and verify round-trip.
	msg := []byte("hello")
	sig := ed25519.Sign(priv, msg)
	if !ed25519.Verify(pub, msg, sig) {
		t.Fatal("sign/verify failed with decoded keys")
	}
	if !ed25519.Verify(serverPub, msg, sig) {
		t.Fatal("server public key decode mismatch")
	}
}

func TestKeyFile_MachineIDRoundTrip(t *testing.T) {
	dir := t.TempDir()
	st := NewStore(filepath.Join(dir, "k.json"))
	kf := &KeyFile{SentinelID: "s1", MachineID: "abc"}
	if err := st.Save(kf); err != nil {
		t.Fatal(err)
	}
	got, err := st.Load()
	if err != nil {
		t.Fatal(err)
	}
	if got.MachineID != "abc" {
		t.Fatalf("machine_id lost: %q", got.MachineID)
	}
}

func TestKeyFileDecodeInvalid(t *testing.T) {
	kf := &KeyFile{
		PrivateKey:       "not-valid-base64!!!",
		PublicKey:        "not-valid-base64!!!",
		SigningPublicKey: "not-valid-base64!!!",
	}

	if _, err := kf.PrivateKeyBytes(); err == nil {
		t.Error("expected error for invalid private key")
	}
	if _, err := kf.PublicKeyBytes(); err == nil {
		t.Error("expected error for invalid public key")
	}
	if _, err := kf.SigningPublicKeyBytes(); err == nil {
		t.Error("expected error for invalid server public key")
	}

	// Valid base64 but wrong size.
	kf.PrivateKey = base64.StdEncoding.EncodeToString([]byte("too-short"))
	kf.PublicKey = base64.StdEncoding.EncodeToString([]byte("too-short"))
	kf.SigningPublicKey = base64.StdEncoding.EncodeToString([]byte("too-short"))

	if _, err := kf.PrivateKeyBytes(); err == nil {
		t.Error("expected error for wrong-size private key")
	}
	if _, err := kf.PublicKeyBytes(); err == nil {
		t.Error("expected error for wrong-size public key")
	}
	if _, err := kf.SigningPublicKeyBytes(); err == nil {
		t.Error("expected error for wrong-size server public key")
	}
}

func testKeyFile(t *testing.T) *KeyFile {
	t.Helper()
	privB64, pubB64, err := GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	return &KeyFile{
		SentinelID:   "sentinel-x",
		KeyID:        "key-x",
		PrivateKey:   privB64,
		PublicKey:    pubB64,
		KeyExpiresAt: time.Now().Add(30 * 24 * time.Hour),
	}
}

// TestSaveIgnoresPrePlantedTmpSymlink pins the temp-file guard: a compromised
// account that owns the key directory plants "<path>.tmp" as a symlink to an
// external file. Save must not write the new private key through that link.
func TestSaveIgnoresPrePlantedTmpSymlink(t *testing.T) {
	dir := t.TempDir()
	victimDir := t.TempDir()
	victim := filepath.Join(victimDir, "victim")
	if err := os.WriteFile(victim, []byte("ORIGINAL"), 0o644); err != nil {
		t.Fatal(err)
	}

	path := filepath.Join(dir, "sentinel-key.json")
	if err := os.Symlink(victim, path+".tmp"); err != nil {
		t.Fatal(err)
	}

	store := NewStore(path)
	if err := store.Save(testKeyFile(t)); err != nil {
		t.Fatalf("Save: %v", err)
	}

	got, err := os.ReadFile(victim)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "ORIGINAL" {
		t.Fatalf("victim file was written through the pre-planted .tmp symlink: %q", got)
	}
	if _, err := store.Load(); err != nil {
		t.Fatalf("key file not written correctly: %v", err)
	}
	assertNoStrayTemp(t, dir)
}

// TestSaveOverDestinationSymlinkDoesNotFollow covers a destination that is
// itself a planted symlink: the atomic rename must replace the link, never
// write the key through it.
func TestSaveOverDestinationSymlinkDoesNotFollow(t *testing.T) {
	dir := t.TempDir()
	victimDir := t.TempDir()
	victim := filepath.Join(victimDir, "victim")
	if err := os.WriteFile(victim, []byte("ORIGINAL"), 0o644); err != nil {
		t.Fatal(err)
	}

	path := filepath.Join(dir, "sentinel-key.json")
	if err := os.Symlink(victim, path); err != nil {
		t.Fatal(err)
	}

	store := NewStore(path)
	kf := testKeyFile(t)
	if err := store.Save(kf); err != nil {
		t.Fatalf("Save: %v", err)
	}

	got, err := os.ReadFile(victim)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "ORIGINAL" {
		t.Fatalf("victim file was written through the destination symlink: %q", got)
	}
	fi, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode()&os.ModeSymlink != 0 {
		t.Fatal("destination is still a symlink after Save")
	}
	loaded, err := store.Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if loaded.SentinelID != kf.SentinelID {
		t.Fatalf("SentinelID = %q, want %q", loaded.SentinelID, kf.SentinelID)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("key file mode = %o, want 600", fi.Mode().Perm())
	}
	assertNoStrayTemp(t, dir)
}

func assertNoStrayTemp(t *testing.T, dir string) {
	t.Helper()
	matches, err := filepath.Glob(filepath.Join(dir, "sentinel-key-*.tmp"))
	if err != nil {
		t.Fatal(err)
	}
	if len(matches) != 0 {
		t.Fatalf("stray temp files remain after Save: %v", matches)
	}
}
