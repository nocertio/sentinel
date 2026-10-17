package keystore

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// DefaultSigningKeyID is the keyid the sentinel expects to see on
// inbound RFC 9421 response signatures when the keystore does not
// pin a specific value. It mirrors the backend's default signing key id.
const DefaultSigningKeyID = "server-1"

// KeyFile is the on-disk JSON representation of sentinel credentials.
type KeyFile struct {
	SentinelID       string    `json:"sentinel_id"`
	KeyID            string    `json:"key_id"`
	PrivateKey       string    `json:"private_key"` // base64-encoded Ed25519 seed (32 bytes)
	PublicKey        string    `json:"public_key"`  // base64-encoded Ed25519 public key (32 bytes)
	KeyExpiresAt     time.Time `json:"key_expires_at"`
	SigningPublicKey string    `json:"signing_public_key"` // base64-encoded backend Ed25519 public key used to sign responses
	// SigningKeyID is the keyid the backend stamps on its RFC 9421
	// response signatures. Captured at registration from the
	// signing_key_id field of the /register response.
	SigningKeyID string `json:"signing_key_id"`
	// MachineID pins this key to the host that enrolled it: /etc/machine-id
	// (falling back to /var/lib/dbus/machine-id) captured at registration. If a
	// key file is cloned into a VM template and the template is deployed, the
	// clone's machine-id differs -> the agent discards the foreign key and
	// re-enrolls as itself, instead of impersonating the origin host.
	MachineID string `json:"machine_id,omitempty"`
}

// CurrentMachineID returns the host machine-id, or "" if unavailable. "" never
// triggers a mismatch (guard is best-effort - a missing id must not brick a
// legitimate host).
func CurrentMachineID() string {
	for _, p := range []string{"/etc/machine-id", "/var/lib/dbus/machine-id"} {
		if b, err := os.ReadFile(p); err == nil {
			if id := strings.TrimSpace(string(b)); id != "" {
				return id
			}
		}
	}
	return ""
}

// Store manages the sentinel key file on disk.
type Store struct {
	path string
}

// NewStore creates a Store targeting the given file path.
func NewStore(path string) *Store {
	return &Store{path: path}
}

// Exists returns true if the key file already exists on disk.
func (s *Store) Exists() bool {
	_, err := os.Stat(s.path)
	return err == nil
}

// Load reads and parses the key file from disk.
func (s *Store) Load() (*KeyFile, error) {
	data, err := os.ReadFile(s.path)
	if err != nil {
		return nil, fmt.Errorf("reading key file: %w", err)
	}

	var kf KeyFile
	if err := json.Unmarshal(data, &kf); err != nil {
		return nil, fmt.Errorf("parsing key file: %w", err)
	}

	return &kf, nil
}

// Save writes the key file atomically: a randomly-named temp file created
// O_EXCL in the same directory (mode 0600), fsync'd, then renamed over the
// destination.
//
// The random O_EXCL temp name is a security property, not just hygiene. A
// compromised service account owns /etc/nocert-sentinel (scripts/postinstall.sh
// chowns the whole directory to it), so a fixed, predictable "<path>.tmp" name
// opened with O_CREATE|O_TRUNC could be pre-planted as a symlink; during a root
// re-enrollment the freshly generated private key would then be written through
// the link into - or truncate - an attacker-chosen file. os.CreateTemp opens
// with O_CREATE|O_EXCL, which refuses to open through any pre-existing path
// (symlink or not), and the random name means the temp cannot be pre-created at
// the exact path in the first place.
//
// The fsync matters for durability: a torn key file after a power loss,
// especially in the window between a successful RotateKey RPC and this write,
// would brick the agent and force an on-site re-enrollment.
func (s *Store) Save(kf *KeyFile) error {
	data, err := json.MarshalIndent(kf, "", "  ")
	if err != nil {
		return fmt.Errorf("marshaling key file: %w", err)
	}

	dir := filepath.Dir(s.path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("creating key directory: %w", err)
	}
	// MkdirAll is a no-op if the dir already exists at a laxer mode.
	if err := os.Chmod(dir, 0700); err != nil {
		return fmt.Errorf("securing key directory: %w", err)
	}

	f, err := os.CreateTemp(dir, "sentinel-key-*.tmp")
	if err != nil {
		return fmt.Errorf("creating temporary key file: %w", err)
	}
	tmp := f.Name()
	// CreateTemp already makes the file 0600, but be explicit: the private key
	// must never be group/other-readable, even for the brief pre-rename window.
	if err := f.Chmod(0600); err != nil {
		_ = f.Close()
		_ = os.Remove(tmp)
		return fmt.Errorf("securing temporary key file: %w", err)
	}
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		_ = os.Remove(tmp)
		return fmt.Errorf("writing temporary key file: %w", err)
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		_ = os.Remove(tmp)
		return fmt.Errorf("syncing temporary key file: %w", err)
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("closing temporary key file: %w", err)
	}

	// rename(2) replaces the destination name itself: if s.path is a symlink an
	// attacker planted, it is removed and replaced by our regular file, never
	// followed - so the key is never written through it to another target.
	if err := os.Rename(tmp, s.path); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("renaming key file: %w", err)
	}

	// Best-effort: fsync the directory so the rename survives a crash too.
	if d, err := os.Open(dir); err == nil {
		_ = d.Sync()
		_ = d.Close()
	}
	return nil
}

// GenerateKeyPair creates a new Ed25519 key pair and returns the base64-encoded
// seed (private key) and public key.
func GenerateKeyPair() (privKeyB64, pubKeyB64 string, err error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return "", "", fmt.Errorf("generating Ed25519 key pair: %w", err)
	}

	seed := priv.Seed()
	privKeyB64 = base64.StdEncoding.EncodeToString(seed)
	pubKeyB64 = base64.StdEncoding.EncodeToString(pub)

	return privKeyB64, pubKeyB64, nil
}

// NeedsRotation returns true if the key expires within the given margin.
func (kf *KeyFile) NeedsRotation(margin time.Duration) bool {
	return time.Until(kf.KeyExpiresAt) < margin
}

// PrivateKeyBytes decodes the base64-encoded seed and returns a full Ed25519 private key.
func (kf *KeyFile) PrivateKeyBytes() (ed25519.PrivateKey, error) {
	seed, err := base64.StdEncoding.DecodeString(kf.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("decoding private key: %w", err)
	}
	if len(seed) != ed25519.SeedSize {
		return nil, fmt.Errorf("invalid seed size: got %d, want %d", len(seed), ed25519.SeedSize)
	}
	return ed25519.NewKeyFromSeed(seed), nil
}

// PublicKeyBytes decodes the base64-encoded public key.
func (kf *KeyFile) PublicKeyBytes() (ed25519.PublicKey, error) {
	pub, err := base64.StdEncoding.DecodeString(kf.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("decoding public key: %w", err)
	}
	if len(pub) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("invalid public key size: got %d, want %d", len(pub), ed25519.PublicKeySize)
	}
	return ed25519.PublicKey(pub), nil
}

// SigningPublicKeyBytes decodes the base64-encoded backend signing public key.
func (kf *KeyFile) SigningPublicKeyBytes() (ed25519.PublicKey, error) {
	pub, err := base64.StdEncoding.DecodeString(kf.SigningPublicKey)
	if err != nil {
		return nil, fmt.Errorf("decoding signing public key: %w", err)
	}
	if len(pub) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("invalid signing public key size: got %d, want %d", len(pub), ed25519.PublicKeySize)
	}
	return ed25519.PublicKey(pub), nil
}
