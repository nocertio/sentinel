//go:build linux

// Package filesystem includes a focused helper that, given a
// certificate file's full path, looks for sibling private-key files
// and reports whether any has insecure (group- or other-readable)
// permissions.
//
// The full path is consumed internal to the sentinel only - it is
// NEVER transmitted on the wire. Only the boolean result, surfaced
// as the FilesystemWarningInsecurePrivateKeyPermissions enum value,
// reaches the backend.
package filesystem

import (
	"bytes"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// privateKeyExtensions are the conventional file extensions for
// private keys. The .pem extension is intentionally absent here:
// .pem files may contain a key, a cert, both, or neither, so we
// inspect their contents (see pemContainsPrivateKey).
var privateKeyExtensions = []string{".key"}

// pemPrivateKeyMarkers are PEM headers that identify private-key
// files when the extension is .pem.
var pemPrivateKeyMarkers = [][]byte{
	[]byte("-----BEGIN PRIVATE KEY-----"),
	[]byte("-----BEGIN ENCRYPTED PRIVATE KEY-----"),
	[]byte("-----BEGIN RSA PRIVATE KEY-----"),
	[]byte("-----BEGIN EC PRIVATE KEY-----"),
	[]byte("-----BEGIN DSA PRIVATE KEY-----"),
	[]byte("-----BEGIN OPENSSH PRIVATE KEY-----"),
}

// insecurePermissionsMask flags any mode bit beyond owner read-write,
// i.e. any group or other readability.
const insecurePermissionsMask = 0o077

// CheckSiblingPrivateKey returns insecure=true iff the sentinel finds
// a private-key file alongside the given certificate path with mode
// looser than 0600.
//
// Heuristics for sibling discovery, applied in order:
//
//  1. Same base name with .key extension       (cert.crt -> cert.key)
//  2. Same base name in a "private/" sibling   (certs/foo.crt -> private/foo.key)
//  3. Adjacent .pem file containing a private key marker
//
// Errors stating the candidate cannot be read (permission denied,
// file vanished) return insecure=false, err=nil - the sentinel does
// not flag what it cannot see. Genuine I/O errors are returned.
func CheckSiblingPrivateKey(certFullPath string) (insecure bool, err error) {
	dir := filepath.Dir(certFullPath)
	baseName := strings.TrimSuffix(filepath.Base(certFullPath), filepath.Ext(certFullPath))

	candidates := siblingCandidates(dir, baseName)

	for _, candidate := range candidates {
		info, statErr := os.Stat(candidate)
		if statErr != nil {
			if errors.Is(statErr, fs.ErrNotExist) || errors.Is(statErr, fs.ErrPermission) {
				continue
			}
			return false, statErr
		}
		if !info.Mode().IsRegular() {
			continue
		}
		if info.Mode()&insecurePermissionsMask != 0 {
			// Confirm it really is a private key (avoid false positives
			// for unrelated .key files). For .key files we trust the
			// extension; for .pem we read first 1 KiB and look for a
			// PEM private-key marker.
			isKey, readErr := looksLikePrivateKey(candidate)
			if readErr != nil {
				if errors.Is(readErr, fs.ErrPermission) {
					// We saw the loose mode bit by stat, but cannot
					// read the file ourselves. Stat is enough - group
					// or other CAN read; that is the warning.
					return true, nil
				}
				return false, readErr
			}
			if isKey {
				return true, nil
			}
		}
	}
	return false, nil
}

// siblingCandidates lists possible private-key paths next to the cert.
func siblingCandidates(dir, baseName string) []string {
	candidates := []string{}
	for _, ext := range privateKeyExtensions {
		candidates = append(candidates, filepath.Join(dir, baseName+ext))
	}
	// Adjacent private/ subdir (common in nginx/apache layouts).
	for _, ext := range privateKeyExtensions {
		candidates = append(candidates, filepath.Join(dir, "private", baseName+ext))
	}
	// Adjacent .pem alongside the cert.
	candidates = append(candidates, filepath.Join(dir, baseName+".pem"))
	return candidates
}

// looksLikePrivateKey returns true if the first 1 KiB of the file
// contains any PEM private-key marker. For .key files we accept by
// extension without reading.
func looksLikePrivateKey(path string) (bool, error) {
	if filepath.Ext(path) == ".key" {
		return true, nil
	}
	f, err := openRegular(path)
	if err != nil || f == nil {
		return false, err
	}
	defer func() { _ = f.Close() }()
	buf := make([]byte, 1024)
	n, err := f.Read(buf)
	if err != nil && !errors.Is(err, io.EOF) {
		return false, err
	}
	head := buf[:n]
	for _, marker := range pemPrivateKeyMarkers {
		if bytes.Contains(head, marker) {
			return true, nil
		}
	}
	return false, nil
}
