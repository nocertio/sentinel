//go:build linux

package filesystem

import "strings"

// searchPaths (Strategy 1) are the well-known directories that hold a host's
// OWN certificates. The system trust store (/etc/ssl/certs, /etc/pki/tls/certs)
// is deliberately NOT walked: it holds public CAs, not the host's certs, and the
// sentinel no longer parses certificates so it can't filter them out. A server
// cert actually in use is still found via the config-reference scan (Strategy 2).
var searchPaths = []string{
	"/etc/letsencrypt/live/",
	"/etc/docker/certs.d/",
	"/usr/local/share/ca-certificates/",
	// Kubernetes control-plane PKI. Self-managed clusters keep their own
	// certs here (kubeadm: 1-year client certs; k3s/RKE2: 365-day certs
	// renewed only on service restart). Readability as the unprivileged
	// nocert-sentinel user varies by distro - unreadable dirs are silently
	// skipped by the walker, so listing them costs nothing where absent.
	"/etc/kubernetes/pki/",
	"/var/lib/kubelet/pki/",
	"/var/lib/rancher/k3s/server/tls/",
	"/var/lib/rancher/rke2/server/tls/",
}

// excludedPrefixes are bulk trust-store trees to skip, so a config that points
// into one (Strategy 2) can't drag the whole store in.
var excludedPrefixes = []string{
	"/etc/pki/ca-trust/",
	"/etc/ca-certificates/",
	"/usr/share/ca-certificates/",
	// Secret volumes projected into pods (tmpfs). They hold tls.key next to
	// tls.crt; the Kubernetes connector reads the public half via the API
	// server instead. Explicit exclusion, not an accident of permissions.
	"/var/lib/kubelet/pods/",
}

// excludedFiles are concatenated trust bundles (one file, hundreds of CAs) to
// skip if a config references one.
var excludedFiles = map[string]bool{
	"/etc/ssl/certs/ca-certificates.crt": true,
	"/etc/ssl/certs/ca-bundle.crt":       true,
}

// SearchPaths returns the Strategy 1 scan directories.
func SearchPaths() []string {
	paths := make([]string, len(searchPaths))
	copy(paths, searchPaths)
	return paths
}

// IsExcluded reports whether a path must be skipped: a prefix/exact match that
// stops the config-reference scan (Strategy 2) from pulling in a bulk trust
// store it happens to point at. It matches on the literal path, not a resolved
// symlink target.
func IsExcluded(path string) bool {
	if excludedFiles[path] {
		return true
	}
	for _, prefix := range excludedPrefixes {
		if strings.HasPrefix(path, prefix) {
			return true
		}
	}
	return false
}
