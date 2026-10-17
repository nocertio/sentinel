//go:build linux

package filesystem

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"regexp"
)

// configExtensions are the file extensions treated as application config
// files worth scanning for referenced certificate paths.
var configExtensions = map[string]bool{
	".conf": true, ".cnf": true, ".cfg": true, ".ini": true,
	".yaml": true, ".yml": true, ".toml": true, ".cf": true,
}

// maxConfigCandidatePaths bounds how many distinct certificate paths one
// sweep collects from config files - guards a hostile config referencing
// thousands of paths. (Total config files read is bounded by the /etc tree
// size and maxDepth; no separate file-count cap is needed.)
const maxConfigCandidatePaths = 10_000

// certPathRE matches an absolute filesystem path ending in a certificate
// extension. Deliberately broad: every match is later read and must parse
// as a real X.509 certificate, so a false positive costs nothing.
var certPathRE = regexp.MustCompile(`(?i)/[\w./@~+-]*\.(?:pem|crt|cer|cert|der)\b`)

func isConfigExt(ext string) bool { return configExtensions[ext] }
func isCertExt(ext string) bool   { return certExtensions[ext] }

// extractCertPaths returns the deduplicated, path-cleaned absolute
// certificate paths referenced as tokens in config-file content.
func extractCertPaths(content []byte) []string {
	matches := certPathRE.FindAll(content, -1)
	seen := make(map[string]struct{}, len(matches))
	out := make([]string, 0, len(matches))
	for _, m := range matches {
		p := filepath.Clean(string(m))
		if _, ok := seen[p]; ok {
			continue
		}
		seen[p] = struct{}{}
		out = append(out, p)
	}
	return out
}

// collectConfigReferencedCertPaths walks root (typically /etc) for config
// files and returns the deduplicated certificate paths they reference. The
// bool is false if the walk was cancelled or hit the candidate cap - the
// caller treats that as an incomplete sweep.
func collectConfigReferencedCertPaths(ctx context.Context, root string) ([]string, bool) {
	seen := make(map[string]struct{})
	var out []string
	capped := false
	readErr := false

	walkComplete := walkBoundedFiles(ctx, root, isConfigExt, func(path string) {
		if capped {
			return
		}
		data, err := readScanFile(path)
		if err != nil {
			if !errors.Is(err, os.ErrNotExist) {
				readErr = true
			}
			return
		}
		for _, p := range extractCertPaths(data) {
			if len(out) >= maxConfigCandidatePaths {
				capped = true
				return
			}
			if _, ok := seen[p]; ok {
				continue
			}
			seen[p] = struct{}{}
			out = append(out, p)
		}
	})
	return out, walkComplete && !capped && !readErr
}
