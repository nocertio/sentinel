//go:build linux

package filesystem

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"sort"
	"syscall"

	"nocert.io/common/pkg/api/sentinel"
)

const (
	maxFileSize = 1 << 20 // 1 MB
	maxDepth    = 5
	maxFiles    = 10_000
	maxDERBytes = 64 * 1024 // backend per-certificate limit
	// maxFingerprints bounds the number of DISTINCT certificates one sweep
	// reports. The whole sweep ships in a single /report call, and the backend
	// rejects a report carrying more than 1000 certs/observations outright. So
	// cap the output here and mark the sweep incomplete (Complete=false, no
	// reconciliation) rather than letting the backend 400 the entire report and
	// ingest nothing. Must stay <= the backend's per-report certificate cap.
	maxFingerprints = 1000
	// maxCertBytesPerSweep and maxPathBytesPerSweep bound the two variable-size
	// dimensions of the single /report body so it can never exceed the backend's
	// 5 MiB cap and 413 the WHOLE sweep (which would silently lose every finding
	// on the host). The 1000-cert count cap alone is not enough: a cert file may
	// be up to maxFileSize (1 MiB), and a compromised host can reference many
	// copies of one cert from /etc configs, so BOTH the DER bytes and the
	// observation paths must be capped.
	//
	// Report sizing under the 5 MiB backend cap: DER travels base64 (x4/3), so
	// 2 MiB raw DER -> ~2.74 MiB; observation FilePaths -> <=1.5 MiB; the
	// fingerprint list plus per-cert framing (<=1000 certs) -> ~0.3 MiB. Total
	// worst case ~4.5 MiB, ~0.5 MiB margin. A normal host is nowhere near either
	// cap (it has few certs at a handful of paths); overflow marks the sweep
	// truncated (Complete=false, no reconciliation) instead of shipping.
	maxCertBytesPerSweep = 2 << 20
	maxPathBytesPerSweep = 3 << 19 // 1.5 MiB
)

var certExtensions = map[string]bool{
	".pem": true, ".crt": true, ".cer": true, ".cert": true, ".der": true,
}

// FSScanResult is the complete, aggregated output of one filesystem sweep.
type FSScanResult struct {
	// Certificates is every distinct certificate found on disk (leaf AND CA -
	// the sentinel no longer classifies; the backend does), deduplicated by
	// fingerprint.
	Certificates []sentinel.Certificate
	// Observations is one entry per distinct fingerprint, carrying every
	// path the certificate was found at on this host.
	Observations []sentinel.SentinelFilesystemObservation
	// Complete is false if the sweep was cancelled or hit a hard cap. When
	// false the backend must NOT reconcile (delete vanished findings).
	Complete bool
	// Truncated is true if a hard cap (maxFiles / maxFingerprints) was hit -
	// certificates on this host went unreported. Distinct from a cancelled
	// sweep so the operator can tell "under-monitored" from "interrupted".
	Truncated bool
}

// fsAgg accumulates, per fingerprint, the DER bytes, the set of paths the
// cert was found at, and the union of filesystem-state warnings.
type fsAgg struct {
	der      []byte
	paths    map[string]struct{}
	warnings map[string]struct{}
}

// Scanner discovers certificates on the local filesystem.
type Scanner struct{}

// NewScanner creates a new filesystem scanner.
func NewScanner() *Scanner {
	return &Scanner{}
}

// Discover runs a full filesystem certificate sweep: Strategy 1 (well-known
// certificate directories in certDirs) plus Strategy 2 (paths referenced by
// config files under cfgRoot). Results are aggregated per fingerprint.
func (s *Scanner) Discover(ctx context.Context, certDirs []string, cfgRoot string) *FSScanResult {
	agg := make(map[string]*fsAgg)
	fileCount := 0
	derBytes := 0
	pathBytes := 0
	truncated := false
	incomplete := false

	processFile := func(path string) {
		if fileCount >= maxFiles {
			truncated = true
			return
		}
		if IsExcluded(path) {
			return
		}
		data, err := readScanFile(path)
		if err != nil {
			if errors.Is(err, errFileTooLarge) {
				truncated = true
			}
			if !errors.Is(err, os.ErrNotExist) {
				incomplete = true
			}
			return
		}
		ders, extractedAll := extractCertDER(data)
		if !extractedAll {
			truncated = true
		}
		if len(ders) == 0 {
			return
		}
		fileCount++
		insecureSibling, _ := CheckSiblingPrivateKey(path)
		for _, der := range ders {
			if len(der) > maxDERBytes {
				truncated = true
				continue
			}
			fp := fingerprintHex(der)
			a := agg[fp]
			if a == nil {
				if len(agg) >= maxFingerprints || derBytes+len(der) > maxCertBytesPerSweep {
					truncated = true
					continue
				}
				a = &fsAgg{
					der:      der,
					paths:    map[string]struct{}{},
					warnings: map[string]struct{}{},
				}
				derBytes += len(der)
				agg[fp] = a
			}
			// Bound the cumulative observation-path bytes too: a host that
			// references many cert copies from /etc configs could otherwise blow
			// the report past the backend cap through paths alone. Each new
			// (fingerprint, path) pair is one entry serialized in the report.
			if _, seen := a.paths[path]; !seen {
				encodedPath, _ := json.Marshal(path)
				cost := len(encodedPath) + 1 // JSON string and array separator
				if pathBytes+cost > maxPathBytesPerSweep {
					truncated = true
				} else {
					pathBytes += cost
					a.paths[path] = struct{}{}
				}
			}
			if insecureSibling {
				a.warnings[sentinel.FilesystemWarningInsecurePrivateKeyPermissions] = struct{}{}
			}
		}
	}

	complete := true
	// Strategy 1: well-known certificate directories.
	for _, dir := range certDirs {
		if !walkBoundedFiles(ctx, dir, isCertExt, processFile) {
			complete = false
		}
	}
	// Strategy 2: paths referenced by config files under cfgRoot.
	cfgPaths, cfgComplete := collectConfigReferencedCertPaths(ctx, cfgRoot)
	for _, p := range cfgPaths {
		if ctx.Err() != nil {
			complete = false
			break
		}
		processFile(p)
	}

	complete = complete && cfgComplete && !truncated && !incomplete && ctx.Err() == nil
	res := buildFSResult(agg, complete)
	res.Truncated = truncated
	return res
}

// buildFSResult flattens the per-fingerprint aggregation into the wire shape.
func buildFSResult(agg map[string]*fsAgg, complete bool) *FSScanResult {
	res := &FSScanResult{Complete: complete}
	for fp, a := range agg {
		res.Certificates = append(res.Certificates, sentinel.Certificate{
			FingerprintSHA256: fp,
			DER:               a.der,
		})
		paths := make([]string, 0, len(a.paths))
		for p := range a.paths {
			paths = append(paths, p)
		}
		sort.Strings(paths) // deterministic output
		var warnings []string
		for w := range a.warnings {
			warnings = append(warnings, w)
		}
		res.Observations = append(res.Observations, sentinel.SentinelFilesystemObservation{
			FilePaths:         paths,
			FingerprintSHA256: fp,
			Warnings:          warnings,
		})
	}
	return res
}

// inodeOf returns the device+inode pair for symlink loop detection.
func inodeOf(path string) ([2]uint64, bool) {
	var stat syscall.Stat_t
	if err := syscall.Stat(path, &stat); err != nil {
		return [2]uint64{}, false
	}
	return [2]uint64{stat.Dev, stat.Ino}, true
}

// fingerprintHex returns the lowercase hex SHA-256 of a DER-encoded
// certificate. Mirrors scanner.Fingerprint - duplicated here to avoid
// an import cycle between this package and the scanner package.
func fingerprintHex(der []byte) string {
	sum := sha256.Sum256(der)
	return hex.EncodeToString(sum[:])
}
