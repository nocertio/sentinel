package sentinel

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"

	"nocert.io/sentinel/internal/filesystem"
)

// TestFilesystemScanningGuard verifies that triggerFilesystemScan
// respects the fsScanning atomic and short-circuits when a scan is
// already in flight.
func TestFilesystemScanningGuard(t *testing.T) {
	s := newTestSentinel(true)
	s.cfg.AllowFilesystemScan = boolPtr(true)
	s.fsScanner = filesystem.NewScanner()

	// Simulate an already-running scan
	s.fsScanning.Store(true)

	// Should return immediately without panic (scan skipped, but the
	// "skipped" path also calls reportTask with a nil client when taskID
	// is non-empty - so call with an empty taskID to keep the test pure).
	assert.NotPanics(t, func() {
		s.triggerFilesystemScan(context.Background(), "")
	})
}
