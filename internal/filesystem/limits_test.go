//go:build linux

package filesystem

import (
	"bytes"
	"context"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestDiscoverRejectsOversizedCertificate(t *testing.T) {
	dir := t.TempDir()
	small := fsBigShapedCert("small", 32)
	large := fsBigShapedCert("large", 64*1024)
	require.NoError(t, os.WriteFile(filepath.Join(dir, "small.der"), small, 0600))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "large.der"), large, 0600))
	res := NewScanner().Discover(context.Background(), []string{dir}, t.TempDir())
	require.Len(t, res.Certificates, 1)
	require.Equal(t, small, res.Certificates[0].DER)
	require.False(t, res.Complete)
	require.True(t, res.Truncated)
}

func TestDiscoverBoundsEscapedPaths(t *testing.T) {
	dir := t.TempDir()
	der := fsBigShapedCert("cert", 32)
	for i := range 1500 {
		name := fmt.Sprintf("%s%d.der", strings.Repeat("<", 220), i)
		require.NoError(t, os.WriteFile(filepath.Join(dir, name), der, 0600))
	}
	res := NewScanner().Discover(context.Background(), []string{dir}, t.TempDir())
	require.True(t, res.Truncated)
	require.False(t, res.Complete)
	total := 0
	for _, obs := range res.Observations {
		for _, path := range obs.FilePaths {
			encoded, err := json.Marshal(path)
			require.NoError(t, err)
			total += len(encoded) + 1
		}
	}
	require.Positive(t, total)
	require.LessOrEqual(t, total, maxPathBytesPerSweep)
}

func TestDiscoverBundleLimitIsIncomplete(t *testing.T) {
	for _, count := range []int{maxCertsPerFile, maxCertsPerFile + 1} {
		dir := t.TempDir()
		block := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: fsBigShapedCert("cert", 32)})
		require.NoError(t, os.WriteFile(filepath.Join(dir, "bundle.pem"), bytes.Repeat(block, count), 0600))
		res := NewScanner().Discover(context.Background(), []string{dir}, t.TempDir())
		require.Len(t, res.Certificates, 1)
		require.Equal(t, count <= maxCertsPerFile, res.Complete)
		require.Equal(t, count > maxCertsPerFile, res.Truncated)
	}
}

func TestOversizedConfigMakesSweepIncomplete(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "large.conf"), bytes.Repeat([]byte(" "), maxFileSize+1), 0600))
	_, complete := collectConfigReferencedCertPaths(context.Background(), dir)
	require.False(t, complete)
}
