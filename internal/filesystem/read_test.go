//go:build linux

package filesystem

import (
	"bytes"
	"os"
	"path/filepath"
	"syscall"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestReadScanFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "cert.pem")
	for _, size := range []int{0, maxFileSize, maxFileSize + 1} {
		require.NoError(t, os.WriteFile(path, bytes.Repeat([]byte("x"), size), 0600))
		data, err := readScanFile(path)
		if size > maxFileSize {
			require.ErrorIs(t, err, errFileTooLarge)
			require.Empty(t, data)
		} else {
			require.NoError(t, err)
			require.Len(t, data, size)
		}
	}
	require.NoError(t, os.WriteFile(path, []byte("certificate"), 0600))
	link := filepath.Join(dir, "link.pem")
	require.NoError(t, os.Symlink(path, link))
	data, err := readScanFile(link)
	require.NoError(t, err)
	require.Equal(t, []byte("certificate"), data)
}

func TestScanSkipsSpecialFiles(t *testing.T) {
	dir := t.TempDir()
	pipe := filepath.Join(dir, "cert.pem")
	require.NoError(t, syscall.Mkfifo(pipe, 0644))
	// No writer: opening this FIFO without O_NONBLOCK would hang.
	data, err := readScanFile(pipe)
	require.NoError(t, err)
	require.Empty(t, data)
	isKey, err := looksLikePrivateKey(pipe)
	require.NoError(t, err)
	require.False(t, isKey)
	insecure, err := CheckSiblingPrivateKey(filepath.Join(dir, "cert.crt"))
	require.NoError(t, err)
	require.False(t, insecure)
}
