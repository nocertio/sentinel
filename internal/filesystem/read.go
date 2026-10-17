//go:build linux

package filesystem

import (
	"errors"
	"io"
	"os"
	"syscall"
)

var errFileTooLarge = errors.New("file exceeds scan size limit")

// openRegular checks the opened descriptor, since a path can change between
// stat and open. O_NONBLOCK prevents a substituted FIFO from stalling a scan.
// Symlinks to regular files remain supported (e.g. Let's Encrypt live/).
func openRegular(path string) (*os.File, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	info, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return nil, err
	}
	if !info.Mode().IsRegular() {
		_ = f.Close()
		return nil, nil
	}
	return f, nil
}

func readScanFile(path string) ([]byte, error) {
	f, err := openRegular(path)
	if err != nil || f == nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	data, err := io.ReadAll(io.LimitReader(f, maxFileSize+1))
	if err != nil {
		return nil, err
	}
	if len(data) > maxFileSize {
		return nil, errFileTooLarge
	}
	return data, nil
}
