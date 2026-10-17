//go:build linux

package filesystem

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// walkBoundedFiles walks root and calls visit for every regular file whose
// lowercased extension accept() accepts. The walk is bounded by maxDepth and
// guarded against symlink loops via device+inode tracking. Returns false if the
// walk was not exhaustive - cancelled mid-walk, or a subdir/root was unreadable
// (EACCES/EIO), or the depth limit was reached. A missing root (ENOENT) or a non-directory root is a normal,
// complete "nothing here" and returns true; the caller must NOT reconcile-delete
// on a false return, or a transient error would look like the certs vanished.
func walkBoundedFiles(ctx context.Context, root string, accept func(ext string) bool, visit func(path string)) bool {
	info, err := os.Stat(root)
	if err != nil {
		// A missing well-known dir is normal (most hosts lack a given distro's
		// cert layout). Any other error means we could not survey this root.
		return errors.Is(err, fs.ErrNotExist)
	}
	if !info.IsDir() {
		return true
	}
	visited := make(map[[2]uint64]bool)
	rootDepth := strings.Count(filepath.Clean(root), string(os.PathSeparator))
	cancelled := false
	incomplete := false

	_ = filepath.WalkDir(root, func(path string, d fs.DirEntry, walkErr error) error {
		if ctx.Err() != nil {
			cancelled = true
			return fs.SkipAll
		}
		if walkErr != nil {
			// An unreadable subdir (EACCES/EIO) is a coverage gap, not an absence:
			// keep walking siblings so we still report what we can see, but mark
			// the sweep incomplete. A mid-walk ENOENT (racing deletion) is benign.
			if !errors.Is(walkErr, fs.ErrNotExist) {
				incomplete = true
			}
			return nil
		}
		depth := strings.Count(filepath.Clean(path), string(os.PathSeparator)) - rootDepth
		if depth > maxDepth {
			incomplete = true
			if d.IsDir() {
				return fs.SkipDir
			}
			return nil
		}
		if d.IsDir() {
			if ino, ok := inodeOf(path); ok {
				if visited[ino] {
					return fs.SkipDir
				}
				visited[ino] = true
			}
			return nil
		}
		if !accept(strings.ToLower(filepath.Ext(path))) {
			return nil
		}
		visit(path)
		return nil
	})
	return !cancelled && !incomplete
}
