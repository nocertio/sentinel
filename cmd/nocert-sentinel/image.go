package main

import (
	"errors"
	"os"
	"path/filepath"
	"strings"

	"nocert.io/sentinel/internal/config"
)

// checkTemplate checks local enrollment state without changing files or contacting
// the backend. The image builder must stop the service before invoking it.
func checkTemplate(cfg *config.Config, envToken, enrollmentFile string) error {
	if cfg.EnrollToken != "" || envToken != "" {
		return errors.New("remove the enrollment token before capturing the image")
	}
	if cfg.SentinelID != "" {
		return errors.New("remove sentinel_id from the template configuration")
	}
	for _, path := range []string{cfg.KeyFile, enrollmentFile} {
		_, err := os.Lstat(path)
		if err == nil {
			return errors.New("template contains a key file or enrollment file; use an unenrolled image")
		}
		if !errors.Is(err, os.ErrNotExist) {
			return errors.New("cannot check template credentials; verify local file access")
		}
	}
	entries, err := os.ReadDir(filepath.Dir(cfg.KeyFile))
	if err != nil {
		return errors.New("cannot inspect the template key directory")
	}
	for _, entry := range entries {
		// An interrupted atomic save can leave a temporary private-key file.
		if strings.HasPrefix(entry.Name(), "sentinel-key-") && strings.HasSuffix(entry.Name(), ".tmp") {
			return errors.New("template contains a temporary key file; use an unenrolled image")
		}
	}
	return nil
}
