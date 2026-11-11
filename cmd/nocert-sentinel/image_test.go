package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
	"nocert.io/sentinel/internal/config"
)

func TestCheckTemplate(t *testing.T) {
	for _, state := range []string{"clean", "custom key path", "empty key", "malformed key", "broken key symlink", "enrollment file", "broken enrollment symlink", "config token", "environment token", "old identity", "temporary key", "missing key directory", "invalid path"} {
		t.Run(state, func(t *testing.T) {
			dir := t.TempDir()
			cfg := &config.Config{KeyFile: filepath.Join(dir, "key.json")}
			enrollFile := filepath.Join(dir, "enroll.env")
			var envToken string
			switch state {
			case "custom key path":
				cfg.KeyFile = filepath.Join(dir, "custom-identity.json")
			case "empty key":
				require.NoError(t, os.WriteFile(cfg.KeyFile, nil, 0600))
			case "malformed key":
				require.NoError(t, os.WriteFile(cfg.KeyFile, []byte("private fixture material"), 0600))
			case "broken key symlink":
				require.NoError(t, os.Symlink(filepath.Join(dir, "absent"), cfg.KeyFile))
			case "enrollment file":
				require.NoError(t, os.WriteFile(enrollFile, []byte("NOCERT_ENROLL_TOKEN=fixture-secret"), 0600))
			case "broken enrollment symlink":
				require.NoError(t, os.Symlink(filepath.Join(dir, "absent"), enrollFile))
			case "config token":
				cfg.EnrollToken = "fixture-secret"
			case "environment token":
				envToken = "fixture-secret"
			case "old identity":
				cfg.SentinelID = "old-instance"
			case "temporary key":
				require.NoError(t, os.WriteFile(filepath.Join(dir, "sentinel-key-123.tmp"), []byte("private fixture material"), 0600))
			case "missing key directory":
				cfg.KeyFile = filepath.Join(dir, "missing", "key.json")
			case "invalid path":
				cfg.KeyFile = filepath.Join(dir, "invalid\x00key")
			}
			err := checkTemplate(cfg, envToken, enrollFile)
			if state == "clean" || state == "custom key path" {
				require.NoError(t, err)
			} else {
				require.Error(t, err)
				require.NotContains(t, err.Error(), "fixture-secret")
				require.NotContains(t, err.Error(), "private fixture material")
			}
			if state == "malformed key" {
				data, err := os.ReadFile(cfg.KeyFile)
				require.NoError(t, err)
				require.Equal(t, "private fixture material", string(data), "a check must not reset an enrolled host")
			}
		})
	}
}
