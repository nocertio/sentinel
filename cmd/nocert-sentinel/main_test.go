package main

import (
	"context"
	"errors"
	"log/slog"
	"os"
	"os/user"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestResolveEnrollToken(t *testing.T) {
	assert.Equal(t, "from-flag", resolveEnrollToken("from-flag", "from-env"), "flag takes priority over env")
	assert.Equal(t, "from-env", resolveEnrollToken("", "from-env"))
	assert.Equal(t, "", resolveEnrollToken("", ""))
}

func TestSetupLoggerLevel(t *testing.T) {
	cases := map[string]slog.Level{
		"debug":   slog.LevelDebug,
		"warn":    slog.LevelWarn,
		"error":   slog.LevelError,
		"info":    slog.LevelInfo,
		"":        slog.LevelInfo,
		"garbage": slog.LevelInfo,
	}
	for in, want := range cases {
		logger := setupLogger(in, "json")
		assert.Equal(t, want == slog.LevelDebug, logger.Enabled(context.Background(), slog.LevelDebug), "debug enablement for %q", in)
		assert.True(t, logger.Enabled(context.Background(), want), "configured level %q must be enabled", in)
		if want > slog.LevelDebug {
			assert.False(t, logger.Enabled(context.Background(), want-1), "level below %q must be filtered", in)
		}
	}
}

func TestSetupLoggerFormat(t *testing.T) {
	// text vs json are distinct handler types; both must construct a usable logger.
	assert.NotNil(t, setupLogger("info", "text").Handler())
	assert.NotNil(t, setupLogger("info", "json").Handler())
}

func TestChownToServiceUser_LookupFailureSkips(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "sentinel-key.json")
	require.NoError(t, os.WriteFile(p, []byte("{}"), 0o600))

	called := false
	err := chownToServiceUser(func(string) (*user.User, error) {
		called = true
		return nil, errors.New("unknown user nocert-sentinel")
	}, p)

	require.Error(t, err, "missing service user must fail so the caller skips start and does not claim success")
	assert.True(t, called)
}

func TestChownToServiceUser_NonNumericUidSkips(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "sentinel-key.json")
	require.NoError(t, os.WriteFile(p, []byte("{}"), 0o600))

	err := chownToServiceUser(func(string) (*user.User, error) {
		return &user.User{Uid: "not-a-number", Gid: "0"}, nil
	}, p)

	require.Error(t, err)
}

func TestChownNoFollowRefusesSymlink(t *testing.T) {
	dir := t.TempDir()
	victim := filepath.Join(dir, "victim")
	if err := os.WriteFile(victim, []byte("data"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "sentinel-key.json")
	if err := os.Symlink(victim, link); err != nil {
		t.Fatal(err)
	}
	// Chowning to our own uid/gid can't visibly change ownership, so the point
	// of the test is that no-follow REFUSES the symlink rather than operating on
	// the victim behind it.
	if err := chownNoFollow(link, os.Getuid(), os.Getgid()); err == nil {
		t.Fatal("chownNoFollow followed a symlink instead of refusing it")
	}
}

func TestChownNoFollowRegularFileSucceeds(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sentinel-key.json")
	if err := os.WriteFile(path, []byte("data"), 0o600); err != nil {
		t.Fatal(err)
	}
	// Chown to the current owner is permitted without privilege and exercises
	// the fchown-on-open-descriptor happy path.
	if err := chownNoFollow(path, os.Getuid(), os.Getgid()); err != nil {
		t.Fatalf("chownNoFollow on a regular file: %v", err)
	}
}

func TestChownNoFollowRefusesNonRegular(t *testing.T) {
	dir := t.TempDir()
	if err := chownNoFollow(dir, os.Getuid(), os.Getgid()); err == nil {
		t.Fatal("chownNoFollow accepted a directory")
	}
}

func TestChownNoFollowRefusesHardlink(t *testing.T) {
	dir := t.TempDir()
	victim := filepath.Join(dir, "victim")
	if err := os.WriteFile(victim, []byte("data"), 0o600); err != nil {
		t.Fatal(err)
	}
	alias := filepath.Join(dir, "sentinel-key.json")
	if err := os.Link(victim, alias); err != nil {
		t.Fatal(err)
	}
	// A hardlink is a regular non-symlink file, so it must be caught by the
	// nlink check, not O_NOFOLLOW / IsRegular.
	if err := chownNoFollow(alias, os.Getuid(), os.Getgid()); err == nil {
		t.Fatal("chownNoFollow chowned a hardlinked (aliased) file")
	}
}

// TestRestartServiceRestartsAnAlreadyRunningUnit pins the reason this is a
// restart and not `enable --now`: a re-enrollment is normally run on a host
// whose service is up, and starting an active unit is a no-op, so the daemon
// would keep polling with the key it replaced.
func TestRestartServiceRestartsAnAlreadyRunningUnit(t *testing.T) {
	var got [][]string
	err := restartService(func(args ...string) ([]byte, error) {
		got = append(got, args)
		return nil, nil
	})

	require.NoError(t, err)
	assert.Equal(t, [][]string{
		{"enable", serviceUnit},
		{"restart", serviceUnit},
	}, got)
}

func TestRestartServiceSurfacesFailure(t *testing.T) {
	err := restartService(func(args ...string) ([]byte, error) {
		if args[0] == "restart" {
			return []byte("Job for nocert-sentinel.service failed"), errors.New("exit status 1")
		}
		return nil, nil
	})

	require.Error(t, err, "a failed restart must not be reported as a successful enrollment")
	assert.Contains(t, err.Error(), "Job for nocert-sentinel.service failed", "systemctl output is the only clue the operator gets")
}

func TestCheckKeyFileUnderConfigDir(t *testing.T) {
	cfg := "/etc/nocert-sentinel/config.yaml"
	cases := map[string]bool{ // key_file -> allowed
		"/etc/nocert-sentinel/sentinel-key.json": true,
		"/etc/nocert-sentinel/other.json":        true,
		"/root/.bashrc":                          false, // arbitrary root file
		"/etc/passwd":                            false,
		"/etc/nocert-sentinel/../../root/x":      false, // traversal (cleaned away)
		"/etc/nocert-sentinel/sub/key.json":      false, // not a direct child (blocks symlinked subdir)
	}
	for keyFile, allowed := range cases {
		err := checkKeyFileUnderConfigDir(cfg, keyFile)
		if allowed && err != nil {
			t.Errorf("%s: expected allowed, got %v", keyFile, err)
		}
		if !allowed && err == nil {
			t.Errorf("%s: expected rejected, got nil", keyFile)
		}
	}
}
