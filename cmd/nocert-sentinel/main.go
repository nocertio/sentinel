package main

import (
	"bytes"
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"os/signal"
	"os/user"
	"path/filepath"
	"strconv"
	"syscall"

	"nocert.io/sentinel/internal/config"
	"nocert.io/sentinel/internal/sentinel"
	"nocert.io/sentinel/internal/version"
)

// serviceUser is the system account the systemd unit runs as (created by the
// package postinstall). A root enrollment hands the freshly written key and
// config to this user so the hardened unit can read them.
const serviceUser = "nocert-sentinel"

// serviceUnit is the systemd unit shipped by the package.
const serviceUnit = "nocert-sentinel"

func main() {
	configPath := flag.String("config", "/etc/nocert-sentinel/config.yaml", "path to configuration file")
	enrollToken := flag.String("enroll-token", "", "enroll once with this token, then exit (prefer NOCERT_ENROLL_TOKEN env; argv is visible via ps/proc)")
	showVersion := flag.Bool("version", false, "print version and exit")
	flag.Parse()

	if *showVersion {
		fmt.Println(version.String())
		os.Exit(0)
	}

	cfg, err := config.Load(*configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	// When run privileged (a `sudo --enroll-token` re-enrollment), the key write
	// happens as root at cfg.KeyFile. The config it comes from lives in a
	// directory the unprivileged service account owns, so a compromised account
	// could point key_file at an arbitrary file and have the root-run atomic
	// rename overwrite it. Confine the key file to the config directory.
	if err := enforceKeyFileUnderConfigDir(*configPath, cfg.KeyFile); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	logger := setupLogger(cfg.LogLevel, cfg.LogFormat)
	logger.Info("starting nocert-sentinel", "version", version.Version)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGTERM, syscall.SIGINT)
	go func() {
		sig := <-sigCh
		logger.Info("received signal, shutting down", "signal", sig)
		cancel()
	}()

	// The --enroll-token FLAG is the manual one-shot: force a fresh enrollment
	// (replacing any existing key) then exit. A token from config/env is
	// different: it feeds service-mode self-enroll, which is IDEMPOTENT - an
	// already-enrolled clone (key file present) reuses its identity and ignores
	// the token. That split is what makes the token safe to bake into a VM image.
	s := sentinel.New(cfg, logger)

	if *enrollToken != "" {
		if err := s.EnrollOnce(ctx, *enrollToken); err != nil {
			logger.Error("enrollment failed", "error", err)
			os.Exit(1)
		}
		// The identity is on disk, but a service left running on the previous one
		// polls forever with a key the backend no longer knows. Exit non-zero so
		// an operator (or the cloud-init / Ansible run doing this) sees it.
		if err := finishEnroll(cfg, *configPath, logger); err != nil {
			logger.Error("enrolled, but the service is not running the new identity",
				"error", err,
				"action", "sudo systemctl enable --now nocert-sentinel",
			)
			os.Exit(1)
		}
		return
	}

	// Service mode. On a fresh template clone (no key yet) self-enroll with the
	// injected token; on an already-enrolled host the token is ignored. Env wins
	// over config so a cloud-init-injected token overrides any stale value baked
	// into the template's config.yaml.
	serviceToken := resolveEnrollToken(os.Getenv("NOCERT_ENROLL_TOKEN"), cfg.EnrollToken)
	if err := s.Run(ctx, serviceToken); err != nil {
		logger.Error("sentinel exited with error", "error", err)
		os.Exit(1)
	}

	logger.Info("nocert-sentinel stopped")
}

// finishEnroll turns enrollment into a one-liner: after a successful register
// it hands the freshly written key + config to the service user (so a root
// enrollment does not leave them root-owned and unreadable by the
// User=nocert-sentinel unit) and restarts the service via systemd. Off systemd
// there is nothing to drive, so it says what is left to do and succeeds.
func finishEnroll(cfg *config.Config, configPath string, logger *slog.Logger) error {
	// If root can't hand the credentials to the service user, the hardened
	// User=nocert-sentinel unit can't read them and crash-loops - don't start
	// it (and don't claim success) in that case.
	if os.Geteuid() == 0 {
		if err := chownToServiceUser(user.Lookup, cfg.KeyFile, configPath); err != nil {
			return fmt.Errorf("handing credentials to user %q: %w", serviceUser, err)
		}
	}

	path, err := exec.LookPath("systemctl")
	if err != nil {
		logger.Info("enrolled; start the service with your init system", "sentinel_id", cfg.SentinelID)
		return nil
	}
	run := func(args ...string) ([]byte, error) { return exec.Command(path, args...).CombinedOutput() }
	if err := restartService(run); err != nil {
		return err
	}
	logger.Info("enrolled and started", "sentinel_id", cfg.SentinelID)
	return nil
}

// restartService hands the freshly written identity to the service. The restart
// is what makes a re-enrollment take effect: the daemon reads its key once at
// start-up, and `enable --now` does nothing to a unit that is already running,
// so without it the service would keep signing with the replaced key and poll
// forever with an "unknown sentinel" 401.
func restartService(run func(args ...string) ([]byte, error)) error {
	for _, args := range [][]string{{"enable", serviceUnit}, {"restart", serviceUnit}} {
		if out, err := run(args...); err != nil {
			return fmt.Errorf("systemctl %s: %w: %s", args[0], err, bytes.TrimSpace(out))
		}
	}
	return nil
}

func chownToServiceUser(lookup func(string) (*user.User, error), paths ...string) error {
	u, err := lookup(serviceUser)
	if err != nil {
		return fmt.Errorf("lookup user %q: %w", serviceUser, err)
	}
	uid, err := strconv.Atoi(u.Uid)
	if err != nil {
		return fmt.Errorf("parse uid %q: %w", u.Uid, err)
	}
	gid, err := strconv.Atoi(u.Gid)
	if err != nil {
		return fmt.Errorf("parse gid %q: %w", u.Gid, err)
	}
	for _, p := range paths {
		if err := chownNoFollow(p, uid, gid); err != nil {
			return fmt.Errorf("chown %q: %w", p, err)
		}
	}
	return nil
}

// chownNoFollow changes ownership of path without following a final-component
// symlink OR a hardlink. The service account owns /etc/nocert-sentinel, so
// between writing a file and chowning it a compromised account could swap the
// name for a symlink (a plain os.Chown would follow it) or hardlink the name
// onto a root-owned file (a symlink guard alone would miss it, since a hardlink
// is itself a regular file) and get its ownership handed to the service user.
// Opening O_NOFOLLOW + fchown on the descriptor defeats the symlink; requiring
// the inode to have exactly one link defeats the hardlink; the regular-file
// check refuses a planted directory/device/fifo. The credential files this
// touches are freshly written / package-installed and never legitimately
// hardlinked, so nlink==1 always holds for the real thing.
func chownNoFollow(path string, uid, gid int) error {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	fi, err := f.Stat()
	if err != nil {
		return err
	}
	if !fi.Mode().IsRegular() {
		return fmt.Errorf("%s is not a regular file", path)
	}
	if st, ok := fi.Sys().(*syscall.Stat_t); ok && st.Nlink != 1 {
		return fmt.Errorf("%s has %d hard links; refusing to chown a possibly aliased file", path, st.Nlink)
	}
	return f.Chown(uid, gid)
}

// enforceKeyFileUnderConfigDir applies the key-path confinement only when
// running as root; unprivileged service-mode is unaffected (it can only write
// where it already has access).
func enforceKeyFileUnderConfigDir(configPath, keyFile string) error {
	if os.Geteuid() != 0 {
		return nil
	}
	return checkKeyFileUnderConfigDir(configPath, keyFile)
}

// checkKeyFileUnderConfigDir requires key_file to be a direct child of the
// config directory. filepath.Abs cleans away any ".." traversal; requiring a
// direct child (not just a prefix) also defeats an attacker-planted symlinked
// subdirectory. A symlink AT the key path itself is handled separately by the
// no-follow atomic rename in keystore.Save.
func checkKeyFileUnderConfigDir(configPath, keyFile string) error {
	keyAbs, err := filepath.Abs(keyFile)
	if err != nil {
		return fmt.Errorf("resolving key_file: %w", err)
	}
	cfgAbs, err := filepath.Abs(configPath)
	if err != nil {
		return fmt.Errorf("resolving config path: %w", err)
	}
	cfgDir := filepath.Dir(cfgAbs)
	if filepath.Dir(keyAbs) != cfgDir {
		return fmt.Errorf("key_file %q must be in the config directory %q for a privileged enrollment", keyAbs, cfgDir)
	}
	return nil
}

func resolveEnrollToken(primary, fallback string) string {
	if primary != "" {
		return primary
	}
	return fallback
}

func setupLogger(level, format string) *slog.Logger {
	var lvl slog.Level
	switch level {
	case "debug":
		lvl = slog.LevelDebug
	case "warn":
		lvl = slog.LevelWarn
	case "error":
		lvl = slog.LevelError
	default:
		lvl = slog.LevelInfo
	}

	opts := &slog.HandlerOptions{Level: lvl}

	var handler slog.Handler
	if format == "text" {
		handler = slog.NewTextHandler(os.Stderr, opts)
	} else {
		handler = slog.NewJSONHandler(os.Stderr, opts)
	}

	return slog.New(handler)
}
