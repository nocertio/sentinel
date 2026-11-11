package sentinel

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"time"

	commonsentinel "nocert.io/common/pkg/api/sentinel"
	"nocert.io/sentinel/internal/keystore"
	"nocert.io/sentinel/internal/scanner"
	"nocert.io/sentinel/internal/transport"
)

// Owned by the poll loop. A periodic task authorizes a traversal; later tasks
// for the same scope coalesce without restarting it.
type networkSweep struct {
	scope             *scanner.Scope
	taskID            string
	configFingerprint string
	checkpoint        sweepCheckpoint
	retryAfter        time.Time
}

type sweepCheckpoint struct {
	Scope string `json:"scope"`
	Next  int    `json:"next"`
}

func (s *Sentinel) scopeIdentity(scope *scanner.Scope) string {
	sum := sha256.Sum256([]byte(s.cfg.ServerURL + "\x00" + s.sentinelID + "\x00" + keystore.CurrentMachineID() + "\x00" + scope.Fingerprint()))
	return hex.EncodeToString(sum[:])
}

func (s *Sentinel) checkpointPath() string {
	if s.cfg.KeyFile == "" {
		return ""
	}
	return s.cfg.KeyFile + ".scan-progress.json"
}

func (s *Sentinel) loadSweepCheckpoint(scope *scanner.Scope) sweepCheckpoint {
	cp := sweepCheckpoint{Scope: s.scopeIdentity(scope)}
	f, err := os.Open(s.checkpointPath())
	if err != nil {
		return cp
	}
	defer f.Close()
	var saved sweepCheckpoint
	// Corrupt, oversized or obsolete progress only causes a fresh traversal.
	data, err := io.ReadAll(io.LimitReader(f, 1025))
	if err == nil && len(data) <= 1024 && json.Unmarshal(data, &saved) == nil && saved.Scope == cp.Scope && saved.Next >= 0 && saved.Next < scope.TotalTargets() {
		cp.Next = saved.Next
	}
	return cp
}

func (s *Sentinel) saveSweepCheckpoint(cp sweepCheckpoint) {
	path := s.checkpointPath()
	if path == "" {
		return
	}
	err := writeSweepCheckpoint(path, cp)
	if err != nil && !s.checkpointFailed {
		s.logger.Warn("scan progress could not be saved; restart may repeat completed probes")
	}
	s.checkpointFailed = err != nil
}

func writeSweepCheckpoint(path string, cp sweepCheckpoint) error {
	data, err := json.Marshal(cp)
	if err != nil {
		return err
	}
	f, err := os.CreateTemp(filepath.Dir(path), ".scan-progress-*.tmp")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if _, err = f.Write(data); err != nil {
		_ = f.Close()
		return err
	}
	if err = f.Sync(); err != nil {
		_ = f.Close()
		return err
	}
	if err = f.Close(); err != nil {
		return err
	}
	return os.Rename(f.Name(), path)
}

func (s *Sentinel) queueNetworkSweep(ctx context.Context, taskID string, ranges []string, ports []int) {
	scope, err := scanner.NewScope(ranges, ports)
	if err != nil || scope.TotalTargets() == 0 {
		s.reportTask(ctx, taskID, commonsentinel.ReportStatusFailed)
		return
	}
	if s.sweep != nil && s.sweep.scope.Fingerprint() == scope.Fingerprint() {
		return
	}
	cfgScope, err := scanner.NewScope(s.scanConfig.IPRanges, s.scanConfig.Ports)
	if err != nil {
		s.reportTask(ctx, taskID, commonsentinel.ReportStatusFailed)
		return
	}
	s.sweep = &networkSweep{scope: scope, taskID: taskID, configFingerprint: cfgScope.Fingerprint(), checkpoint: s.loadSweepCheckpoint(scope)}
	s.logger.Info("network sweep queued", "task_id", taskID, "targets", scope.TotalTargets(), "resume_at", s.sweep.checkpoint.Next)
}

// Yield after one worker wave. Failed reports retry no sooner than the next
// polling interval; the cursor never moves past unacknowledged observations.
func (s *Sentinel) runSweepBatch(ctx context.Context) {
	sweep := s.sweep
	if sweep == nil || !*s.cfg.AllowNetworkScan || !s.scanning.CompareAndSwap(false, true) {
		return
	}
	defer s.scanning.Store(false)
	accepted := true
	if sweep.checkpoint.Next < sweep.scope.TotalTargets() {
		ch, meta := s.scanner.ScanScopeBatch(ctx, sweep.scope, sweep.checkpoint.Next)
		meta.More = true
		accepted = s.collectAndPushNetwork(ctx, ch, sweep.taskID, meta, false, false)
		if ctx.Err() != nil {
			for range ch {
			}
		}
		if accepted {
			sweep.checkpoint.Next += meta.TotalTargets
			s.saveSweepCheckpoint(sweep.checkpoint)
		}
	}
	if accepted && ctx.Err() == nil && sweep.checkpoint.Next == sweep.scope.TotalTargets() {
		err := s.client.PostReport(ctx, &transport.ReportRequest{TaskID: sweep.taskID, Status: commonsentinel.ReportStatusCompleted})
		if err == nil {
			s.saveSweepCheckpoint(sweepCheckpoint{Scope: sweep.checkpoint.Scope})
			s.logger.Info("network sweep complete", "task_id", sweep.taskID, "targets", sweep.scope.TotalTargets())
			s.sweep = nil
			return
		}
		accepted = false
	}
	if !accepted {
		delay := s.cfg.PollingInterval
		if delay <= 0 {
			delay = 30 * time.Second
		}
		sweep.retryAfter = time.Now().Add(delay)
	}
}

func (s *Sentinel) reconcileSweepConfig(cfg transport.SentinelConfig) {
	if s.sweep == nil {
		return
	}
	scope, err := scanner.NewScope(cfg.IPRanges, cfg.Ports)
	if err == nil && scope.Fingerprint() == s.sweep.configFingerprint {
		return
	}
	// A changed scope needs a fresh backend task. Never resume old destinations
	// simply because they were recorded in a local progress file.
	s.saveSweepCheckpoint(sweepCheckpoint{})
	s.sweep = nil
}
