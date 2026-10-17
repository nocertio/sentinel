package sentinel

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	commonsentinel "nocert.io/common/pkg/api/sentinel"
	"nocert.io/sentinel/internal/config"
	"nocert.io/sentinel/internal/filesystem"
	"nocert.io/sentinel/internal/keystore"
	"nocert.io/sentinel/internal/kubernetes"
	"nocert.io/sentinel/internal/listeners"
	"nocert.io/sentinel/internal/scanner"
	"nocert.io/sentinel/internal/transport"
	"nocert.io/sentinel/internal/version"
)

const maxRegisterRetries = 5

const (
	batchSize    = 50
	batchTimeout = 30 * time.Second
	// Leave room below the backend's 5 MiB body limit for report framing.
	maxNetworkBatchBytes = 4 << 20
)

// Consecutive credential rejections before the poll loop escalates, then how
// often it repeats the alert. Sized on the default 30s interval: about two
// minutes before the first error, then one reminder every ten minutes.
const (
	credentialAlertAfter  = 5
	credentialAlertRepeat = 20
)

// Sentinel is the top-level orchestrator that ties all components together.
//
// Protocol: the sentinel is a "dumb executor". It runs a single
// polling loop against /tasks; the server lazy-emits periodic sweep tasks
// (network_scan, filesystem_scan), and we dispatch them by type. There is
// no internal cron, no /config fetch - the freshest SentinelConfig comes
// embedded in every TasksResponse.
type Sentinel struct {
	cfg     *config.Config
	store   *keystore.Store
	scanner *scanner.Scanner
	logger  *slog.Logger

	// HTTP transport client (set after registration)
	client *transport.Client

	// Dynamic state (cached scan config)
	mu         sync.RWMutex
	scanConfig transport.SentinelConfig
	hasConfig  bool

	// Prevents concurrent scans (network, filesystem, local and kubernetes are independent).
	scanning      atomic.Bool
	fsScanning    atomic.Bool
	localScanning atomic.Bool
	kubeScanning  atomic.Bool

	// Filesystem scanner
	fsScanner *filesystem.Scanner

	// Kubernetes connector
	kubeScanner *kubernetes.Scanner

	// batchTimeout is how long collectAndPushNetwork waits before flushing a
	// batch (or, when it has nothing to flush, sending a presence heartbeat).
	// Zero falls back to the batchTimeout const; overridable in tests.
	batchTimeout time.Duration

	// credentialFailures counts consecutive polls the backend rejected. Owned by
	// the poll loop, so it needs no lock.
	credentialFailures int
}

func New(cfg *config.Config, logger *slog.Logger) *Sentinel {
	return &Sentinel{
		cfg:          cfg,
		store:        keystore.NewStore(cfg.KeyFile),
		scanner:      scanner.New(logger),
		fsScanner:    filesystem.NewScanner(),
		kubeScanner:  kubernetes.NewScanner(logger),
		logger:       logger,
		batchTimeout: batchTimeout,
	}
}

// Run is the main loop. It handles registration and all background tasks.
// It blocks until the context is cancelled.
func (s *Sentinel) Run(ctx context.Context, registerToken string) error {
	kf, err := s.ensureRegistered(ctx, registerToken)
	if err != nil {
		return fmt.Errorf("registration: %w", err)
	}

	privKey, err := kf.PrivateKeyBytes()
	if err != nil {
		return fmt.Errorf("loading private key: %w", err)
	}
	signingPub, err := kf.SigningPublicKeyBytes()
	if err != nil {
		return fmt.Errorf("loading backend signing public key: %w", err)
	}

	s.client = transport.NewClient(s.cfg.ServerURL, kf.SentinelID, kf.KeyID, privKey, signingPub, kf.SigningKeyID, version.Version, s.logger)

	s.logger.Info("sentinel started",
		"sentinel_id", kf.SentinelID,
		"key_id", kf.KeyID,
		"server", s.cfg.ServerURL,
	)

	// Run both loops under a child context so that if one returns (a fatal
	// error), the other is cancelled too. Drain both before returning so a scan
	// goroutine isn't abandoned mid-report on shutdown.
	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	errc := make(chan error, 2)
	go func() { errc <- s.pollLoop(runCtx) }()
	go func() { errc <- s.keyRotationLoop(runCtx) }()

	select {
	case <-ctx.Done():
		cancel()
		<-errc
		<-errc
		return nil
	case err := <-errc:
		cancel()
		<-errc
		return err
	}
}

// EnrollOnce registers the sentinel and returns immediately, without starting
// the poll and key-rotation loops. Backs the one-shot `--enroll-token` install
// step so enrollment is a command that exits 0, not a foreground process to
// Ctrl+C.
//
// An explicit token means "enroll with THIS token now", so it FORCES a fresh
// registration: any existing key is replaced. Otherwise re-pointing a host at a
// new enrollment would silently keep its old (possibly deleted) identity and
// poll forever with an "unknown sentinel" 401. Service start-up (no token) still
// reuses the existing key via ensureRegistered.
func (s *Sentinel) EnrollOnce(ctx context.Context, token string) error {
	if token == "" {
		return ErrTokenRequired
	}
	if s.store.Exists() {
		if kf, err := s.store.Load(); err == nil {
			s.logger.Warn("re-enrolling: replacing existing credentials", "previous_sentinel_id", kf.SentinelID)
		}
	}
	_, err := s.registerWithToken(ctx, token)
	return err
}

// ErrTokenRequired is returned on a first run with no enrollment token.
var ErrTokenRequired = fmt.Errorf("registration token is required for first run")

// ensureRegistered returns the durable identity for service start-up: the
// existing key when present, otherwise a fresh first-run registration with the
// token. It never REPLACES an existing key - replacing is EnrollOnce's job.
func (s *Sentinel) ensureRegistered(ctx context.Context, token string) (*keystore.KeyFile, error) {
	if s.store.Exists() {
		kf, err := s.store.Load()
		if err != nil {
			return nil, err
		}
		if cur := keystore.CurrentMachineID(); cur != "" && kf.MachineID != "" && kf.MachineID != cur {
			s.logger.Warn("key file belongs to a different machine (cloned image?); discarding and re-enrolling",
				"key_machine_id", kf.MachineID, "host_machine_id", cur)
			kf, err := s.registerWithToken(ctx, token)
			if errors.Is(err, ErrTokenRequired) {
				// A cloned host discarded its foreign key but has no token to re-enroll.
				return nil, fmt.Errorf("cloned host (machine-id changed) needs a re-enrollment token; set NOCERT_ENROLL_TOKEN or enroll_token: %w", err)
			}
			return kf, err
		}
		s.logger.Info("loaded existing credentials", "sentinel_id", kf.SentinelID)
		// In-memory only - the key file is the durable identity, so config.yaml
		// stays the minimal file the operator wrote (never rewritten by the agent).
		s.cfg.SentinelID = kf.SentinelID
		return kf, nil
	}
	return s.registerWithToken(ctx, token)
}

// registerWithToken performs a fresh registration with the token and writes
// (overwriting) the key file. The token is required.
func (s *Sentinel) registerWithToken(ctx context.Context, token string) (*keystore.KeyFile, error) {
	if token == "" {
		return nil, ErrTokenRequired
	}

	s.logger.Info("starting registration")

	privB64, pubB64, err := keystore.GenerateKeyPair()
	if err != nil {
		return nil, err
	}

	resp, err := s.doRegister(ctx, token, pubB64)
	if err != nil {
		return nil, err
	}

	// Adopt the signing keyid from the registration response so the
	// sentinel binds response-signature verification to the keyid the
	// backend actually signs with. Fall back to the platform
	// default only when the backend leaves the field empty.
	signingKeyID := resp.SigningKeyID
	if signingKeyID == "" {
		signingKeyID = keystore.DefaultSigningKeyID
	}

	kf := &keystore.KeyFile{
		SentinelID:       resp.SentinelID,
		KeyID:            resp.KeyID,
		PrivateKey:       privB64,
		PublicKey:        pubB64,
		KeyExpiresAt:     resp.KeyExpiresAt,
		SigningPublicKey: resp.SigningPublicKey,
		SigningKeyID:     signingKeyID,
		MachineID:        keystore.CurrentMachineID(),
	}

	if err := s.store.Save(kf); err != nil {
		return nil, fmt.Errorf("saving key file: %w", err)
	}

	s.logger.Info("registration successful", "sentinel_id", resp.SentinelID, "key_id", resp.KeyID)

	s.cfg.SentinelID = kf.SentinelID // in-memory only; the key file is the durable identity

	return kf, nil
}

func (s *Sentinel) doRegister(ctx context.Context, token, pubKeyB64 string) (*transport.RegisterResponse, error) {
	meta := CollectMetadata(s.cfg.ServerURL)
	regReq := transport.RegisterRequest{
		PublicKey:        pubKeyB64,
		Hostname:         meta.Hostname,
		OS:               meta.OS,
		Arch:             meta.Arch,
		Version:          meta.Version,
		IPAddress:        meta.IPAddress,
		InterfaceSubnets: meta.InterfaceSubnets,
	}

	var lastErr error
	for attempt := range maxRegisterRetries {
		resp, err := transport.Register(ctx, s.cfg.ServerURL, token, regReq)
		if err == nil {
			return resp, nil
		}
		lastErr = err

		// Don't retry client errors (4xx) - only retry on network/server errors
		errMsg := err.Error()
		if strings.Contains(errMsg, "status 4") {
			return nil, err
		}

		delay := 10 * time.Second
		s.logger.Warn("registration failed, retrying",
			"delay", delay,
			"attempt", attempt+1,
			"error", err,
		)

		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(delay):
		}
	}
	return nil, lastErr
}

// pollLoop polls /tasks at the configured interval. Each response carries
// the freshest SentinelConfig (cached in s.scanConfig) and a list of tasks
// to execute. Tasks are dispatched in order; we don't fan out to goroutines
// (the rest of the binary assumes one scan at a time, and the scanning
// guards enforce that anyway).
//
// This is the only loop in the sentinel - no internal scheduler, no
// per-scan ticker. Periodic CIDR/FS sweeps are emitted by the backend as
// regular tasks.
func (s *Sentinel) pollLoop(ctx context.Context) error {
	ticker := time.NewTicker(s.cfg.PollingInterval)
	defer ticker.Stop()

	s.trackPollResult(s.pollOnce(ctx), "initial poll failed")

	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			s.trackPollResult(s.pollOnce(ctx), "poll failed")
		}
	}
}

// trackPollResult logs the outcome of one poll. A backend that rejects our
// credentials is the one failure an operator has to act on: it never recovers
// on its own, so it gets an error carrying the fix instead of blending into the
// warning that every transient blip already produces. Only a poll that goes
// through clears the count, otherwise one flaky proxy timeout mixed into the
// rejections would hold the counter below the threshold forever. Called from
// pollLoop only, which owns credentialFailures.
func (s *Sentinel) trackPollResult(err error, failureMsg string) {
	if err == nil {
		s.credentialFailures = 0
		return
	}
	if !errors.Is(err, transport.ErrCredentialsRejected) {
		s.logger.Warn(failureMsg, "error", err)
		return
	}

	s.credentialFailures++
	if s.credentialFailures < credentialAlertAfter || (s.credentialFailures-credentialAlertAfter)%credentialAlertRepeat != 0 {
		s.logger.Warn(failureMsg, "error", err)
		return
	}
	// The backend does not say which of its reasons applies in a form we can
	// branch on, and the fixes differ, so the log maps each reason to its own.
	s.logger.Error("the backend keeps rejecting this sentinel",
		"error", err,
		"rejected_polls", s.credentialFailures,
		"action", "unknown or replaced sentinel: re-enroll with sudo nocert-sentinel --enroll-token <token>; rejected timestamp: fix this host's clock; inactive sentinel: re-enable it in NoCert",
	)
}

// pollOnce performs a single poll cycle: fetch tasks, cache the embedded
// config, and dispatch each task by type.
func (s *Sentinel) pollOnce(ctx context.Context) error {
	resp, err := s.client.GetTasks(ctx)
	if err != nil {
		return fmt.Errorf("get tasks: %w", err)
	}

	s.applyConfig(resp.Config)

	for _, task := range resp.Tasks {
		if err := s.dispatchTask(ctx, task); err != nil {
			s.logger.Warn("task failed", "task_id", task.ID, "type", task.Type, "error", err)
		}
	}
	return nil
}

// applyConfig caches the freshest org-level scan config under the agent's
// lock. Handlers that need ports / IP ranges read from this cache.
func (s *Sentinel) applyConfig(cfg transport.SentinelConfig) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.scanConfig = cfg
	s.hasConfig = true
}

// dispatchTask routes a task to the appropriate handler. Unknown task
// types are logged and dropped (no failure report - the backend already
// considers it queued; we just don't speak that dialect).
func (s *Sentinel) dispatchTask(ctx context.Context, task transport.TaskResponse) error {
	s.logger.Info("dispatching task", "task_id", task.ID, "type", task.Type)

	switch task.Type {
	case commonsentinel.TaskTypeNetworkScan:
		return s.runNetworkScan(ctx, task)
	case commonsentinel.TaskTypeFilesystemScan:
		return s.runFilesystemScan(ctx, task)
	case commonsentinel.TaskTypeLocalScan:
		return s.runLocalScan(ctx, task)
	case commonsentinel.TaskTypeKubernetesScan:
		return s.runKubernetesScan(ctx, task)
	default:
		s.logger.Warn("unknown task type, dropped", "type", task.Type, "task_id", task.ID)
		return nil
	}
}

// runNetworkScan executes a network_scan task: full CIDR sweep if no
// fqdn, targeted scan otherwise. Ports may be overridden per-task; if
// not, the cached SentinelConfig.Ports apply.
func (s *Sentinel) runNetworkScan(ctx context.Context, task transport.TaskResponse) error {
	if !*s.cfg.AllowNetworkScan {
		// Refused locally - no report. The task was already deleted from
		// the backend pool on claim, and a "failed" report is a no-op
		// there; one report per refused task only causes report bursts.
		s.logger.Warn("network_scan rejected: network scanning is disabled locally", "task_id", task.ID)
		return nil
	}

	var p commonsentinel.NetworkScanPayload
	if len(task.Payload) > 0 {
		if err := json.Unmarshal(task.Payload, &p); err != nil {
			s.reportTask(ctx, task.ID, commonsentinel.ReportStatusFailed)
			return fmt.Errorf("decode network_scan payload: %w", err)
		}
	}

	if len(p.Targets) > 0 {
		s.triggerTargetedScan(ctx, task.ID, p.Targets)
		return nil
	}

	s.mu.RLock()
	cfg := s.scanConfig
	hasConfig := s.hasConfig
	s.mu.RUnlock()

	ports := p.Ports
	if len(ports) == 0 {
		ports = cfg.Ports
	}

	if p.Fqdn != "" {
		if len(ports) == 0 {
			s.logger.Warn("network_scan dropped: no ports configured", "task_id", task.ID, "fqdn", p.Fqdn)
			s.reportTask(ctx, task.ID, commonsentinel.ReportStatusFailed)
			return nil
		}
		s.triggerHostnameScan(ctx, task.ID, p.Fqdn, ports, p.DeepEnum)
		return nil
	}

	if !hasConfig || len(cfg.IPRanges) == 0 {
		s.logger.Warn("network_scan dropped: no IP ranges configured", "task_id", task.ID)
		s.reportTask(ctx, task.ID, commonsentinel.ReportStatusFailed)
		return nil
	}

	s.triggerScan(ctx, task.ID, cfg.IPRanges, ports)
	return nil
}

// runFilesystemScan executes a filesystem_scan task. Payload is currently
// ignored (the backend never emits one); the scan walks the standard FS
// search paths for the detected distro.
func (s *Sentinel) runFilesystemScan(ctx context.Context, task transport.TaskResponse) error {
	if !*s.cfg.AllowFilesystemScan {
		// Refused locally - no report (see runNetworkScan).
		s.logger.Warn("filesystem_scan rejected: filesystem scanning is disabled locally", "task_id", task.ID)
		return nil
	}
	s.triggerFilesystemScan(ctx, task.ID)
	return nil
}

// runLocalScan executes a local_scan task: enumerate the TCP ports listening
// on the sentinel's OWN host and probe each over loopback for a TLS
// certificate. No payload. Refused locally if AllowLocalScan is false.
func (s *Sentinel) runLocalScan(ctx context.Context, task transport.TaskResponse) error {
	if !*s.cfg.AllowLocalScan {
		// Refused locally - no report (see runNetworkScan).
		s.logger.Warn("local_scan rejected: local scanning is disabled locally", "task_id", task.ID)
		return nil
	}
	s.triggerLocalScan(ctx, task.ID)
	return nil
}

// runKubernetesScan executes a kubernetes_scan task: sweep the clusters
// configured in the local config file. No payload. Refused locally if
// AllowKubernetesScan is false.
func (s *Sentinel) runKubernetesScan(ctx context.Context, task transport.TaskResponse) error {
	if !*s.cfg.AllowKubernetesScan {
		// Refused locally - no report (see runNetworkScan).
		s.logger.Warn("kubernetes_scan rejected: kubernetes scanning is disabled locally", "task_id", task.ID)
		return nil
	}
	s.triggerKubernetesScan(ctx, task.ID)
	return nil
}

// kubernetesSweepTimeout bounds an ENTIRE kubernetes sweep (all clusters, all
// list pages), not one request. The sweep runs synchronously in the poll loop,
// so a hostile or stalled API server that never finishes a list would otherwise
// freeze every other scan. Generous versus a real multi-cluster sweep, finite
// so the poll loop always recovers; a sweep cut short reports Complete=false.
const kubernetesSweepTimeout = 10 * time.Minute

// triggerKubernetesScan sweeps all configured clusters and ships the single
// completed report. Concurrent sweeps are coalesced via s.kubeScanning.
func (s *Sentinel) triggerKubernetesScan(ctx context.Context, taskID string) {
	if !s.kubeScanning.CompareAndSwap(false, true) {
		s.logger.Info("kubernetes scan already in progress, skipping", "task_id", taskID)
		if taskID != "" {
			s.reportTask(ctx, taskID, commonsentinel.ReportStatusFailed)
		}
		return
	}
	defer s.kubeScanning.Store(false)

	if len(s.cfg.KubernetesClusters) == 0 {
		// Backend switch is on but this host has no clusters configured: ship
		// a bare completed report that still carries the k8s discriminator
		// (clusters_configured=0), so the backend can record "a sweep ran,
		// zero clusters" instead of an anonymous empty report.
		s.logger.Info("kubernetes_scan: no clusters configured", "task_id", taskID)
		if taskID != "" {
			zero := 0
			report := &transport.ReportRequest{
				TaskID:                       taskID,
				Status:                       commonsentinel.ReportStatusCompleted,
				KubernetesClustersConfigured: &zero,
			}
			if err := s.client.PostReport(ctx, report); err != nil {
				s.logger.Error("failed to report task", "task_id", taskID, "error", err)
			}
		}
		return
	}

	clusters := make([]kubernetes.ClusterSpec, 0, len(s.cfg.KubernetesClusters))
	for _, kc := range s.cfg.KubernetesClusters {
		clusters = append(clusters, kubernetes.ClusterSpec{
			Name: kc.Name, Kubeconfig: kc.Kubeconfig, Context: kc.Context,
			Server: kc.Server, CAFile: kc.CAFile, TokenFile: kc.TokenFile,
		})
	}

	s.mu.RLock()
	opts := kubernetes.SweepOptions{
		IncludeNamespaces: s.scanConfig.KubernetesNamespacesInclude,
		ExcludeNamespaces: s.scanConfig.KubernetesNamespacesExclude,
	}
	s.mu.RUnlock()

	start := time.Now()
	s.logger.Info("starting kubernetes scan", "clusters", len(clusters))
	sweepCtx, cancel := context.WithTimeout(ctx, kubernetesSweepTimeout)
	defer cancel()
	result := s.kubeScanner.Sweep(sweepCtx, clusters, opts)
	if result.Truncated {
		s.logger.Warn("kubernetes sweep truncated at a hard cap; some certificates went unreported",
			"task_id", taskID, "reported_certs", len(result.Certificates))
	}

	if err := s.client.PostReport(ctx, buildKubernetesReport(taskID, result)); err != nil {
		s.logger.Error("failed to push kubernetes report", "task_id", taskID, "error", err)
		return
	}
	s.logger.Info("kubernetes scan complete",
		"task_id", taskID,
		"certs", len(result.Certificates),
		"observations", len(result.Observations),
		"duration", time.Since(start))
}

// buildKubernetesReport turns an aggregated cluster sweep into the single
// completed report, mirroring buildFilesystemReport: buffered, no streaming,
// carrying the per-cluster reconciliation sets. clusters_configured is set
// ONLY here and on the zero-cluster bare report - never by reportTask, which
// is shared by every task type.
func buildKubernetesReport(taskID string, res *kubernetes.SweepResult) *transport.ReportRequest {
	configured := len(res.Sweeps)
	return &transport.ReportRequest{
		TaskID:                       taskID,
		Status:                       commonsentinel.ReportStatusCompleted,
		Certificates:                 res.Certificates,
		KubernetesObservations:       res.Observations,
		KubernetesSweeps:             res.Sweeps,
		KubernetesClustersConfigured: &configured,
	}
}

// sendHeartbeat posts a bare partial report during a long, silent scan so the
// backend's per-request last_seen update keeps the sentinel shown as online.
// It carries no certs or observations and never finalizes the task (partial,
// not completed); presence is refreshed by the auth middleware regardless of
// the empty body. Best-effort: a missed heartbeat only affects the UI badge.
func (s *Sentinel) sendHeartbeat(ctx context.Context, taskID string) {
	report := &transport.ReportRequest{
		TaskID: taskID,
		Status: commonsentinel.ReportStatusPartial,
	}
	if err := s.client.PostReport(ctx, report); err != nil {
		s.logger.Debug("scan heartbeat failed", "task_id", taskID, "error", err)
	}
}

// reportTask sends a bare task-status report (no observations). Used for
// failure paths and final completion when the channel produced nothing.
func (s *Sentinel) reportTask(ctx context.Context, taskID, status string) {
	report := &transport.ReportRequest{
		TaskID: taskID,
		Status: status,
	}
	if err := s.client.PostReport(ctx, report); err != nil {
		s.logger.Error("failed to report task", "task_id", taskID, "error", err)
	}
}

func localScanCompletionReport(taskID string, keys map[string]commonsentinel.LocalListenerKey, complete bool) *transport.ReportRequest {
	report := &transport.ReportRequest{
		TaskID:            taskID,
		Status:            commonsentinel.ReportStatusCompleted,
		LocalScanComplete: complete,
	}
	if !complete || len(keys) == 0 {
		return report
	}

	report.LocalListenerKeys = make([]commonsentinel.LocalListenerKey, 0, len(keys))
	for _, key := range keys {
		report.LocalListenerKeys = append(report.LocalListenerKeys, key)
	}
	sort.Slice(report.LocalListenerKeys, func(i, j int) bool {
		if report.LocalListenerKeys[i].IP == report.LocalListenerKeys[j].IP {
			return report.LocalListenerKeys[i].Port < report.LocalListenerKeys[j].Port
		}
		return report.LocalListenerKeys[i].IP < report.LocalListenerKeys[j].IP
	})
	return report
}

// collectAndPushNetwork drains a network probe-output channel, computes
// SHA-256 fingerprints, deduplicates certificates within each batch, and
// pushes batches as ReportRequest{Certificates, NetworkObservations}.
//
// When local is true the observations are carried in the LocalObservations
// slice instead (local_scan task). The probe-output shape is identical; only
// the report slice differs.
func (s *Sentinel) collectAndPushNetwork(ctx context.Context, resultCh <-chan scanner.ProbeOutput, taskID string, meta *scanner.ScanMeta, local, localEnumerationComplete bool) {
	scanTaskID := taskID
	if scanTaskID == "" {
		scanTaskID = meta.ScanID
	}

	var (
		batchCerts         []transport.Certificate
		batchObservations  []transport.SentinelNetworkObservation
		seenCerts          = make(map[string]bool)
		localKeys          = make(map[string]commonsentinel.LocalListenerKey)
		allBatchesAccepted = true
		batchBytes         int
	)

	resetBatch := func() {
		batchCerts = nil
		batchObservations = nil
		seenCerts = make(map[string]bool)
		batchBytes = 0
	}

	bt := s.batchTimeout
	if bt <= 0 {
		bt = batchTimeout
	}
	timer := time.NewTimer(bt)
	defer timer.Stop()

	pushBatch := func() {
		if len(batchObservations) == 0 && len(batchCerts) == 0 {
			return
		}

		report := &transport.ReportRequest{
			TaskID:       scanTaskID,
			Status:       commonsentinel.ReportStatusPartial,
			Certificates: batchCerts,
		}
		if local {
			report.LocalObservations = batchObservations
		} else {
			report.NetworkObservations = batchObservations
		}

		if err := s.client.PostReport(ctx, report); err != nil {
			s.logger.Error("failed to push batch", "error", err, "observations", len(batchObservations), "certs", len(batchCerts))
			allBatchesAccepted = false
		} else {
			s.logger.Debug("pushed batch", "observations", len(batchObservations), "certs", len(batchCerts))
		}

		resetBatch()
	}

	observationCount := 0

	for {
		select {
		case out, ok := <-resultCh:
			if !ok {
				pushBatch()

				report := &transport.ReportRequest{TaskID: scanTaskID, Status: commonsentinel.ReportStatusCompleted}
				if local {
					report = localScanCompletionReport(
						scanTaskID,
						localKeys,
						allBatchesAccepted && localEnumerationComplete && ctx.Err() == nil,
					)
				}
				if err := s.client.PostReport(ctx, report); err != nil {
					s.logger.Error("failed to send scan completion", "error", err)
				}

				scanType := "network"
				if local {
					scanType = "local"
				}
				s.logger.Info("scan complete",
					"scan_id", meta.ScanID,
					"type", scanType,
					"observations", observationCount,
					"duration", time.Since(meta.StartedAt),
				)
				return
			}

			fps := make([]string, 0, len(out.Chain))
			for _, der := range out.Chain {
				fps = append(fps, scanner.Fingerprint(der))
			}
			if len(fps) == 0 {
				continue
			}

			observation := transport.SentinelNetworkObservation{
				IP:                        out.IP,
				Port:                      out.Port,
				SNI:                       out.SNI,
				ObservedChainFingerprints: fps,
				TLS:                       out.TLS,
			}
			encoded, _ := json.Marshal(observation)
			outputBytes := len(encoded) + 1
			for _, der := range out.Chain {
				// Count shared certificates again for a conservative budget. This
				// remains valid when a flush resets the per-batch deduplication.
				outputBytes += base64.StdEncoding.EncodedLen(len(der)) + 128
			}
			if outputBytes > maxNetworkBatchBytes {
				s.logger.Error("probe output exceeds report budget", "task_id", scanTaskID)
				allBatchesAccepted = false
				continue
			}
			if batchBytes+outputBytes > maxNetworkBatchBytes {
				pushBatch()
			}
			for i, der := range out.Chain {
				fp := fps[i]
				if !seenCerts[fp] {
					seenCerts[fp] = true
					batchCerts = append(batchCerts, transport.Certificate{FingerprintSHA256: fp, DER: der})
				}
			}
			batchObservations = append(batchObservations, observation)
			batchBytes += outputBytes
			if local {
				key := fmt.Sprintf("%s\x00%d", out.IP, out.Port)
				localKeys[key] = commonsentinel.LocalListenerKey{IP: out.IP, Port: out.Port}
			}
			observationCount++

			if len(batchObservations) >= batchSize {
				pushBatch()
				if !timer.Stop() {
					select {
					case <-timer.C:
					default:
					}
				}
				timer.Reset(bt)
			}

		case <-timer.C:
			if len(batchObservations) == 0 && len(batchCerts) == 0 {
				// Nothing to flush, but a long silent sweep (e.g. a large
				// firewalled CIDR range yielding no TLS endpoint for many
				// minutes) would otherwise send no signed request at all, and
				// the UI would show the sentinel offline while it is working.
				// A bare signed report refreshes last_seen via the auth
				// middleware, before the backend even parses the body.
				s.sendHeartbeat(ctx, scanTaskID)
			} else {
				pushBatch()
			}
			timer.Reset(bt)

		case <-ctx.Done():
			return
		}
	}
}

// buildFilesystemReport turns an aggregated filesystem sweep into the single
// completed report. The sweep is buffered and small (dozens of certs), so it
// is sent in one report - no streaming, no batching. The report carries the
// scan-complete flag and the full discovered-fingerprint set the backend
// uses to reconcile vanished findings.
func buildFilesystemReport(taskID string, res *filesystem.FSScanResult) *transport.ReportRequest {
	fps := make([]string, 0, len(res.Observations))
	for _, o := range res.Observations {
		fps = append(fps, o.FingerprintSHA256)
	}
	return &transport.ReportRequest{
		TaskID:                 taskID,
		Status:                 commonsentinel.ReportStatusCompleted,
		Certificates:           res.Certificates,
		FilesystemObservations: res.Observations,
		FilesystemScanComplete: res.Complete,
		FilesystemFingerprints: fps,
	}
}

const (
	defaultScanTimeout = 5 * time.Second
	// localScanTimeout is shorter than the network budget: loopback handshakes
	// complete in milliseconds, so a stalled local port shouldn't hold a worker
	// for the full WAN timeout (keeps the worst-case local sweep short).
	localScanTimeout = 2 * time.Second
)

// triggerScan runs a full CIDR sweep with the supplied ranges and ports.
// Concurrent scans are coalesced via s.scanning.
func (s *Sentinel) triggerScan(ctx context.Context, taskID string, ipRanges []string, ports []int) {
	if !*s.cfg.AllowNetworkScan {
		return
	}

	if !s.scanning.CompareAndSwap(false, true) {
		s.logger.Info("scan already in progress, skipping", "task_id", taskID)
		if taskID != "" {
			s.reportTask(ctx, taskID, commonsentinel.ReportStatusFailed)
		}
		return
	}
	defer s.scanning.Store(false)

	cfg := scanner.ScanConfig{
		IPRanges: ipRanges,
		Ports:    ports,
		Timeout:  defaultScanTimeout,
	}

	resultCh, meta := s.scanner.ScanStream(ctx, cfg)
	s.collectAndPushNetwork(ctx, resultCh, taskID, meta, false, false)
}

// triggerHostnameScan runs a single-target scan against an FQDN. The
// scanner package handles the FQDN -> probe path; we just delegate.
// deepEnum=true asks the scanner to also perform TLS cipher
// enumeration after the fast probe.
func (s *Sentinel) triggerHostnameScan(ctx context.Context, taskID, fqdn string, ports []int, deepEnum bool) {
	if !*s.cfg.AllowNetworkScan {
		return
	}

	if !s.scanning.CompareAndSwap(false, true) {
		s.logger.Info("scan already in progress, skipping", "task_id", taskID, "fqdn", fqdn)
		if taskID != "" {
			s.reportTask(ctx, taskID, commonsentinel.ReportStatusFailed)
		}
		return
	}
	defer s.scanning.Store(false)

	resultCh, meta := s.scanner.ScanHostname(ctx, fqdn, ports, defaultScanTimeout, deepEnum)
	s.collectAndPushNetwork(ctx, resultCh, taskID, meta, false, false)
}

// triggerTargetedScan probes the exact (ip, port, sni) targets from the task
// payload with deep enum, bypassing CIDR expansion - the backend already
// resolved this scope from an earlier discovery (closed-loop verification of
// a specific endpoint), so the sentinel executes it rather than deciding it.
func (s *Sentinel) triggerTargetedScan(ctx context.Context, taskID string, specs []commonsentinel.TargetSpec) {
	if !*s.cfg.AllowNetworkScan {
		return
	}

	if !s.scanning.CompareAndSwap(false, true) {
		s.logger.Info("scan already in progress, skipping", "task_id", taskID)
		if taskID != "" {
			s.reportTask(ctx, taskID, commonsentinel.ReportStatusFailed)
		}
		return
	}
	defer s.scanning.Store(false)

	targets := make([]scanner.Target, 0, len(specs))
	for _, spec := range specs {
		targets = append(targets, scanner.Target{Host: spec.IP, Port: spec.Port, ServerName: spec.SNI})
	}

	resultCh, meta := s.scanner.ScanTargets(ctx, targets, defaultScanTimeout)
	s.collectAndPushNetwork(ctx, resultCh, taskID, meta, false, false)
}

// triggerLocalScan enumerates the host's listening ports and probes each over
// loopback. Concurrent local scans are coalesced via s.localScanning.
func (s *Sentinel) triggerLocalScan(ctx context.Context, taskID string) {
	if !*s.cfg.AllowLocalScan {
		return
	}

	if !s.localScanning.CompareAndSwap(false, true) {
		s.logger.Info("local scan already in progress, skipping", "task_id", taskID)
		if taskID != "" {
			s.reportTask(ctx, taskID, commonsentinel.ReportStatusFailed)
		}
		return
	}
	defer s.localScanning.Store(false)

	found, enumerationComplete := listeners.Enumerate()
	s.logger.Info("starting local scan", "listeners", len(found), "enumeration_complete", enumerationComplete)
	if len(found) == 0 {
		// Only an authoritative empty enumeration may remove every previous
		// observation. A missing/truncated /proc view stays additive-only.
		if taskID != "" {
			if err := s.client.PostReport(ctx, localScanCompletionReport(
				taskID,
				map[string]commonsentinel.LocalListenerKey{},
				enumerationComplete && ctx.Err() == nil,
			)); err != nil {
				s.logger.Error("failed to send empty local scan completion", "task_id", taskID, "error", err)
			}
		}
		return
	}

	targets := make([]scanner.LocalTarget, 0, len(found))
	for _, l := range found {
		targets = append(targets, scanner.LocalTarget{Host: l.Host, Port: l.Port})
	}

	resultCh, meta := s.scanner.ScanLocalListeners(ctx, targets, localScanTimeout)
	s.collectAndPushNetwork(ctx, resultCh, taskID, meta, true, enumerationComplete)
}

func (s *Sentinel) triggerFilesystemScan(ctx context.Context, taskID string) {
	if !s.fsScanning.CompareAndSwap(false, true) {
		s.logger.Info("filesystem scan already in progress, skipping", "task_id", taskID)
		if taskID != "" {
			s.reportTask(ctx, taskID, commonsentinel.ReportStatusFailed)
		}
		return
	}
	defer s.fsScanning.Store(false)

	start := time.Now()
	certDirs := filesystem.SearchPaths()
	s.logger.Info("starting filesystem scan", "cert_dirs", len(certDirs))

	result := s.fsScanner.Discover(ctx, certDirs, "/etc")
	if result.Truncated {
		s.logger.Warn("filesystem sweep truncated at a hard cap; some certificates on this host went unreported",
			"task_id", taskID,
			"reported_certs", len(result.Observations))
	}

	if err := s.client.PostReport(ctx, buildFilesystemReport(taskID, result)); err != nil {
		s.logger.Error("failed to push filesystem report", "task_id", taskID, "error", err)
		return
	}

	s.logger.Info("filesystem scan complete",
		"task_id", taskID,
		"certs", len(result.Observations),
		"complete", result.Complete,
		"duration", time.Since(start))
}

// keyRotationLoop checks periodically if the key needs rotation.
func (s *Sentinel) keyRotationLoop(ctx context.Context) error {
	ticker := time.NewTicker(s.cfg.KeyRotationCheckInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			s.checkKeyRotation(ctx)
		}
	}
}

func (s *Sentinel) checkKeyRotation(ctx context.Context) {
	kf, err := s.store.Load()
	if err != nil {
		s.logger.Error("failed to load key file for rotation check", "error", err)
		return
	}

	if !kf.NeedsRotation(s.cfg.KeyRotationMargin) {
		return
	}

	s.logger.Info("key rotation needed", "expires_at", kf.KeyExpiresAt)

	newPrivB64, newPubB64, err := keystore.GenerateKeyPair()
	if err != nil {
		s.logger.Error("failed to generate new key pair", "error", err)
		return
	}

	resp, err := s.client.RotateKey(ctx, newPubB64)
	if err != nil {
		s.logger.Error("key rotation request failed", "error", err)
		return
	}

	kf.PrivateKey = newPrivB64
	kf.PublicKey = newPubB64
	kf.KeyID = resp.KeyID
	kf.KeyExpiresAt = resp.KeyExpiresAt

	if err := s.store.Save(kf); err != nil {
		s.logger.Error("failed to save rotated key file", "error", err)
		return
	}

	newPriv, err := kf.PrivateKeyBytes()
	if err != nil {
		s.logger.Error("failed to decode new private key", "error", err)
		return
	}
	s.client.UpdateCredentials(resp.KeyID, newPriv)

	s.logger.Info("key rotation successful", "new_key_id", resp.KeyID, "expires_at", resp.KeyExpiresAt)
}
