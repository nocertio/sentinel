package scanner

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"log/slog"
	"slices"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	commonsentinel "nocert.io/common/pkg/api/sentinel"
	"nocert.io/common/pkg/tlsconst"
	"nocert.io/common/pkg/tlsenum"
	"nocert.io/common/pkg/tlsprobe"
	"nocert.io/sentinel/internal/transport"
)

const (
	// MaxTotalTargets bounds explicit target lists; CIDR scopes stream lazily.
	MaxTotalTargets = 100_000

	// MaxSNIReprobesPerTarget caps the number of SNI re-probes per IP:port.
	// CDN certs can have 100+ SANs; re-probing all is wasteful.
	MaxSNIReprobesPerTarget = 50

	// Defaults for concurrent execution
	DefaultWorkers       = 50
	DefaultMaxConnPerSec = 100

	// deepEnumOverallTimeout bounds one cipher enumeration (hundreds of
	// sequential handshakes) so a single slow host can't monopolize the
	// sequential scan.
	deepEnumOverallTimeout = 60 * time.Second
)

// ScanConfig defines the parameters for a network scan.
type ScanConfig struct {
	batch         bool
	gentle        bool
	IPRanges      []string
	Ports         []int
	Timeout       time.Duration
	Workers       int // max concurrent TLS workers, default 50
	MaxConnPerSec int // max new connections per second, default 100
	// DeepEnum, when true, asks the scanner to run TLS cipher enumeration
	// after each successful fast probe. The findings are server-level
	// (independent of the cert presented), so they are attached to every
	// ProbeOutput emitted from the same (host, port). Only honoured for
	// targeted scans - full CIDR sweeps ignore this flag.
	DeepEnum bool
	// Targets, when non-empty, is used as the exact probe set and bypasses
	// CIDR expansion (IPRanges/Ports are ignored). Used by the local_scan
	// path, which feeds the host's own listening (loopback/host-local)
	// sockets directly, and by ScanTargets, which feeds a backend-supplied
	// network_scan targets[] list.
	Targets []target
	// SkipSNIReprobe disables the per-SAN SNI re-probe. Set by both the
	// local_scan path, to keep probing inert (one ClientHello per discovered
	// listener, no extra connections to the host's own services), and by
	// ScanTargets, since the backend already named the exact endpoints it
	// wants observed.
	SkipSNIReprobe bool
}

// target is a single IP:port to probe. serverName is the explicit SNI to send:
// ScanHostname sets it to the FQDN so virtual-hosted endpoints serve the right
// certificate and the emitted observation records that SNI. ScanTargets sets
// it from the backend-supplied Target.ServerName (may be empty). CIDR and
// local scans leave it empty (no SNI on an IP literal).
type target struct {
	host       string
	port       int
	serverName string
}

// ScanMeta contains metadata about a scan returned synchronously by ScanStream.
type ScanMeta struct {
	// More suppresses task completion while a bounded scope batch is collected.
	More         bool
	ScanID       string
	StartedAt    time.Time
	TotalTargets int
}

// ProbeOutput is the streaming unit produced by a network scan: one
// fully-observed (IP, port, sni?) handshake. Chain holds the raw DER
// bytes presented during the handshake in the order received (leaf
// first). The downstream collector computes SHA-256 fingerprints and
// deduplicates per batch before assembling the wire-level
// Certificates / NetworkObservations split.
type ProbeOutput struct {
	IP    string
	Port  int
	SNI   string
	Chain [][]byte
	TLS   *transport.TLSObservation
}

// ScanResult contains the aggregated output of a network scan: the
// deduplicated cert blobs plus the observations that link to them by
// fingerprint. This is the in-memory view used by the convenience
// `Scan` wrapper; the streaming `ScanStream` API is what the agent
// actually consumes.
type ScanResult struct {
	ScanID              string
	StartedAt           time.Time
	CompletedAt         time.Time
	Certificates        []transport.Certificate
	NetworkObservations []transport.SentinelNetworkObservation
	TotalTargets        int
}

// Prober abstracts the TLS probing for testing.
type Prober interface {
	Probe(ctx context.Context, host string, port int, timeout time.Duration, serverName string) (*tlsprobe.Result, error)
}

// Scanner discovers TLS certificates on the network.
type Scanner struct {
	hosts  hostBudget
	gentle atomic.Bool
	logger *slog.Logger
	prober Prober
}

func New(logger *slog.Logger) *Scanner {
	s := &Scanner{logger: logger}
	s.prober = &tlsProber{logger: logger}
	return s
}

// NewWithProber creates a scanner with a custom prober (for testing).
func NewWithProber(logger *slog.Logger, prober Prober) *Scanner {
	return &Scanner{logger: logger, prober: prober}
}

// SetGentle applies the centrally selected profile to subsequent scans.
func (s *Scanner) SetGentle(enabled bool) { s.gentle.Store(enabled) }

func (s *Scanner) applyProfile(cfg *ScanConfig) {
	cfg.gentle = s.gentle.Load()
	if cfg.gentle {
		cfg.Workers = 5
		cfg.MaxConnPerSec = 5
		cfg.Timeout = 10 * time.Second
		cfg.DeepEnum = false
		cfg.SkipSNIReprobe = true
	}
}

func (s *Scanner) dialer(ticks <-chan time.Time, gentle bool) *scanDialer {
	gap := time.Duration(0)
	if gentle {
		gap = time.Second
	}
	return &scanDialer{hosts: &s.hosts, ticks: ticks, gap: gap}
}

// ScanStream starts a concurrent scan and returns a channel of probe
// outputs plus metadata. The caller must drain the returned channel.
// Probe outputs are streamed as they are observed; certificate
// fingerprinting and dedup happens downstream in the collector.
func (s *Scanner) ScanStream(ctx context.Context, cfg ScanConfig) (<-chan ProbeOutput, *ScanMeta) {
	s.applyProfile(&cfg)
	// Apply defaults
	if cfg.Timeout <= 0 {
		cfg.Timeout = 5 * time.Second
	}
	workers := cfg.Workers
	if workers <= 0 {
		workers = DefaultWorkers
	}
	maxConn := cfg.MaxConnPerSec
	if maxConn <= 0 {
		maxConn = DefaultMaxConnPerSec
	}

	var targets []target
	var scope *Scope
	var total int
	if len(cfg.Targets) > 0 {
		targets = interleaveTargets(cfg.Targets)
		if len(targets) > MaxTotalTargets {
			s.logger.Warn("explicit scan scope truncated", "limit", MaxTotalTargets)
			targets = targets[:MaxTotalTargets]
		}
		total = len(targets)
	} else {
		var err error
		scope, err = NewScope(cfg.IPRanges, cfg.Ports)
		if err != nil {
			s.logger.Warn("invalid scan scope", "error", err)
		} else {
			total = scope.TotalTargets()
		}
	}
	resultCh := make(chan ProbeOutput, workers*2)
	targetCh := make(chan target, workers*2)

	meta := &ScanMeta{
		ScanID:       generateScanID(),
		StartedAt:    time.Now().UTC(),
		TotalTargets: total,
	}

	if cfg.batch {
		s.logger.Debug("starting scan batch", "scan_id", meta.ScanID, "targets", total)
	} else {
		s.logger.Info("starting scan", "scan_id", meta.ScanID, "targets", total, "workers", workers)
	}

	// Rate limiter shared by all workers
	interval := time.Second / time.Duration(maxConn)
	if interval <= 0 {
		interval = time.Millisecond
	}
	rateTicker := time.NewTicker(interval)

	// Scheduler goroutine: dispatches targets (no rate limiting)
	go func() {
		defer close(targetCh)
		for i := 0; i < total; i++ {
			if ctx.Err() != nil {
				return
			}
			var tgt target
			if scope != nil {
				tgt = scope.targetAt(i)
			} else {
				tgt = targets[i]
			}
			select {
			case targetCh <- tgt:
			case <-ctx.Done():
				return
			}
		}
	}()

	// Worker goroutines
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case tgt, ok := <-targetCh:
					if !ok {
						return
					}
					s.probeTarget(ctx, tgt, cfg, resultCh, rateTicker)
				case <-ctx.Done():
					return
				}
			}
		}()
	}

	// Closer goroutine: waits for all workers then closes resultCh
	go func() {
		wg.Wait()
		rateTicker.Stop()
		close(resultCh)
	}()

	return resultCh, meta
}

// probeTarget probes a single target and sends results to resultCh.
// Errors are logged at Debug level and not collected.
func (s *Scanner) probeTarget(ctx context.Context, tgt target, cfg ScanConfig, resultCh chan<- ProbeOutput, rateTicker *time.Ticker) {
	prober := s.prober
	if p, ok := prober.(*tlsProber); ok {
		prober = &tlsProber{logger: p.logger, dialer: s.dialer(rateTicker.C, cfg.gentle)}
	}
	probe := func(name string) (*tlsprobe.Result, error) {
		if _, ok := prober.(*tlsProber); !ok {
			select {
			case <-rateTicker.C:
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		}
		return prober.Probe(ctx, tgt.host, tgt.port, cfg.Timeout, name)
	}
	probeResult, err := probe(tgt.serverName)
	if err != nil {
		s.logger.Debug("probe failed", "host", tgt.host, "port", tgt.port, "error", err)
		return
	}

	// Enumeration is pinned to the first peer and SNI. Re-probes of other
	// virtual hosts must not inherit its findings.
	enumSNI := tgt.serverName
	if probeResult.ObservedServerName != nil {
		enumSNI = *probeResult.ObservedServerName
	}
	if enumSNI == "" {
		enumSNI = probeResult.PeerIP
	}
	var (
		enumFindings  []commonsentinel.CipherFinding
		enumAttempted bool
	)
	if cfg.DeepEnum {
		enumFindings, enumAttempted = s.runCipherEnum(ctx, enumSNI, probeResult.PeerIP, tgt.port, cfg.Timeout, rateTicker)
		if probeResult.TLS != nil {
			pinned, err := tlsprobe.NewPinnedDialer(s.dialer(rateTicker.C, false), probeResult.PeerIP)
			if err == nil {
				dialer := upgradeDialer{base: pinned}
				for _, legacy := range tlsenum.CollectObsolete(ctx, probeResult.PeerIP, tgt.port, tlsenum.Options{DisableALPN: true, Dialer: dialer, HandshakeTimeout: cfg.Timeout}) {
					probeResult.TLS.SupportedProtocolIDs = append(probeResult.TLS.SupportedProtocolIDs, legacy.Version)
					if len(legacy.SSL2Ciphers) > 0 {
						probeResult.TLS.SSL2CipherSpecs = legacy.SSL2Ciphers
					}
				}
			}
		}
	}

	out := s.probeResultToOutput(tgt.port, tgt.serverName, probeResult, enumFindings, enumAttempted)
	if out == nil {
		return
	}
	if cfg.DeepEnum && out.TLS != nil {
		out.TLS.DeepEnumFailed = !enumAttempted
	}
	select {
	case resultCh <- *out:
	case <-ctx.Done():
		return
	}

	// SNI re-probing
	if !cfg.SkipSNIReprobe && len(probeResult.PeerCerts) > 0 {
		leaf := probeResult.PeerCerts[0]
		seen := map[string]bool{
			resultFingerprint(probeResult): true,
		}
		reprobes := 0

		reprobeWith := func(sni string) {
			sniResult, err := probe(sni)
			if err != nil {
				return
			}
			if seen[resultFingerprint(sniResult)] {
				return
			}
			seen[resultFingerprint(sniResult)] = true

			// Do NOT inherit the primary SNI's enumeration. This reprobe selected a
			// DIFFERENT certificate, which can be a different vhost with a different
			// TLS policy (per-server_name ssl_ciphers/ssl_protocols), so the primary's
			// cipher findings may not characterise this endpoint. Emit with no enum
			// evidence (nil/false); the backend's targeted per-(host,port,SNI) DeepEnum
			// fills it in authoritatively. A brief gap beats attributing wrong evidence.
			sd := s.probeResultToOutput(tgt.port, sni, sniResult, nil, false)
			if sd == nil {
				return
			}
			select {
			case resultCh <- *sd:
			case <-ctx.Done():
				return
			}
		}

		for _, san := range leaf.DNSNames {
			if reprobes >= MaxSNIReprobesPerTarget || ctx.Err() != nil {
				break
			}
			if strings.HasPrefix(san, "*") {
				continue
			}
			reprobes++
			reprobeWith(san)
		}
	}
}

// probeResultToOutput preserves raw certificates or positive protocol evidence.
// The reported address is always the actual TCP peer, never an input hostname.
func (s *Scanner) probeResultToOutput(port int, sni string, result *tlsprobe.Result, enumFindings []commonsentinel.CipherFinding, enumAttempted bool) *ProbeOutput {
	if result == nil {
		return nil
	}
	if result.PeerIP == "" {
		return nil
	}
	out := &ProbeOutput{
		IP:    result.PeerIP,
		Port:  port,
		SNI:   sni,
		Chain: make([][]byte, 0, 1+len(result.Chain)),
	}
	if result.ObservedServerName != nil {
		out.SNI = *result.ObservedServerName
	}
	if len(result.RawChain) > 0 {
		out.Chain = result.RawChain
	} else if result.Certificate != nil && len(result.Certificate.RawDER) > 0 {
		out.Chain = append(out.Chain, result.Certificate.RawDER)
		for _, ce := range result.Chain {
			if len(ce.RawDER) > 0 && !bytes.Equal(ce.RawDER, result.Certificate.RawDER) {
				out.Chain = append(out.Chain, ce.RawDER)
			}
		}
	} else if result.TLS == nil || result.TLS.TLSVersionID == nil {
		return nil
	}
	if result.TLS != nil || enumAttempted {
		out.TLS = &transport.TLSObservation{}
		var negotiatedVersion string
		if result.TLS != nil {
			out.TLS.HandshakeComplete = result.TLS.HandshakeComplete
			out.TLS.DHBits = result.TLS.DHBits
			out.TLS.SSL2CipherSpecs = result.TLS.SSL2CipherSpecs
			checked := false
			out.TLS.HSTSChecked = &checked
			out.TLS.TLSVersion = result.TLS.TLSVersion
			out.TLS.TLSVersionID = result.TLS.TLSVersionID
			out.TLS.CipherSuiteID = result.TLS.CipherSuiteID
			out.TLS.NegotiatedGroupID = result.TLS.NegotiatedGroupID
			out.TLS.CipherSuite = result.TLS.CipherSuite
			out.TLS.NegotiatedGroup = result.TLS.NegotiatedGroup
			out.TLS.OCSPStapling = result.TLS.OCSPStapling
			out.TLS.HSTSEnabled = result.TLS.HSTSEnabled
			out.TLS.HSTSMaxAge = result.TLS.HSTSMaxAge
			out.TLS.SupportedProtocols = result.TLS.SupportedProtocols
			out.TLS.SupportedProtocolIDs = append([]uint16(nil), result.TLS.SupportedProtocolIDs...)
			negotiatedVersion = result.TLS.TLSVersion
		}
		out.TLS.CipherEnumeration = enumFindings
		out.TLS.DeepEnumAttempted = enumAttempted
		if enumAttempted {
			out.TLS.CipherEnumerationProfile = tlsconst.EnumerationProfile
			// A completed enumeration reports the version set it observed - the
			// fast-probe negotiated version plus any versions in the findings - so
			// a clean empty enum (a TLS 1.3-only server) still yields a non-empty
			// SupportedProtocols and stays distinguishable from "no deep enum ran".
			out.TLS.SupportedProtocols = mergeProtocols(negotiatedVersion, enumFindings)
		}
		for _, f := range enumFindings {
			if f.VersionID != nil {
				out.TLS.SupportedProtocolIDs = append(out.TLS.SupportedProtocolIDs, *f.VersionID)
			}
		}
		if result.TLS != nil && result.TLS.TLSVersionID != nil {
			out.TLS.SupportedProtocolIDs = append(out.TLS.SupportedProtocolIDs, *result.TLS.TLSVersionID)
		}
		sort.Slice(out.TLS.SupportedProtocolIDs, func(i, j int) bool { return out.TLS.SupportedProtocolIDs[i] < out.TLS.SupportedProtocolIDs[j] })
		out.TLS.SupportedProtocolIDs = slices.Compact(out.TLS.SupportedProtocolIDs)
		if enumAttempted || len(enumFindings) > 0 || (result.TLS != nil && len(result.TLS.SupportedProtocolIDs) > 0) {
			out.TLS.SupportedProtocols = nil
			for _, id := range out.TLS.SupportedProtocolIDs {
				out.TLS.SupportedProtocols = append(out.TLS.SupportedProtocols, tlsconst.VersionString(id))
			}
		}
	}
	return out
}

// mergeProtocols returns the sorted, deduplicated set of TLS versions a
// completed enumeration observed: the fast-probe negotiated version plus the
// versions carried by the cipher findings. Empty strings are skipped.
func mergeProtocols(negotiated string, findings []commonsentinel.CipherFinding) []string {
	set := make(map[string]struct{}, 4)
	if negotiated != "" {
		set[negotiated] = struct{}{}
	}
	for _, f := range findings {
		if f.Version != "" {
			set[f.Version] = struct{}{}
		}
	}
	out := make([]string, 0, len(set))
	for v := range set {
		out = append(out, v)
	}
	sort.Strings(out)
	return out
}

// runCipherEnum shares the scan-wide connection budget and returns partial
// positive findings on error. The boolean attests completion of the TLS profile.
func (s *Scanner) runCipherEnum(ctx context.Context, sniHost, peerIP string, port int, timeout time.Duration, rateTicker *time.Ticker) ([]commonsentinel.CipherFinding, bool) {
	base := s.dialer(rateTicker.C, false)
	pinned, err := tlsprobe.NewPinnedDialer(base, peerIP)
	if err != nil {
		return nil, false
	}
	var dialer tlsprobe.ContextDialer = upgradeDialer{base: pinned}
	// Every enumeration connection shares the fast probes' scan-wide budget.
	// The pinned dialer already shares admission and rate limits.
	enumCtx, cancel := context.WithTimeout(ctx, deepEnumOverallTimeout)
	defer cancel()
	res, err := tlsenum.Enumerate(enumCtx, sniHost, port, tlsenum.Options{
		DisableALPN:      true,
		Dialer:           dialer,
		HandshakeTimeout: timeout,
	})
	if err != nil {
		s.logger.Warn("cipher enumeration failed", "host", sniHost, "port", port, "error", err)
	}
	if res == nil {
		return nil, err == nil
	}
	out := make([]commonsentinel.CipherFinding, len(res.Findings))
	for i, f := range res.Findings {
		out[i] = commonsentinel.CipherFinding{Version: f.Version, Cipher: f.Cipher, VersionID: &f.VersionID, CipherID: &f.CipherID, DHBits: f.DHBits}
	}
	return out, err == nil
}

// ScanHostname starts a single-target scan against an FQDN. The dialer
// resolves the FQDN before applying the destination-IP connection budget;
// SNI is set to the FQDN so virtual-hosted endpoints serve the right
// certificate. SNI re-probing for SAN names also runs, exactly as on a
// CIDR-based scan target.
//
// deepEnum=true also runs TLS cipher enumeration after the fast probe.
//
// If ports is empty the caller decides what to do - we don't fall back
// to a default. This keeps the policy in one place (the agent).
func (s *Scanner) ScanHostname(ctx context.Context, fqdn string, ports []int, timeout time.Duration, deepEnum bool) (<-chan ProbeOutput, *ScanMeta) {
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	cfg := ScanConfig{
		Ports:   ports,
		Timeout: timeout,
		// Single target: no point in spinning up the default 50 workers
		// and 100 conns/s rate budget. One worker is plenty.
		Workers:       1,
		MaxConnPerSec: DefaultMaxConnPerSec,
		DeepEnum:      deepEnum,
	}

	targets := make([]target, 0, len(ports))
	for _, port := range ports {
		targets = append(targets, target{host: fqdn, port: port, serverName: fqdn})
	}

	s.applyProfile(&cfg)
	// Keep pending results bounded when report delivery pauses the consumer.
	resultCh := make(chan ProbeOutput, 2)
	meta := &ScanMeta{
		ScanID:       generateScanID(),
		StartedAt:    time.Now().UTC(),
		TotalTargets: len(targets),
	}

	s.logger.Info("starting hostname scan", "scan_id", meta.ScanID, "fqdn", fqdn, "ports", len(targets))

	// Rate limiter (single ticker - same shape as ScanStream so probeTarget
	// behaves identically).
	interval := time.Second / time.Duration(cfg.MaxConnPerSec)
	if interval <= 0 {
		interval = time.Millisecond
	}
	rateTicker := time.NewTicker(interval)

	go func() {
		defer rateTicker.Stop()
		defer close(resultCh)
		for _, tgt := range targets {
			if ctx.Err() != nil {
				return
			}
			s.probeTarget(ctx, tgt, cfg, resultCh, rateTicker)
		}
	}()

	return resultCh, meta
}

// LocalTarget is one host-local address:port to probe in a local_scan. Host is
// the address to actually dial (loopback for wildcard/loopback binds, the
// specific IP for interface-bound services).
type LocalTarget struct {
	Host string
	Port int
}

// localScanWorkers is the worker count for a local_scan. Loopback handshakes
// are cheap and a host has at most a few hundred listeners; a small pool keeps
// the probing gentle (it must never look like a port scan to the host's IDS).
const localScanWorkers = 10

// ScanLocalListeners probes a fixed set of host-local listeners ONCE each (no
// SNI re-probe, no cipher enumeration) with the shared connection budget.
// It streams ProbeOutput exactly like ScanStream/ScanHostname so the agent
// reuses the same collector. The targets come from the host's own listening
// sockets (see internal/listeners); this method never invents a port range.
func (s *Scanner) ScanLocalListeners(ctx context.Context, targets []LocalTarget, timeout time.Duration) (<-chan ProbeOutput, *ScanMeta) {
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	its := make([]target, 0, len(targets))
	for _, t := range targets {
		its = append(its, target{host: t.Host, port: t.Port})
	}
	return s.ScanStream(ctx, ScanConfig{
		Targets:        its,
		Timeout:        timeout,
		Workers:        localScanWorkers,
		MaxConnPerSec:  DefaultMaxConnPerSec,
		SkipSNIReprobe: true,
	})
}

// Target is one explicit (host, port, serverName) probe target requested by
// the backend through a network_scan task's targets[] field - a closed-loop
// verification of a specific endpoint the backend already discovered
// elsewhere. Host is dialed as-is (an IP literal, per the wire contract);
// ServerName is the SNI to send.
type Target struct {
	Host       string
	Port       int
	ServerName string
}

// ScanTargets probes a fixed, backend-supplied target list with deep cipher
// enumeration, no SAN re-probing, and no CIDR expansion: the caller asked for
// exactly these (host, port, serverName) triples, so the scanner doesn't grow
// the scope beyond them (same "exactly this set" discipline ScanLocalListeners
// applies to the host's own listeners).
func (s *Scanner) ScanTargets(ctx context.Context, targets []Target, timeout time.Duration) (<-chan ProbeOutput, *ScanMeta) {
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	its := make([]target, 0, len(targets))
	for _, t := range targets {
		its = append(its, target{host: t.Host, port: t.Port, serverName: t.ServerName})
	}
	return s.ScanStream(ctx, ScanConfig{
		Targets: its,
		Timeout: timeout,
		// Reusing local_scan's small pool is fine here too: the backend already
		// bounded the target set, so this isn't a full-scope sweep needing more
		// concurrency.
		Workers:        localScanWorkers,
		MaxConnPerSec:  DefaultMaxConnPerSec,
		DeepEnum:       true,
		SkipSNIReprobe: true,
	})
}

// Scan runs a full discovery scan and returns the aggregated result
// with certificates deduplicated by fingerprint and observations
// referencing them. It is a convenience wrapper around ScanStream.
func (s *Scanner) Scan(ctx context.Context, cfg ScanConfig) (*ScanResult, error) {
	resultCh, meta := s.ScanStream(ctx, cfg)

	result := &ScanResult{
		ScanID:    meta.ScanID,
		StartedAt: meta.StartedAt,
	}

	seenCerts := make(map[string]bool)

	for out := range resultCh {
		fps := make([]string, 0, len(out.Chain))
		for _, der := range out.Chain {
			fp := Fingerprint(der)
			if !seenCerts[fp] {
				seenCerts[fp] = true
				result.Certificates = append(result.Certificates, transport.Certificate{
					FingerprintSHA256: fp,
					DER:               der,
				})
			}
			fps = append(fps, fp)
		}
		if len(fps) == 0 && (out.TLS == nil || out.TLS.TLSVersionID == nil) {
			continue
		}
		result.NetworkObservations = append(result.NetworkObservations, transport.SentinelNetworkObservation{
			IP:                        out.IP,
			Port:                      out.Port,
			SNI:                       out.SNI,
			ObservedChainFingerprints: fps,
			TLS:                       out.TLS,
		})
	}

	result.CompletedAt = time.Now().UTC()
	result.TotalTargets = meta.TotalTargets

	if ctx.Err() != nil {
		return result, ctx.Err()
	}

	s.logger.Info("scan complete",
		"scan_id", result.ScanID,
		"observations", len(result.NetworkObservations),
		"unique_certs", len(result.Certificates),
		"duration", result.CompletedAt.Sub(result.StartedAt),
	)

	return result, nil
}

// Fingerprint computes the lowercase hex SHA-256 of a DER-encoded
// certificate. This is the canonical fingerprint format used on the
// wire by the certificates / observations split.
func Fingerprint(der []byte) string {
	sum := sha256.Sum256(der)
	return hex.EncodeToString(sum[:])
}

func generateScanID() string {
	b := make([]byte, 12)
	_, _ = rand.Read(b)
	return "scan_" + hex.EncodeToString(b)
}

// tlsProber wraps nocert-common's tlsprobe.Probe for the sentinel's Prober interface.
type tlsProber struct {
	dialer tlsprobe.ContextDialer
	logger *slog.Logger
}
