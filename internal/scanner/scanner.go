package scanner

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"log/slog"
	mathrand "math/rand/v2"
	"net"
	"sort"
	"strings"
	"sync"
	"time"

	commonsentinel "nocert.io/common/pkg/api/sentinel"
	"nocert.io/common/pkg/tlsenum"
	"nocert.io/common/pkg/tlsprobe"
	"nocert.io/sentinel/internal/transport"
)

const (
	// MaxTotalTargets is the maximum number of IP:port combinations in a single scan.
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

// expandAllCIDRs expands all configured CIDRs into individual IPs, bounded to
// MaxTotalTargets. When the configured space is larger, it keeps a uniform
// random sample (reservoir sampling) rather than the first MaxTotalTargets in
// enumeration order: a plain prefix-cut would deterministically drop the same
// tail IPs on every run, leaving them permanently unscanned. Memory stays
// bounded to the reservoir plus one CIDR's expansion (ExpandCIDR caps each at
// /16).
func (s *Scanner) expandAllCIDRs(cidrs []string) []net.IP {
	reservoir := make([]net.IP, 0, MaxTotalTargets)
	total := 0
	for _, cidr := range cidrs {
		ips, err := ExpandCIDR(cidr)
		if err != nil {
			s.logger.Warn("skipping invalid CIDR", "cidr", cidr, "error", err)
			continue
		}
		for _, ip := range ips {
			if len(reservoir) < MaxTotalTargets {
				reservoir = append(reservoir, ip)
			} else if j := mathrand.IntN(total + 1); j < MaxTotalTargets {
				reservoir[j] = ip
			}
			total++
		}
	}
	if total > MaxTotalTargets {
		s.logger.Warn("scan scope exceeds target cap; scanning a rotating random sample",
			"configured", total, "limit", MaxTotalTargets)
	}
	// Shuffle so probe order is not correlated with CIDR/enumeration order.
	mathrand.Shuffle(len(reservoir), func(i, j int) { reservoir[i], reservoir[j] = reservoir[j], reservoir[i] })
	return reservoir
}

// ScanStream starts a concurrent scan and returns a channel of probe
// outputs plus metadata. The caller must drain the returned channel.
// Probe outputs are streamed as they are observed; certificate
// fingerprinting and dedup happens downstream in the collector.
func (s *Scanner) ScanStream(ctx context.Context, cfg ScanConfig) (<-chan ProbeOutput, *ScanMeta) {
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

	// Either probe an explicit target set (local_scan) or expand CIDRs x ports.
	var targets []target
	if len(cfg.Targets) > 0 {
		targets = cfg.Targets
		if len(targets) > MaxTotalTargets {
			s.logger.Warn("scan scope truncated", "limit", MaxTotalTargets)
			targets = targets[:MaxTotalTargets]
		}
	} else {
		allIPs := s.expandAllCIDRs(cfg.IPRanges)
		for _, ip := range allIPs {
			for _, port := range cfg.Ports {
				targets = append(targets, target{host: ip.String(), port: port})
				if len(targets) >= MaxTotalTargets {
					s.logger.Warn("scan scope truncated", "limit", MaxTotalTargets)
					break
				}
			}
			if len(targets) >= MaxTotalTargets {
				break
			}
		}
	}

	resultCh := make(chan ProbeOutput, workers*2)
	targetCh := make(chan target, workers*2)

	meta := &ScanMeta{
		ScanID:       generateScanID(),
		StartedAt:    time.Now().UTC(),
		TotalTargets: len(targets),
	}

	s.logger.Info("starting scan", "scan_id", meta.ScanID, "targets", len(targets), "workers", workers)

	// Rate limiter shared by all workers
	interval := time.Second / time.Duration(maxConn)
	if interval <= 0 {
		interval = time.Millisecond
	}
	rateTicker := time.NewTicker(interval)

	// Scheduler goroutine: dispatches targets (no rate limiting)
	go func() {
		defer close(targetCh)
		for _, tgt := range targets {
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
	// Wait for rate limiter before initial probe
	select {
	case <-rateTicker.C:
	case <-ctx.Done():
		return
	}

	// tgt.serverName is the FQDN for ScanHostname (virtual-host SNI); empty for
	// CIDR/local scans, where Probe sends no SNI on an IP literal.
	probeResult, err := s.prober.Probe(ctx, tgt.host, tgt.port, cfg.Timeout, tgt.serverName)
	if err != nil {
		s.logger.Debug("probe failed", "host", tgt.host, "port", tgt.port, "error", err)
		return
	}

	// Cipher enumeration runs once AFTER the fast probe confirmed TLS, BEFORE the
	// SNI re-probes. It is pinned to the peer the fast probe reached and re-uses
	// its SNI, so the findings characterise THIS (peer, SNI). They are attached
	// to the primary observation only: an SNI re-probe of a different SAN can
	// select a different certificate behind a different TLS configuration, so it
	// must NOT inherit this enumeration (see reprobeWith below). On error findings
	// stay nil and enumAttempted=false - the fast-probe observation is still
	// reported, but the enum is retried rather than recorded as fresh.
	enumSNI := tgt.serverName
	if enumSNI == "" {
		enumSNI = tgt.host // CIDR: SNI = IP literal, preserving prior behaviour
	}
	var (
		enumFindings  []commonsentinel.CipherFinding
		enumAttempted bool
	)
	if cfg.DeepEnum {
		enumFindings, enumAttempted = s.runCipherEnum(ctx, enumSNI, probeResult.PeerIP, tgt.port, cfg.Timeout, rateTicker)
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
			probeResult.Certificate.Fingerprint: true,
		}
		reprobes := 0

		reprobeWith := func(sni string) {
			select {
			case <-rateTicker.C:
			case <-ctx.Done():
				return
			}

			sniResult, err := s.prober.Probe(ctx, tgt.host, tgt.port, cfg.Timeout, sni)
			if err != nil {
				return
			}
			if seen[sniResult.Certificate.Fingerprint] {
				return
			}
			seen[sniResult.Certificate.Fingerprint] = true

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

// probeResultToOutput converts a tlsprobe.Result into a ProbeOutput.
// Returns nil if the probe yielded no usable cert bytes OR no resolved
// peer IP (skipped by the caller - keeps the downstream collector simple).
//
// IP is taken from result.PeerIP (the actual TCP RemoteAddr after the
// stdlib resolver did its work), never from the input target host -
// which for FQDN-targeted scans is a hostname, not an IP literal. The
// backend's observations index has a strict `ip` mapping that would
// reject a hostname.
func (s *Scanner) probeResultToOutput(port int, sni string, result *tlsprobe.Result, enumFindings []commonsentinel.CipherFinding, enumAttempted bool) *ProbeOutput {
	if result == nil || result.Certificate == nil || len(result.Certificate.RawDER) == 0 {
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
	// result.Certificate is the leaf; result.Chain is the FULL presented chain,
	// which already starts with that same leaf. Add the leaf once, then the rest
	// of the chain skipping any copy of it - otherwise observed_chain_fingerprints
	// carries a duplicate leaf.
	out.Chain = append(out.Chain, result.Certificate.RawDER)
	for _, ce := range result.Chain {
		if len(ce.RawDER) > 0 && !bytes.Equal(ce.RawDER, result.Certificate.RawDER) {
			out.Chain = append(out.Chain, ce.RawDER)
		}
	}
	if result.TLS != nil || enumAttempted {
		out.TLS = &transport.TLSObservation{}
		var negotiatedVersion string
		if result.TLS != nil {
			out.TLS.HandshakeComplete = result.TLS.HandshakeComplete
			checked := false
			out.TLS.HSTSChecked = &checked
			out.TLS.TLSVersion = result.TLS.TLSVersion
			out.TLS.CipherSuite = result.TLS.CipherSuite
			out.TLS.NegotiatedGroup = result.TLS.NegotiatedGroup
			out.TLS.OCSPStapling = result.TLS.OCSPStapling
			out.TLS.HSTSEnabled = result.TLS.HSTSEnabled
			out.TLS.HSTSMaxAge = result.TLS.HSTSMaxAge
			out.TLS.SupportedProtocols = result.TLS.SupportedProtocols
			negotiatedVersion = result.TLS.TLSVersion
		}
		out.TLS.CipherEnumeration = enumFindings
		out.TLS.DeepEnumAttempted = enumAttempted
		if enumAttempted {
			// A completed enumeration reports the version set it observed - the
			// fast-probe negotiated version plus any versions in the findings - so
			// a clean empty enum (a TLS 1.3-only server) still yields a non-empty
			// SupportedProtocols and stays distinguishable from "no deep enum ran".
			out.TLS.SupportedProtocols = mergeProtocols(negotiatedVersion, enumFindings)
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

// runCipherEnum performs TLS cipher enumeration. It uses an unrestricted
// net.Dialer because the sentinel intentionally scans customer-internal
// networks, wrapped in a PinnedDialer so the enumeration reaches the exact peer
// the fast probe observed (peerIP); sniHost is sent as the SNI so it matches the
// fast probe's virtual-host selection. On error returns nil + false (the caller
// treats that as "not attempted"; the fast-probe observation still goes
// through). On a clean run it returns the findings (possibly empty) plus true,
// so the backend may stamp last_cipher_enum_at even when no legacy cipher was
// accepted (e.g., a TLS 1.3-only server).
func (s *Scanner) runCipherEnum(ctx context.Context, sniHost, peerIP string, port int, timeout time.Duration, rateTicker *time.Ticker) ([]commonsentinel.CipherFinding, bool) {
	base := &net.Dialer{Timeout: timeout}
	var dialer tlsprobe.ContextDialer = base
	if pd, err := tlsprobe.NewPinnedDialer(base, peerIP); err == nil {
		dialer = pd
	}
	// Every enumeration connection shares the fast probes' scan-wide budget.
	dialer = &rateLimitedDialer{base: dialer, ticks: rateTicker.C}
	enumCtx, cancel := context.WithTimeout(ctx, deepEnumOverallTimeout)
	defer cancel()
	res, err := tlsenum.Enumerate(enumCtx, sniHost, port, tlsenum.Options{
		Dialer:           dialer,
		HandshakeTimeout: timeout,
	})
	if err != nil {
		s.logger.Warn("cipher enumeration failed", "host", sniHost, "port", port, "error", err)
		return nil, false
	}
	if res == nil {
		return nil, true
	}
	out := make([]commonsentinel.CipherFinding, len(res.Findings))
	for i, f := range res.Findings {
		out[i] = commonsentinel.CipherFinding{Version: f.Version, Cipher: f.Cipher}
	}
	return out, true
}

// ScanHostname starts a single-target scan against an FQDN. The dialer
// resolves the FQDN to one or more IPs (transparently, inside tlsprobe);
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

	resultCh := make(chan ProbeOutput, len(targets)+1)
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
// SNI re-probe, no cipher enumeration) over an unrestricted dialer.
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
		if len(fps) == 0 {
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
	logger *slog.Logger
}

func (p *tlsProber) Probe(ctx context.Context, host string, port int, timeout time.Duration, serverName string) (*tlsprobe.Result, error) {
	return tlsprobe.Probe(ctx, host, port, tlsprobe.Options{
		ConnectTimeout:   timeout,
		HandshakeTimeout: timeout,
		ServerName:       serverName,
		// Sentinel scans customer-internal networks by design; use an
		// unrestricted dialer (no SSRF block).
		Dialer: &net.Dialer{Timeout: timeout},
	})
}
