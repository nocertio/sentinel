// Package sentinel defines the canonical request/response types for the
// /api/v1/sentinels/* endpoints exposed by nocert-app and consumed by
// nocert-sentinel.
//
// Both sides import these structs so that the Go compiler enforces the
// contract. The canonical wire contract is the backend's OpenAPI document;
// these structs MUST be kept in sync with it.
//
// Authentication: RFC 9421 Ed25519 signatures on all endpoints except
// /register (Bearer enrollment token).
package sentinel

import (
	"encoding/json"
	"time"
)

// ----------------------------------------------------------------------------
// POST /api/v1/sentinels/register
// ----------------------------------------------------------------------------

// RegisterRequest is sent once at enrollment with a Bearer one-time token.
// The sentinel locally generated its Ed25519 keypair; only the public key is
// transmitted.
type RegisterRequest struct {
	PublicKey string `json:"public_key"`
	Hostname  string `json:"hostname,omitempty"`
	OS        string `json:"os,omitempty"`
	Arch      string `json:"arch,omitempty"`
	Version   string `json:"version,omitempty"`
	IPAddress string `json:"ip_address,omitempty"`

	// InterfaceSubnets are the IPv4 networks (CIDR, e.g. "10.20.30.0/23") of the
	// host's own non-virtual interfaces, as the sentinel sees them. Advisory only.
	InterfaceSubnets []string `json:"interface_subnets,omitempty"`
}

// RegisterResponse carries the server-assigned identity and the backend's
// signing public key (used by the sentinel to verify signed responses).
//
// SigningKeyID is the keyid the backend uses on its RFC 9421 response
// signatures. Sentinels pin it during registration and use it to bind
// subsequent response verifications to the correct identity.
type RegisterResponse struct {
	SentinelID       string    `json:"sentinel_id"`
	KeyID            string    `json:"key_id"`
	KeyExpiresAt     time.Time `json:"key_expires_at"`
	SigningPublicKey string    `json:"signing_public_key"`
	SigningKeyID     string    `json:"signing_key_id"`
}

// ----------------------------------------------------------------------------
// POST /api/v1/sentinels/rotate
// ----------------------------------------------------------------------------

// RotateRequest is signed with the current key and carries the new public key.
type RotateRequest struct {
	NewPublicKey string `json:"new_public_key"`
}

// RotateResponse returns the new key id and its expiration.
type RotateResponse struct {
	KeyID        string    `json:"key_id"`
	KeyExpiresAt time.Time `json:"key_expires_at"`
}

// ----------------------------------------------------------------------------
// GET /api/v1/sentinels/{id}/tasks
// ----------------------------------------------------------------------------

// TaskResponse is one task pulled from the backend queue.
// Type is an enum of known task types: "network_scan", "filesystem_scan",
// "local_scan".
//
// Payload is the task-type-specific JSON. For network_scan it MAY contain
// {"fqdn": string, "ports": [int], "targets": [TargetSpec]} (all optional -
// absent fqdn means "full CIDR sweep"). When targets is present, the
// sentinel probes exactly those (ip, port, sni) with deep cipher
// enumeration, ignoring CIDR expansion. For filesystem_scan and local_scan
// it is empty.
type TaskResponse struct {
	ID      string          `json:"id"`
	Type    string          `json:"type"`
	Payload json.RawMessage `json:"payload,omitempty"`
}

// TargetSpec is one explicit (ip, port, sni) probe target for a network_scan
// task. When a network_scan payload carries Targets, the sentinel probes
// exactly these with deep cipher enumeration, bypassing CIDR expansion.
type TargetSpec struct {
	IP   string `json:"ip"`
	Port int    `json:"port"`
	SNI  string `json:"sni,omitempty"`
}

// NetworkScanPayload is the task-type-specific body carried in
// TaskResponse.Payload for a network_scan task. All fields are optional: an
// absent payload - or an empty object - means a full sweep of the sentinel's
// configured CIDR ranges. When Targets is non-empty the sentinel probes exactly
// those (ip, port, sni) triples with deep enumeration and does NOT expand any
// CIDR. This is the single wire definition - marshaled by the backend and
// unmarshaled by the sentinel - so the two ends cannot silently drift.
type NetworkScanPayload struct {
	Fqdn     string       `json:"fqdn,omitempty"`
	Ports    []int        `json:"ports,omitempty"`
	DeepEnum bool         `json:"deep_enum,omitempty"`
	Targets  []TargetSpec `json:"targets,omitempty"`
}

// SentinelConfig is the scan configuration the sentinel applies to all scans.
// Embedded in every TasksResponse so the sentinel always uses the freshest
// settings.
type SentinelConfig struct {
	IPRanges                      []string `json:"ip_ranges"`
	Ports                         []int    `json:"ports"`
	ScanNetworkIntervalSeconds    int      `json:"scan_network_interval_seconds"`
	ScanFilesystemIntervalSeconds int      `json:"scan_filesystem_interval_seconds"`
	ScanEnabled                   bool     `json:"scan_enabled"`

	// KubernetesNamespacesInclude/Exclude scope the Kubernetes connector.
	// Empty include means all namespaces (cluster-wide list); a non-empty
	// include makes the agent list per-namespace, which also fits
	// namespace-scoped RBAC. Exclusion wins.
	KubernetesNamespacesInclude []string `json:"kubernetes_namespaces_include,omitempty"`
	KubernetesNamespacesExclude []string `json:"kubernetes_namespaces_exclude,omitempty"`
}

// TasksResponse is what the sentinel receives on every poll. It carries the
// freshest org-level SentinelConfig plus any tasks queued for execution.
type TasksResponse struct {
	Config SentinelConfig `json:"config"`
	Tasks  []TaskResponse `json:"tasks"`
}

// Task types the sentinel knows how to execute. Constants match the OpenAPI
// const enum on SentinelTask.type.
const (
	TaskTypeNetworkScan    = "network_scan"
	TaskTypeFilesystemScan = "filesystem_scan"
	// TaskTypeLocalScan asks the sentinel to enumerate the TCP ports listening
	// on its OWN host and probe each for a TLS certificate over loopback. It
	// has no payload.
	TaskTypeLocalScan = "local_scan"
	// TaskTypeKubernetesScan asks the sentinel to sweep the Kubernetes
	// clusters configured in its local config file: list Secrets of type
	// kubernetes.io/tls (plus a named allowlist of well-known mesh CA
	// objects), extract public certificate material only, and report
	// kubernetes_observations. No payload.
	TaskTypeKubernetesScan = "kubernetes_scan"
)

// ----------------------------------------------------------------------------
// POST /api/v1/sentinels/{id}/report
// ----------------------------------------------------------------------------

// Certificate carries one raw certificate as DER bytes alongside its
// SHA-256 fingerprint. The backend recomputes SHA-256(DER) on receipt
// and rejects any mismatch - fingerprint is therefore not trusted as
// input, only as a lookup key for observations referencing the cert.
type Certificate struct {
	FingerprintSHA256 string `json:"fingerprint_sha256"`
	DER               []byte `json:"der"`
}

// CipherFinding is one (TLS version, cipher suite) pair the scanner observed.
// Populated by deep enumeration; absent on fast-probe-only results.
//
// This is the AGENT INPUT type and intentionally does NOT carry IsWeak: the
// flag is backend-derived (from the IANA registry) and never trusted from
// agent input. The backend-internal counterpart with IsWeak lives in
// pkg/certinfo.CipherFinding - used after normalization, for storage and
// API responses.
type CipherFinding struct {
	Version string `json:"version"` // canonical "TLSv1.0" / "TLSv1.1" / "TLSv1.2"
	Cipher  string `json:"cipher"`  // IANA name
}

// TLSObservation carries TLS handshake metadata that the backend
// cannot derive from the certificate bytes alone (cipher, OCSP status,
// HSTS header, supported protocols, etc.). All fields are optional -
// what's populated reflects what the scanner actually observed.
type TLSObservation struct {
	HandshakeComplete  *bool           `json:"handshake_complete,omitempty"`
	HSTSChecked        *bool           `json:"hsts_checked,omitempty"`
	TLSVersion         string          `json:"tls_version,omitempty"`
	CipherSuite        string          `json:"cipher_suite,omitempty"`
	NegotiatedGroup    string          `json:"negotiated_group,omitempty"`
	OCSPStapling       bool            `json:"ocsp_stapling"`
	HSTSEnabled        bool            `json:"hsts_enabled"`
	HSTSMaxAge         int             `json:"hsts_max_age,omitempty"`
	SupportedProtocols []string        `json:"supported_protocols,omitempty"`
	CipherEnumeration  []CipherFinding `json:"cipher_enumeration,omitempty"`
	// DeepEnumAttempted is set only when the deep enumeration pass completed
	// cleanly; it distinguishes "no completed enum" from "completed but found
	// no cipher" (e.g., a TLS-1.3-only server probed only across TLS
	// 1.0/1.1/1.2). Interrupted or failed runs must leave it false and drop
	// their partial findings.
	DeepEnumAttempted bool `json:"deep_enum_attempted,omitempty"`
	DeepEnumFailed    bool `json:"deep_enum_failed,omitempty"`
}

// SentinelNetworkObservation links one observed (IP, port[, sni])
// endpoint to a certificate chain via the cert fingerprints.
// ObservedChainFingerprints is in TLS handshake order.
type SentinelNetworkObservation struct {
	IP                        string          `json:"ip"`
	Port                      int             `json:"port"`
	SNI                       string          `json:"sni,omitempty"`
	ObservedChainFingerprints []string        `json:"observed_chain_fingerprints"`
	TLS                       *TLSObservation `json:"tls,omitempty"`
}

// LocalListenerKey identifies one TLS service observed during a complete
// local_scan. The final report carries the full set so the backend can remove
// stale observations for services that disappeared. IP is normalized again by
// the backend; the authenticated sentinel identity supplies the host scope.
type LocalListenerKey struct {
	IP   string `json:"ip"`
	Port int    `json:"port"`
}

// Filesystem-state warning enum values. The agent reports only
// findings that are NOT derivable from the certificate content
// (which the backend re-derives via the certparser sandbox).
const (
	// FilesystemWarningInsecurePrivateKeyPermissions indicates the
	// sentinel found a private-key file alongside this certificate
	// (heuristics: same basename .key, sibling private/ subdir,
	// PEM header detection) whose mode is looser than 0600 (group
	// or other readable). The actual key path is never transmitted
	// - only the warning enum value.
	FilesystemWarningInsecurePrivateKeyPermissions = "insecure_private_key_permissions"
)

// SentinelFilesystemObservation links a discovered certificate to every
// absolute path it was found at on the reporting sentinel's host. The
// sentinel aggregates by fingerprint, so there is exactly one observation
// per certificate and FilePaths is complete - the backend never merges.
type SentinelFilesystemObservation struct {
	FilePaths         []string `json:"file_paths"`
	FingerprintSHA256 string   `json:"fingerprint_sha256"`
	Warnings          []string `json:"warnings,omitempty"`
}

// SentinelKubernetesObservation links the certificates extracted from one
// data key of one Secret or ConfigMap (in one cluster) to their fingerprints.
// The agent extracts only public material - allowlisted data keys such as
// tls.crt and ca.crt, never tls.key - so this shape structurally cannot
// carry private-key bytes.
type SentinelKubernetesObservation struct {
	Cluster    string `json:"cluster"`
	Namespace  string `json:"namespace"`
	SecretName string `json:"secret_name"`
	// SourceKind discriminates the object kind: "secret" or "configmap".
	SourceKind string `json:"source_kind"`
	// DataKey is the data key the certificates were extracted from
	// (tls.crt, ca.crt, ca-cert.pem, ...).
	DataKey                   string   `json:"data_key"`
	ObservedChainFingerprints []string `json:"observed_chain_fingerprints"`
	// ManagedBy is "cert-manager" when the Secret carries the
	// cert-manager.io/certificate-name annotation; empty otherwise. It drives
	// the "cert-manager" badge on the certificate detail page.
	ManagedBy string `json:"managed_by,omitempty"`
}

// KubernetesSweepResult is the per-cluster outcome of a kubernetes_scan
// sweep, set only on the final "completed" report. Complete=true authorizes
// the backend to reconcile: delete this sentinel+cluster's findings whose
// location key is absent from ObservedKeys. Location keys are
// "<source_kind>/<namespace>/<name>/<data_key>".
type KubernetesSweepResult struct {
	Cluster      string   `json:"cluster"`
	Complete     bool     `json:"complete"`
	ObservedKeys []string `json:"observed_keys"`
	// Reason classifies why Complete is false, from the closed set below. A
	// closed enum rather than an error string: raw errors can embed the API
	// server URL (customer-local configuration that must not reach the
	// backend). Empty when Complete is true.
	Reason string `json:"reason,omitempty"`
}

// Values for KubernetesSweepResult.Reason.
const (
	// KubernetesReasonConfigError: the cluster entry's local credentials or
	// kubeconfig could not be loaded (missing file, rejected exec plugin, bad
	// CA) - nothing was dialed.
	KubernetesReasonConfigError = "config_error"
	// KubernetesReasonUnreachable: dial/TLS failure talking to the API server.
	KubernetesReasonUnreachable = "unreachable"
	// KubernetesReasonAuthFailed: the API server answered 401.
	KubernetesReasonAuthFailed = "auth_failed"
	// KubernetesReasonForbidden: the API server answered 403 (RBAC).
	KubernetesReasonForbidden = "forbidden"
	// KubernetesReasonTimeout: the sweep deadline expired during this cluster.
	KubernetesReasonTimeout = "timeout"
	// KubernetesReasonTruncated: a sweep-wide cap was reached while sweeping
	// this cluster; its result set is partial.
	KubernetesReasonTruncated = "truncated"
	// KubernetesReasonSkipped: a sweep-wide cap was reached on an earlier
	// cluster; this one was not swept at all.
	KubernetesReasonSkipped = "skipped"
	// KubernetesReasonInternal: anything else; also the backend's fallback
	// for a reason value outside this set.
	KubernetesReasonInternal = "internal"
)

// Values for SentinelKubernetesObservation.SourceKind.
const (
	KubernetesSourceKindSecret    = "secret"
	KubernetesSourceKindConfigMap = "configmap"
)

// ReportRequest is the payload pushed by the sentinel after a task
// completes. Status is "partial" (more to come), "completed", or
// "failed". Certificates are deduplicated within the request by
// fingerprint; observations reference them by fingerprint.
type ReportRequest struct {
	TaskID                 string                          `json:"task_id"`
	Status                 string                          `json:"status"`
	Certificates           []Certificate                   `json:"certificates,omitempty"`
	NetworkObservations    []SentinelNetworkObservation    `json:"network_observations,omitempty"`
	FilesystemObservations []SentinelFilesystemObservation `json:"filesystem_observations,omitempty"`

	// LocalObservations carries TLS probes of services listening on the
	// sentinel's OWN host (loopback), produced by a local_scan task. The wire
	// shape is identical to a network observation - the slice membership is
	// the discriminator (same idiom as Network vs Filesystem). The backend
	// keys these by the authenticated sentinel id (not by IP, which is always
	// loopback and would collide across hosts) and stamps
	// discovered_via=sentinel_local. IP is the loopback address actually
	// dialed (127.0.0.1 / ::1).
	LocalObservations []SentinelNetworkObservation `json:"local_observations,omitempty"`

	// LocalScanComplete is true only on the final completed report after every
	// local-observation batch was accepted. It authorizes reconciliation; false
	// or absent is additive-only and never deletes existing observations.
	LocalScanComplete bool `json:"local_scan_complete,omitempty"`

	// LocalListenerKeys is the complete (ip, port) set observed during that
	// local scan. An empty set with LocalScanComplete=true intentionally removes
	// all previous local observations for the authenticated sentinel.
	LocalListenerKeys []LocalListenerKey `json:"local_listener_keys,omitempty"`

	// FilesystemScanComplete is set only on the final "completed" report of
	// a filesystem_scan task. true means the sweep enumerated the host
	// without truncation or cancellation, which authorizes the backend to
	// reconcile (delete findings whose certs vanished). Absent/false means
	// the backend ingests additively and deletes nothing.
	FilesystemScanComplete bool `json:"filesystem_scan_complete,omitempty"`

	// FilesystemFingerprints is the full set of certificate fingerprints
	// discovered during the sweep, set only on the final "completed" report
	// of a filesystem_scan task. The backend deletes this sentinel's
	// findings whose fingerprint is absent from this set.
	FilesystemFingerprints []string `json:"filesystem_fingerprints,omitempty"`

	// KubernetesObservations carries certificates found in Kubernetes
	// Secrets/ConfigMaps by a kubernetes_scan task. Public material only.
	KubernetesObservations []SentinelKubernetesObservation `json:"kubernetes_observations,omitempty"`

	// KubernetesSweeps carries the per-cluster completeness + observed
	// location-key sets used for reconciliation, set only on the final
	// "completed" report of a kubernetes_scan task.
	KubernetesSweeps []KubernetesSweepResult `json:"kubernetes_sweeps,omitempty"`

	// KubernetesClustersConfigured is non-nil ONLY on the final "completed"
	// report of a kubernetes_scan task - including with zero clusters, where
	// the report otherwise carries nothing k8s-shaped. It is how the backend
	// tells "a k8s sweep ran (against N configured clusters)" apart from any
	// other bare report, which drives the per-sentinel cluster status.
	KubernetesClustersConfigured *int `json:"kubernetes_clusters_configured,omitempty"`
}

// Report statuses.
const (
	ReportStatusPartial   = "partial"
	ReportStatusCompleted = "completed"
	ReportStatusFailed    = "failed"
)

// ReportResponse is the backend acknowledgement.
type ReportResponse struct {
	Accepted bool `json:"accepted"`
}
