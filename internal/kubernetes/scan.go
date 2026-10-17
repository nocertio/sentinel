package kubernetes

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"sort"

	commonsentinel "nocert.io/common/pkg/api/sentinel"
)

const (
	// Sweep-wide caps mirror the backend report caps: the whole sweep ships
	// in one report, and the backend rejects >1000 certs/observations
	// outright. Overflow marks the sweep truncated (Complete=false, no
	// reconciliation) instead of losing the entire report to a 400.
	maxCertsPerSweep        = 1000
	maxObservationsPerSweep = 1000

	// maxCertBytesPerSweep bounds the cumulative raw DER of the retained certs
	// so the single completed report stays under the backend's 5 MiB body cap
	// on POST /report; overflow would 413 the WHOLE report
	// and lose every cluster's findings, so it must truncate gracefully like
	// the count caps above rather than ship. Sizing: DER travels base64 in the
	// JSON report (×4/3), and the non-DER worst case is bounded by the other
	// caps -- up to maxObservationsPerSweep observations at their wire field
	// lengths, their observed_keys, and 1000-distinct-cert framing, ~3.06 MiB
	// (all three maxes co-occur: distinct certs supply the framing while later
	// observations reuse them without growing derBytes). Capping raw DER at
	// 1 MiB keeps base64(DER) ≈ 1.4 MiB, so 1.4 + 3.06 ≈ 4.5 MiB < 5 MiB with
	// ~0.7 MiB margin even against a hostile cluster maxing everything. A
	// legitimate cluster is nowhere near this (its certs are a few KiB each and
	// it hits the 1000-cert count cap first).
	maxCertBytesPerSweep = 1024 * 1024
)

// annotationCertManagerName marks a Secret managed by cert-manager; its
// presence sets managed_by="cert-manager" on the observation.
const annotationCertManagerName = "cert-manager.io/certificate-name"

const (
	// RFC 1123 length bounds on the API-returned namespace (label) and object
	// name (subdomain), matching the wire caps on namespace/secret_name.
	maxNamespaceChars  = 63
	maxObjectNameChars = 253
)

// clusterAPI is the read surface Sweep needs from one cluster; satisfied by
// clusterClient and substituted by tests.
type clusterAPI interface {
	listTLSSecrets(ctx context.Context, namespace string, visit func(*secret) bool) (bool, error)
	getSecret(ctx context.Context, namespace, name string) (*secret, bool, error)
	getConfigMap(ctx context.Context, namespace, name string) (*configMap, bool, error)
}

// newClusterAPI is a seam for tests.
var newClusterAPI = func(spec ClusterSpec) (clusterAPI, error) { return newClusterClient(spec) }

// SweepOptions carries the backend-configured namespace scoping. Exclusion
// wins; a non-empty include switches to per-namespace lists (which also fits
// namespace-scoped RBAC).
type SweepOptions struct {
	IncludeNamespaces []string
	ExcludeNamespaces []string
}

// SweepResult is the aggregated output of one kubernetes_scan sweep across
// all configured clusters, in wire shape.
type SweepResult struct {
	Certificates []commonsentinel.Certificate
	Observations []commonsentinel.SentinelKubernetesObservation
	Sweeps       []commonsentinel.KubernetesSweepResult
	// Truncated is true when a hard cap was hit; affected clusters are
	// marked Complete=false so the backend never reconciles on them.
	Truncated bool

	// derBytes tracks the cumulative raw DER of the certs retained this sweep,
	// enforcing maxCertBytesPerSweep. Sweep-scoped internal state, never wired.
	derBytes int
}

// LocationKey is the reconciliation key of one observation. The format is a
// shared invariant with the backend (delete-by-query on location_key).
func LocationKey(kind, namespace, name, dataKey string) string {
	return kind + "/" + namespace + "/" + name + "/" + dataKey
}

// classifyError maps one cluster-API failure to a wire Reason value. The
// enum travels instead of the error string: raw errors can embed the API
// server URL, customer-local configuration that must not reach the backend.
func classifyError(err error) string {
	var se *statusError
	if errors.As(err, &se) {
		switch se.code {
		case http.StatusUnauthorized:
			return commonsentinel.KubernetesReasonAuthFailed
		case http.StatusForbidden:
			return commonsentinel.KubernetesReasonForbidden
		}
		return commonsentinel.KubernetesReasonInternal
	}
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
		return commonsentinel.KubernetesReasonTimeout
	}
	var ne net.Error
	if errors.As(err, &ne) {
		return commonsentinel.KubernetesReasonUnreachable
	}
	return commonsentinel.KubernetesReasonInternal
}

// setReason records the FIRST failure reason of a cluster sweep; later
// failures keep the original diagnosis.
func setReason(sweep *commonsentinel.KubernetesSweepResult, reason string) {
	if sweep.Reason == "" {
		sweep.Reason = reason
	}
}

// Scanner sweeps Kubernetes clusters for certificate material.
type Scanner struct {
	logger *slog.Logger
}

func NewScanner(logger *slog.Logger) *Scanner {
	return &Scanner{logger: logger}
}

// Sweep reads every configured cluster sequentially: the kubernetes.io/tls
// Secret list plus the well-known mesh allowlist. Certificates are
// deduplicated by fingerprint across the whole sweep; observations are one
// per (cluster, kind, namespace, name, data key).
func (s *Scanner) Sweep(ctx context.Context, clusters []ClusterSpec, opts SweepOptions) *SweepResult {
	res := &SweepResult{}
	seen := make(map[string]bool) // certificate fingerprints across clusters

	exclude := make(map[string]bool, len(opts.ExcludeNamespaces))
	for _, ns := range opts.ExcludeNamespaces {
		exclude[ns] = true
	}

	capped := false
	for _, spec := range clusters {
		sweep := commonsentinel.KubernetesSweepResult{Cluster: spec.Name, ObservedKeys: []string{}}
		if capped {
			// A previous cluster hit a sweep-wide cap: everything after is
			// unswept, so it must not reconcile either.
			sweep.Reason = commonsentinel.KubernetesReasonSkipped
			res.Sweeps = append(res.Sweeps, sweep)
			continue
		}

		api, err := newClusterAPI(spec)
		if err != nil {
			s.logger.Warn("kubernetes scan: cluster unusable", "cluster", spec.Name, "error", err)
			sweep.Reason = commonsentinel.KubernetesReasonConfigError
			res.Sweeps = append(res.Sweeps, sweep)
			continue
		}

		sweep.Complete = true

		// A mesh allowlist target can also be kubernetes.io/tls-typed (e.g.
		// linkerd-identity-issuer), so it is reachable by both passes below.
		// location_key is THE reconciliation key: collect each one once.
		collectedKeys := map[string]bool{}

		// 1. kubernetes.io/tls Secrets (server-side field selector). Each Secret
		// is processed as it streams in, so whole Secrets (which carry tls.key)
		// are never all buffered - only the public material survives collect().
		visit := func(sec *secret) bool {
			if exclude[sec.Metadata.Namespace] {
				return true
			}
			if !s.collect(res, seen, collectedKeys, spec.Name, commonsentinel.KubernetesSourceKindSecret, sec, tlsSecretPublicKeys, &sweep) {
				capped = true
				return false // sweep-wide cap hit; stop paging
			}
			return true
		}
		if len(opts.IncludeNamespaces) > 0 {
			for _, ns := range opts.IncludeNamespaces {
				if exclude[ns] {
					continue
				}
				ok, err := api.listTLSSecrets(ctx, ns, visit)
				if err != nil {
					s.logger.Warn("kubernetes scan: list failed", "cluster", spec.Name, "namespace", ns, "error", err)
					sweep.Complete = false
					setReason(&sweep, classifyError(err))
					continue
				}
				sweep.Complete = sweep.Complete && ok
				if !ok {
					setReason(&sweep, commonsentinel.KubernetesReasonTruncated)
				}
				if capped {
					break
				}
			}
		} else {
			ok, err := api.listTLSSecrets(ctx, "", visit)
			if err != nil {
				s.logger.Warn("kubernetes scan: cluster-wide list failed", "cluster", spec.Name, "error", err)
				sweep.Complete = false
				setReason(&sweep, classifyError(err))
			} else {
				sweep.Complete = sweep.Complete && ok
				if !ok {
					setReason(&sweep, commonsentinel.KubernetesReasonTruncated)
				}
			}
		}
		if capped {
			sweep.Complete = false
			setReason(&sweep, commonsentinel.KubernetesReasonTruncated)
		}

		// 2. Well-known mesh allowlist (targeted gets; absence is normal).
		if !capped {
			for _, target := range wellKnownTargets {
				if exclude[target.Namespace] {
					continue
				}
				var obj *secret
				switch target.Kind {
				case commonsentinel.KubernetesSourceKindSecret:
					got, found, err := api.getSecret(ctx, target.Namespace, target.Name)
					if err != nil {
						s.logger.Warn("kubernetes scan: allowlist get failed", "cluster", spec.Name, "name", target.Name, "error", err)
						sweep.Complete = false
						setReason(&sweep, classifyError(err))
						continue
					}
					if !found {
						continue
					}
					obj = got
				case commonsentinel.KubernetesSourceKindConfigMap:
					got, found, err := api.getConfigMap(ctx, target.Namespace, target.Name)
					if err != nil {
						s.logger.Warn("kubernetes scan: allowlist get failed", "cluster", spec.Name, "name", target.Name, "error", err)
						sweep.Complete = false
						setReason(&sweep, classifyError(err))
						continue
					}
					if !found {
						continue
					}
					obj = configMapAsSecret(got)
				}
				if !s.collect(res, seen, collectedKeys, spec.Name, target.Kind, obj, target.Keys, &sweep) {
					sweep.Complete, capped = false, true
					setReason(&sweep, commonsentinel.KubernetesReasonTruncated)
					break
				}
			}
		}

		if ctx.Err() != nil {
			sweep.Complete = false
			setReason(&sweep, commonsentinel.KubernetesReasonTimeout)
		}
		sort.Strings(sweep.ObservedKeys) // deterministic output
		res.Sweeps = append(res.Sweeps, sweep)
	}
	res.Truncated = res.Truncated || capped
	return res
}

// collect extracts the allowed public material of one object, appends the
// deduplicated certificates and one observation per data key, and records the
// location keys. collectedKeys holds the location keys already emitted this
// cluster: a location key seen twice (a mesh target that is also tls-typed,
// reachable by both sweep passes) yields one observation, honoring the
// location_key reconciliation contract and the sweep observation cap. Returns
// false when a sweep-wide cap was hit.
func (s *Scanner) collect(res *SweepResult, seen, collectedKeys map[string]bool, cluster, kind string, obj *secret, allowedKeys []string, sweep *commonsentinel.KubernetesSweepResult) bool {
	// A hostile API server can return a namespace/name outside RFC 1123 (e.g.
	// containing "/"), which would forge or collide entries in the
	// "kind/namespace/name/dataKey" location-key set the backend reconciles on.
	// Skip such an object rather than emit an ambiguous key; the length bounds
	// also honor the namespace/secret_name wire caps. Impact is confined to the
	// attacker's own cluster (one observation omitted), so this is not a
	// sweep-wide failure.
	if !validObjectName(obj.Metadata.Namespace, maxNamespaceChars) || !validObjectName(obj.Metadata.Name, maxObjectNameChars) {
		s.logger.Warn("kubernetes scan: skipping object with non-RFC1123 namespace/name",
			"cluster", cluster, "namespace", obj.Metadata.Namespace, "name", obj.Metadata.Name)
		return true
	}

	perKey := map[string][]string{} // data key -> fingerprints in file order
	certs, truncated := extractPublicMaterial(obj.Data, allowedKeys)
	if truncated {
		res.Truncated = true
		sweep.Complete = false
		setReason(sweep, commonsentinel.KubernetesReasonTruncated)
	}
	for _, ec := range certs {
		fp := fingerprintHex(ec.der)
		if !seen[fp] {
			if len(res.Certificates) >= maxCertsPerSweep || res.derBytes+len(ec.der) > maxCertBytesPerSweep {
				return false
			}
			seen[fp] = true
			res.derBytes += len(ec.der)
			res.Certificates = append(res.Certificates, commonsentinel.Certificate{
				FingerprintSHA256: fp,
				DER:               ec.der,
			})
		}
		perKey[ec.dataKey] = append(perKey[ec.dataKey], fp)
	}

	keys := make([]string, 0, len(perKey))
	for k := range perKey {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, dataKey := range keys {
		lk := LocationKey(kind, obj.Metadata.Namespace, obj.Metadata.Name, dataKey)
		if collectedKeys[lk] {
			continue // already emitted this cluster by the other sweep pass
		}
		if len(res.Observations) >= maxObservationsPerSweep {
			return false
		}
		collectedKeys[lk] = true
		obs := commonsentinel.SentinelKubernetesObservation{
			Cluster:                   cluster,
			Namespace:                 obj.Metadata.Namespace,
			SecretName:                obj.Metadata.Name,
			SourceKind:                kind,
			DataKey:                   dataKey,
			ObservedChainFingerprints: perKey[dataKey],
		}
		if _, ok := obj.Metadata.Annotations[annotationCertManagerName]; ok {
			obs.ManagedBy = "cert-manager"
		}
		res.Observations = append(res.Observations, obs)
		sweep.ObservedKeys = append(sweep.ObservedKeys, lk)
	}
	return true
}

// configMapAsSecret adapts a ConfigMap to the secret shape so collect handles
// both. ConfigMap string data becomes bytes; Type stays empty (ConfigMaps
// have no type).
func configMapAsSecret(cm *configMap) *secret {
	data := make(map[string][]byte, len(cm.Data)+len(cm.BinaryData))
	for k, v := range cm.Data {
		data[k] = []byte(v)
	}
	for k, v := range cm.BinaryData {
		data[k] = v
	}
	return &secret{Metadata: cm.Metadata, Data: data}
}

// fingerprintHex mirrors scanner.Fingerprint / filesystem.fingerprintHex
// (duplicated to avoid cross-package coupling for two lines).
func fingerprintHex(der []byte) string {
	sum := sha256.Sum256(der)
	return hex.EncodeToString(sum[:])
}

// validObjectName gates an API-returned namespace or object name to the RFC
// 1123 charset ([a-z0-9.-]) and a length bound before it is concatenated into a
// location key. It is a safety gate against a hostile API server, not a full
// RFC validator: the point is that a "/" (or any out-of-charset byte) can never
// forge or collide the reconciliation key, and an over-length name can never
// break the namespace/secret_name wire caps.
func validObjectName(s string, maxLen int) bool {
	if s == "" || len(s) > maxLen {
		return false
	}
	for _, r := range s {
		if (r < 'a' || r > 'z') && (r < '0' || r > '9') && r != '.' && r != '-' {
			return false
		}
	}
	return true
}
