package kubernetes

import commonsentinel "nocert.io/common/pkg/api/sentinel"

// wellKnownTarget is one named, versioned entry of the mesh/CA allowlist:
// an exact (kind, namespace, name) plus the PUBLIC data keys to read from it.
// The list is deliberately a plain var in the open-source tree so a security
// reviewer can audit exactly what the connector fetches beyond
// kubernetes.io/tls Secrets. Private-key data keys (ca-key.pem, key.pem,
// tls.key) must never appear here - enforced by a test.
type wellKnownTarget struct {
	Kind      string // commonsentinel.KubernetesSourceKindSecret or ...ConfigMap
	Namespace string
	Name      string
	Keys      []string
}

var wellKnownTargets = []wellKnownTarget{
	// Istio self-signed CA (type istio.io/ca-root - invisible to the
	// kubernetes.io/tls field selector).
	{Kind: commonsentinel.KubernetesSourceKindSecret, Namespace: "istio-system", Name: "istio-ca-secret", Keys: []string{"ca-cert.pem"}},
	// Istio plug-in CA (Opaque). ca-key.pem lives in the same Secret and is
	// deliberately NOT listed.
	{Kind: commonsentinel.KubernetesSourceKindSecret, Namespace: "istio-system", Name: "cacerts", Keys: []string{"ca-cert.pem", "root-cert.pem", "cert-chain.pem"}},
	// Linkerd issuer: Opaque (crt.pem) or kubernetes.io/tls (tls.crt)
	// depending on the install scheme; key.pem / tls.key stay behind.
	{Kind: commonsentinel.KubernetesSourceKindSecret, Namespace: "linkerd", Name: "linkerd-identity-issuer", Keys: []string{"crt.pem", "tls.crt", "ca.crt"}},
	// Linkerd trust anchor bundle: public-only ConfigMap; its 365-day
	// expiry with no auto-rotation is a classic outage cause.
	{Kind: commonsentinel.KubernetesSourceKindConfigMap, Namespace: "linkerd", Name: "linkerd-identity-trust-roots", Keys: []string{"ca-bundle.crt"}},
}
