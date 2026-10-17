package kubernetes

import (
	"encoding/pem"

	"nocert.io/sentinel/internal/certshape"
)

const (
	// maxDERBytes mirrors the backend per-cert wire cap; oversized material
	// is dropped here (it could never ship anyway).
	maxDERBytes = 64 * 1024
	// maxCertsPerValue caps the certificates read out of one data key. 16
	// mirrors the observed_chain_fingerprints maxItems of the report wire
	// contract: a hostile Secret packing
	// more CERTIFICATE blocks into one value would build an over-contract
	// observation the backend rejects with 400, failing the whole report. A
	// real leaf+chain or trust bundle stays well under.
	maxCertsPerValue = 16
)

// tlsSecretPublicKeys are the only data keys read from kubernetes.io/tls
// Secrets. tls.key is deliberately absent and must stay absent.
var tlsSecretPublicKeys = []string{"tls.crt", "ca.crt"}

// extractedCert is one raw DER certificate extracted from one data key.
type extractedCert struct {
	dataKey string
	der     []byte
}

// extractPublicMaterial is the single redaction boundary of the connector:
// the API server returns whole Secrets (tls.key included - Kubernetes offers
// no field projection on Secrets), and ONLY the data keys listed in
// allowedKeys are ever read past this function. Non-allowlisted values are
// never copied, logged, or buffered. Extraction is structural (PEM
// CERTIFICATE blocks, or a raw DER SEQUENCE tag) - never parsed: the backend
// sandboxed parser is the sole X.509 parser, as everywhere in this agent.
func extractPublicMaterial(data map[string][]byte, allowedKeys []string) []extractedCert {
	var out []extractedCert
	for _, key := range allowedKeys {
		value, ok := data[key]
		if !ok {
			continue
		}
		for _, der := range certDERBlocks(value) {
			if len(der) > maxDERBytes {
				continue
			}
			out = append(out, extractedCert{dataKey: key, der: der})
		}
	}
	return out
}

// certDERBlocks mirrors filesystem.extractCertDER (kept in step with it,
// sharing only the leaf certshape gate to avoid a filesystem import): collect
// PEM CERTIFICATE blocks, else accept a single raw DER value, then pass each
// candidate through the structural gate so that a private key mislabelled
// under tls.crt/ca.crt (as a CERTIFICATE PEM block or raw key DER) is never
// shipped. Parsing itself stays with the backend's parser sandbox.
func certDERBlocks(data []byte) [][]byte {
	var candidates [][]byte
	rest := data
	for len(rest) > 0 && len(candidates) < maxCertsPerValue {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type == "CERTIFICATE" {
			candidates = append(candidates, block.Bytes)
		}
	}
	if len(candidates) == 0 && len(data) > 0 && data[0] == 0x30 {
		candidates = [][]byte{data}
	}
	var ders [][]byte
	for _, der := range candidates {
		if certshape.LooksLikeCertificateDER(der) {
			ders = append(ders, der)
		}
	}
	return ders
}
