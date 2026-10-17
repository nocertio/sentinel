//go:build linux

package filesystem

import (
	"encoding/pem"

	"nocert.io/sentinel/internal/certshape"
)

const maxCertsPerFile = 50

// extractCertDER pulls raw DER certificate bytes out of a PEM or DER file
// WITHOUT decoding them as X.509: pem.Decode collects every CERTIFICATE block,
// or a file whose first byte is an ASN.1 SEQUENCE tag (0x30) is taken as a
// single DER certificate. Each candidate then passes a bounded structural gate
// (certshape) so that a private key mislabelled inside a CERTIFICATE PEM block,
// or a raw key file carrying a cert extension, is never shipped as a
// "certificate" - a private key must never leave the host. Discovery still
// does no crypto/x509 parsing; the backend is the sole
// parser, leaf/CA classifier and warning source. The bool is false when the
// PEM block limit prevented examining the whole bundle.
func extractCertDER(data []byte) ([][]byte, bool) {
	candidates, complete := pemCertBlocks(data)
	if len(candidates) == 0 && len(data) > 0 && data[0] == 0x30 {
		candidates = [][]byte{data}
	}
	var ders [][]byte
	for _, der := range candidates {
		if certshape.LooksLikeCertificateDER(der) {
			ders = append(ders, der)
		}
	}
	return ders, complete
}

func pemCertBlocks(data []byte) ([][]byte, bool) {
	var ders [][]byte
	rest := data
	for len(rest) > 0 {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type == "CERTIFICATE" {
			if len(ders) == maxCertsPerFile {
				return ders, false
			}
			ders = append(ders, block.Bytes)
		}
	}
	return ders, true
}
