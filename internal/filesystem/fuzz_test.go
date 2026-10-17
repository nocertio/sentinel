//go:build linux

package filesystem

import (
	"bytes"
	"encoding/pem"
	"testing"

	"nocert.io/sentinel/internal/certshape"
)

func FuzzCertificateExtraction(f *testing.F) {
	shape := []byte{0x30, 7, 0x30, 0, 0x30, 0, 3, 1, 0}
	block := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: shape})
	for _, seed := range [][]byte{nil, shape, block, bytes.Repeat(block, maxCertsPerFile+1), {0x30, 3, 2, 1, 0}} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 128*1024 {
			t.Skip()
		}
		before := bytes.Clone(data)
		ders, _ := extractCertDER(data)
		if !bytes.Equal(data, before) || len(ders) > maxCertsPerFile {
			t.Fatal("extraction modified input or exceeded certificate limit")
		}
		for _, der := range ders {
			if !certshape.LooksLikeCertificateDER(der) {
				t.Fatal("extracted non-certificate material")
			}
			wrapped := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
			again, complete := extractCertDER(wrapped)
			if !complete || len(again) != 1 || !bytes.Equal(again[0], der) {
				t.Fatal("certificate changed during PEM round trip")
			}
		}
		// Arbitrary bytes in a non-certificate PEM block must never escape.
		ignored := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: data})
		if got, complete := extractCertDER(ignored); len(got) != 0 || !complete {
			t.Fatal("extracted a non-certificate PEM block")
		}
	})
}
