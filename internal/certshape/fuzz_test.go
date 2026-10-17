package certshape

import (
	"bytes"
	"encoding/asn1"
	"testing"
)

func FuzzCertificateShape(f *testing.F) {
	for _, seed := range [][]byte{
		{}, {0x30, 7, 0x30, 0, 0x30, 0, 3, 1, 0},
		{0x30, 3, 2, 1, 0}, {0x30, 0x80, 0, 0},
		{0x30, 0x84, 0xff, 0xff, 0xff, 0xff},
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 128*1024 {
			t.Skip()
		}
		before := bytes.Clone(data)
		accepted := LooksLikeCertificateDER(data)
		if !bytes.Equal(data, before) {
			t.Fatal("shape gate modified its input")
		}
		if !accepted {
			return
		}
		// An independent stdlib decoder checks the accepted outer shape. Inner
		// certificate fields remain opaque; this is deliberately not X.509 validation.
		var outer asn1.RawValue
		rest, err := asn1.Unmarshal(data, &outer)
		if err != nil || len(rest) != 0 || outer.Class != 0 || outer.Tag != 16 || !outer.IsCompound {
			t.Fatal("accepted invalid outer DER sequence")
		}
		rest = outer.Bytes
		for _, wantTag := range []int{16, 16, 3} {
			var element asn1.RawValue
			rest, err = asn1.Unmarshal(rest, &element)
			if err != nil || element.Class != 0 || element.Tag != wantTag || element.IsCompound != (wantTag == 16) {
				t.Fatal("accepted invalid certificate element")
			}
			if wantTag == 3 && (len(element.Bytes) == 0 || element.Bytes[0] != 0) {
				t.Fatal("accepted non-byte-aligned signature")
			}
		}
		if len(rest) != 0 || LooksLikeCertificateDER(append(bytes.Clone(data), 0)) {
			t.Fatal("accepted trailing data")
		}
	})
}
