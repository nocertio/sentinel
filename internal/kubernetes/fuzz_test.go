package kubernetes

import (
	"bytes"
	"reflect"
	"testing"

	"nocert.io/sentinel/internal/certshape"
)

func FuzzPublicMaterialIsolation(f *testing.F) {
	for _, seed := range [][]byte{nil, shapedCert("leaf"), pemCert("leaf"), bytes.Repeat(pemCert("chain"), maxCertsPerValue+1), shapedCert(string(bytes.Repeat([]byte{'A'}, maxDERBytes)))} {
		f.Add(seed, []byte("ignored material"))
	}
	f.Fuzz(func(t *testing.T, public, ignored []byte) {
		if len(public) > 128*1024 || len(ignored) > 128*1024 {
			t.Skip()
		}
		beforePublic, beforeIgnored := bytes.Clone(public), bytes.Clone(ignored)
		allowed := map[string][]byte{"tls.crt": public, "ca.crt": pemCert("ca")}
		want, wantTruncated := extractPublicMaterial(allowed, tlsSecretPublicKeys)
		allowed["tls.key"], allowed["unapproved.crt"] = ignored, ignored
		got, truncated := extractPublicMaterial(allowed, tlsSecretPublicKeys)
		if !reflect.DeepEqual(got, want) || truncated != wantTruncated {
			t.Fatal("unapproved keys influenced the public result")
		}
		if !bytes.Equal(public, beforePublic) || !bytes.Equal(ignored, beforeIgnored) {
			t.Fatal("extraction modified secret data")
		}
		if len(got) > len(tlsSecretPublicKeys)*maxCertsPerValue {
			t.Fatal("certificate count limit exceeded")
		}
		for _, cert := range got {
			if (cert.dataKey != "tls.crt" && cert.dataKey != "ca.crt") || len(cert.der) > maxDERBytes || !certshape.LooksLikeCertificateDER(cert.der) {
				t.Fatal("unsafe public material")
			}
		}
	})
}
