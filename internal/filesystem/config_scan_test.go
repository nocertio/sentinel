//go:build linux

package filesystem

import (
	"context"
	"os"
	"testing"
)

func TestExtractCertPaths(t *testing.T) {
	content := []byte(`
server {
    ssl_certificate     /etc/nginx/ssl/site.pem;
    ssl_certificate_key /etc/nginx/ssl/site.key;
}
# commented: /etc/old/legacy.crt
SSLCertificateFile "/opt/app/certs/app.cert"
relative = cert.pem
messy /etc/nginx/ssl/./site.pem
`)
	got := extractCertPaths(content)
	want := map[string]bool{
		"/etc/nginx/ssl/site.pem": true, // the "messy" form Cleans to this -> dedup
		"/etc/old/legacy.crt":     true,
		"/opt/app/certs/app.cert": true,
	}
	if len(got) != len(want) {
		t.Fatalf("got %d paths %v, want %d", len(got), got, len(want))
	}
	for _, p := range got {
		if !want[p] {
			t.Errorf("unexpected path %q", p)
		}
	}
}

func TestCollectConfigReferencedCertPaths(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(root+"/nginx/sites", 0o755); err != nil {
		t.Fatal(err)
	}
	writeTestFile(t, root+"/nginx/nginx.conf", "ssl_certificate /data/a.pem;")
	writeTestFile(t, root+"/nginx/sites/b.conf", "ssl_certificate /data/b.crt;")
	writeTestFile(t, root+"/notes.txt", "ssl_certificate /data/ignored.pem;")

	paths, complete := collectConfigReferencedCertPaths(context.Background(), root)
	if !complete {
		t.Fatal("expected complete=true")
	}
	got := map[string]bool{}
	for _, p := range paths {
		got[p] = true
	}
	if !got["/data/a.pem"] || !got["/data/b.crt"] || got["/data/ignored.pem"] {
		t.Fatalf("unexpected paths: %v", paths)
	}
}

func writeTestFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}
