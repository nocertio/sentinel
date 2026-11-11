//go:build integration

package scanner

import (
	"bytes"
	"context"
	"encoding/pem"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"nocert.io/common/pkg/tlsenum"
)

// The fixture runs with --network none. All keys and certificates are disposable.
func TestLegacyIntegration(t *testing.T) {
	binary := os.Getenv("OPENSSL_LEGACY")
	if binary == "" {
		t.Fatal("OPENSSL_LEGACY must point to the isolated fixture binary; run scripts/test-legacy-tls.sh")
	}
	dir := t.TempDir()
	config := filepath.Join(dir, "openssl.cnf")
	if err := os.WriteFile(config, []byte("[req]\ndistinguished_name=dn\n[dn]\n"), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("OPENSSL_CONF", config)
	t.Setenv("RANDFILE", filepath.Join(dir, ".rnd"))
	command := func(args ...string) {
		t.Helper()
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		cmd := exec.CommandContext(ctx, binary, args...)
		cmd.Dir = dir
		if output, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("fixture %v: %v\n%s", args, err, output)
		}
	}
	for _, hash := range []string{"sha1", "md5"} {
		command("req", "-new", "-x509", "-newkey", "rsa:1024", "-nodes", "-"+hash, "-subj", "/CN=legacy.invalid", "-days", "1", "-keyout", hash+".key", "-out", hash+".pem")
	}
	command("dsaparam", "-out", "dsa.params", "1024")
	command("gendsa", "-out", "dsa.key", "dsa.params")
	command("req", "-new", "-x509", "-key", "dsa.key", "-sha1", "-subj", "/CN=legacy.invalid", "-days", "1", "-out", "dsa.pem")
	command("dhparam", "-out", "dh.pem", "512")

	for _, tc := range []struct {
		name, protocol, cipher, certificate string
		version                             uint16
		complete                            bool
		dh                                  int
	}{
		{"tls12_rsa1024_sha1", "-tls1_2", "AES128-SHA", "sha1", 0x0303, true, 0},
		{"tls11_rsa1024_md5", "-tls1_1", "AES128-SHA", "md5", 0x0302, true, 0},
		{"tls10_rc4", "-tls1", "RC4-SHA", "sha1", 0x0301, true, 0},
		{"tls10_3des", "-tls1", "DES-CBC3-SHA", "sha1", 0x0301, true, 0},
		{"tls12_dhe512", "-tls1_2", "DHE-RSA-AES128-SHA", "sha1", 0x0303, false, 512},
		{"tls12_dsa", "-tls1_2", "DHE-DSS-AES128-SHA", "dsa", 0x0303, false, 512},
		{"tls10_export", "-tls1", "EXP-RC4-MD5", "sha1", 0x0301, false, 0},
		{"ssl3", "-ssl3", "DES-CBC3-SHA", "sha1", 0x0300, false, 0},
		{"ssl2", "-ssl2", "RC4-MD5", "sha1", 0x0002, false, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			port := legacyServer(t, binary, dir, tc.protocol, "-cipher", tc.cipher, "-cert", tc.certificate+".pem", "-key", tc.certificate+".key", "-dhparam", "dh.pem")
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			result, err := (&tlsProber{}).Probe(ctx, "127.0.0.1", port, time.Second, "legacy.invalid")
			if err != nil {
				t.Fatal(err)
			}
			if result.TLS == nil || result.TLS.TLSVersionID == nil || *result.TLS.TLSVersionID != tc.version {
				t.Fatalf("version: %+v", result.TLS)
			}
			if result.TLS.HandshakeComplete == nil || *result.TLS.HandshakeComplete != tc.complete {
				t.Fatalf("handshake: %+v", result.TLS.HandshakeComplete)
			}
			if int(result.TLS.DHBits) != tc.dh {
				t.Fatalf("DH bits: got %d want %d", result.TLS.DHBits, tc.dh)
			}
			if tc.dh > 0 {
				enum, err := tlsenum.Enumerate(ctx, "127.0.0.1", port, tlsenum.Options{Dialer: &net.Dialer{}, HandshakeTimeout: time.Second})
				if err != nil {
					t.Fatal(err)
				}
				if len(enum.Findings) != 1 || int(enum.Findings[0].DHBits) != tc.dh {
					t.Fatalf("DH enumeration: %+v", enum.Findings)
				}
			}
			certPEM, err := os.ReadFile(filepath.Join(dir, tc.certificate+".pem"))
			if err != nil {
				t.Fatal(err)
			}
			block, _ := pem.Decode(certPEM)
			out := (&Scanner{}).probeResultToOutput(port, "legacy.invalid", result, nil, false)
			if out == nil || len(out.Chain) == 0 || !bytes.Equal(out.Chain[0], block.Bytes) {
				t.Fatal("certificate DER was lost or changed")
			}
			if tc.name == "tls12_dhe512" {
				for _, f := range []preambleFixture{upgradeFixtures()[0], upgradeFixtures()[7]} {
					t.Run(f.name, func(t *testing.T) {
						addr := legacyUpgradeServer(t, f, port)
						d := &redirectDialer{base: &net.Dialer{}, addr: addr}
						r, err := (&tlsProber{dialer: d}).Probe(ctx, "127.0.0.1", f.port, time.Second, "legacy.invalid")
						if err != nil {
							t.Fatal(err)
						}
						if *r.TLS.HandshakeComplete || r.TLS.DHBits != 512 || len(r.RawChain) == 0 || !bytes.Equal(r.RawChain[0], block.Bytes) {
							t.Fatal("legacy certificate or DH evidence lost after upgrade")
						}
					})
				}
			}
			if tc.version <= 0x0300 && out.SNI != "" {
				t.Fatal("obsolete protocols must not claim SNI")
			}
			if tc.version == 0x0002 && (result.TLS.CipherSuiteID != nil || len(result.TLS.SSL2CipherSpecs) == 0) {
				t.Fatal("SSLv2 cipher namespace lost")
			}
		})
	}
	t.Run("gentle_ssl2_fallback", func(t *testing.T) {
		port := legacyServer(t, binary, dir, "-ssl2", "-cipher", "RC4-MD5", "-cert", "sha1.pem", "-key", "sha1.key")
		s := New(slog.Default())
		s.SetGentle(true)
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		ch, _ := s.ScanTargets(ctx, []Target{{Host: "127.0.0.1", Port: port}}, time.Second)
		var results []ProbeOutput
		for out := range ch {
			results = append(results, out)
		}
		if ctx.Err() != nil || len(results) != 1 {
			t.Fatalf("gentle fallback: %d results, %v", len(results), ctx.Err())
		}
		out := results[0]
		if out.TLS == nil || out.TLS.TLSVersionID == nil || *out.TLS.TLSVersionID != 0x0002 || len(out.Chain) == 0 {
			t.Fatal("gentle fallback did not retain the SSLv2 certificate")
		}
		if out.TLS.DeepEnumAttempted {
			t.Fatal("gentle fallback started deep enumeration")
		}
	})
	t.Run("anonymous_dh_without_certificate", func(t *testing.T) {
		port := legacyServer(t, binary, dir, "-tls1_2", "-nocert", "-cipher", "ADH-AES128-SHA", "-dhparam", "dh.pem")
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		result, err := (&tlsProber{}).Probe(ctx, "127.0.0.1", port, time.Second, "")
		if err != nil {
			t.Fatal(err)
		}
		if result.TLS.TLSVersionID == nil || *result.TLS.TLSVersionID != 0x0303 || result.TLS.DHBits != 512 || len(result.RawChain) != 0 {
			t.Fatalf("anonymous detection: %+v", result)
		}
		if result.TLS.HandshakeComplete == nil || *result.TLS.HandshakeComplete {
			t.Fatal("anonymous probe claimed completed handshake")
		}
	})
	t.Run("client_certificate_required", func(t *testing.T) {
		port := legacyServer(t, binary, dir, "-tls1_2", "-Verify", "1", "-cipher", "AES128-SHA", "-cert", "sha1.pem", "-key", "sha1.key")
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		result, err := (&tlsProber{}).Probe(ctx, "127.0.0.1", port, time.Second, "")
		if err != nil {
			t.Fatal(err)
		}
		out := (&Scanner{}).probeResultToOutput(port, "", result, nil, false)
		if len(out.Chain) == 0 || out.TLS.HandshakeComplete == nil || *out.TLS.HandshakeComplete {
			t.Fatal("client authentication must retain the certificate without claiming completion")
		}
	})

	t.Run("obsolete_alongside_modern", func(t *testing.T) {
		port := legacyServer(t, binary, dir, "-cipher", "RC4-MD5:DES-CBC3-SHA:AES128-SHA", "-cert", "sha1.pem", "-key", "sha1.key")
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		modern, err := (&tlsProber{}).Probe(ctx, "127.0.0.1", port, time.Second, "")
		if err != nil || modern.TLS.TLSVersionID == nil || *modern.TLS.TLSVersionID != 0x0303 {
			t.Fatalf("modern: %v %+v", err, modern)
		}
		results := tlsenum.CollectObsolete(ctx, "127.0.0.1", port, tlsenum.Options{Dialer: &net.Dialer{}, HandshakeTimeout: time.Second})
		versions := map[uint16]bool{}
		for _, result := range results {
			versions[result.Version] = true
		}
		if !versions[0x0300] {
			t.Fatalf("missing obsolete protocols: %v", versions)
		}
	})
}

func legacyServer(t *testing.T, binary, dir string, args ...string) int {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	_ = listener.Close()
	logFile, err := os.CreateTemp(dir, "server-*.log")
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(binary, append([]string{"s_server", "-accept", strconv.Itoa(port), "-quiet", "-www"}, args...)...)
	cmd.Dir, cmd.Stdout, cmd.Stderr = dir, logFile, logFile
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	exited := false
	t.Cleanup(func() {
		if !exited {
			_ = cmd.Process.Kill()
			<-done
		}
		_ = logFile.Close()
		if t.Failed() {
			data, _ := os.ReadFile(logFile.Name())
			t.Logf("server: %s", data)
		}
	})
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		select {
		case err := <-done:
			exited = true
			t.Fatalf("server exited: %v", err)
		default:
		}
		conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), 50*time.Millisecond)
		if err == nil {
			_ = conn.Close()
			return port
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("server startup timed out")
	return 0
}

// Relay only the test preamble; OpenSSL performs the legacy TLS exchange.
func legacyUpgradeServer(t *testing.T, f preambleFixture, port int) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			client, err := ln.Accept()
			if err != nil {
				return
			}
			_ = client.SetDeadline(time.Now().Add(3 * time.Second))
			if serveUpgrade(client, f) != nil {
				client.Close()
				continue
			}
			server, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)), time.Second)
			if err != nil {
				client.Close()
				continue
			}
			_ = server.SetDeadline(time.Now().Add(3 * time.Second))
			copied := make(chan struct{})
			go func() { _, _ = io.Copy(server, client); server.Close(); close(copied) }()
			_, _ = io.Copy(client, server)
			client.Close()
			server.Close()
			<-copied
		}
	}()
	t.Cleanup(func() { ln.Close(); <-done })
	return ln.Addr().String()
}
