package signing

import (
	"bytes"
	"crypto/ed25519"
	"net/http"
	"testing"

	"nocert.io/common/pkg/httpsig"
)

func seedKey(b byte) ed25519.PrivateKey {
	return ed25519.NewKeyFromSeed(bytes.Repeat([]byte{b}, ed25519.SeedSize))
}

// TestSignRequest_RoundTrip confirms a request the sentinel signs verifies under
// the shared RFC 9421 verifier - the wire-format contract with the backend.
func TestSignRequest_RoundTrip(t *testing.T) {
	priv := seedKey(0x33)
	pub := priv.Public().(ed25519.PublicKey)

	body := []byte(`{}`)
	req, err := http.NewRequest("POST", "https://nocert.local/api/v1/sentinels/x/report", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	if err := SignRequest(req, body, priv, "test-key"); err != nil {
		t.Fatalf("SignRequest: %v", err)
	}
	if err := httpsig.VerifyRequest(req, pub, "test-key", nil); err != nil {
		t.Errorf("verify: %v", err)
	}
}

// signedResponse builds a server-signed response bound to tag.
func signedResponse(body []byte, priv ed25519.PrivateKey, keyID, tag string) *http.Response {
	digest, sigInput, sig := httpsig.SignResponse(http.StatusOK, body, tag, priv, keyID)
	resp := &http.Response{StatusCode: http.StatusOK, Header: http.Header{}}
	resp.Header.Set("Content-Digest", digest)
	resp.Header.Set("Signature-Input", sigInput)
	resp.Header.Set("Signature", sig)
	return resp
}

func TestVerifyResponse_AcceptsValid(t *testing.T) {
	priv := seedKey(0x55)
	resp := signedResponse([]byte(`{"ok":true}`), priv, "server-1", "nonce-from-client")
	if err := VerifyResponse(resp, "nonce-from-client", priv.Public().(ed25519.PublicKey), "server-1"); err != nil {
		t.Errorf("VerifyResponse: %v", err)
	}
}

func TestVerifyResponse_RejectsWrongTag(t *testing.T) {
	priv := seedKey(0x55)
	resp := signedResponse([]byte(`{"ok":true}`), priv, "server-1", "some-other-tag")
	if err := VerifyResponse(resp, "nonce-from-client", priv.Public().(ed25519.PublicKey), "server-1"); err == nil {
		t.Error("expected error for mismatched tag, got nil")
	}
}

func TestVerifyResponse_RejectsWrongServerKey(t *testing.T) {
	wrong := seedKey(0x77)
	expected := seedKey(0x55)
	resp := signedResponse([]byte(`{"ok":true}`), wrong, "server-1", "nonce-from-client")
	if err := VerifyResponse(resp, "nonce-from-client", expected.Public().(ed25519.PublicKey), "server-1"); err == nil {
		t.Error("expected error for wrong server key, got nil")
	}
}

func TestVerifyResponse_RejectsMissingSignatureInput(t *testing.T) {
	priv := seedKey(0x55)
	resp := signedResponse([]byte(`{"ok":true}`), priv, "server-1", "nonce-from-client")
	resp.Header.Del("Signature-Input")
	resp.Header.Del("Signature")
	if err := VerifyResponse(resp, "nonce-from-client", priv.Public().(ed25519.PublicKey), "server-1"); err == nil {
		t.Error("expected error for missing Signature-Input, got nil")
	}
}

func TestNonceFromRequest_ReturnsStampedNonce(t *testing.T) {
	priv := seedKey(0x33)
	req, err := http.NewRequest("POST", "https://nocert.local/foo", bytes.NewReader([]byte(`{}`)))
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	if err := SignRequest(req, []byte(`{}`), priv, "test-key"); err != nil {
		t.Fatalf("SignRequest: %v", err)
	}
	nonce, err := NonceFromRequest(req)
	if err != nil {
		t.Fatalf("NonceFromRequest: %v", err)
	}
	if len(nonce) != 32 {
		t.Errorf("expected 32-char hex nonce, got %q (len %d)", nonce, len(nonce))
	}
}
