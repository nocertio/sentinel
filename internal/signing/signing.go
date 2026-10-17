// Package signing is the sentinel's RFC 9421 facade over the shared
// nocert-common/pkg/httpsig primitive: sign every backend request, and verify
// the signed response, binding it to the request's nonce.
package signing

import (
	"crypto/ed25519"
	"fmt"
	"net/http"

	"nocert.io/common/pkg/httpsig"
)

// SignatureLabel is the sf-dictionary label on Signature-Input / Signature.
const SignatureLabel = httpsig.Label

// SignRequest sets Content-Digest, Signature-Input and Signature on req, signing
// the request with priv under keyID. body is the exact bytes req will send.
func SignRequest(req *http.Request, body []byte, priv ed25519.PrivateKey, keyID string) error {
	return httpsig.SignRequest(req, body, priv, keyID)
}

// VerifyResponse verifies resp against pub and requires its tag to equal
// requestNonce, binding the response to the request that produced it.
func VerifyResponse(resp *http.Response, requestNonce string, pub ed25519.PublicKey, keyID string) error {
	return httpsig.VerifyResponse(resp, requestNonce, pub, keyID)
}

// NonceFromRequest returns the nonce SignRequest stamped on req, which the
// transport passes to VerifyResponse to bind the response.
func NonceFromRequest(req *http.Request) (string, error) {
	d, err := httpsig.RequestDetails(req)
	if err != nil {
		return "", err
	}
	if d.Nonce == "" {
		return "", fmt.Errorf("missing nonce in signature-input")
	}
	return d.Nonce, nil
}
