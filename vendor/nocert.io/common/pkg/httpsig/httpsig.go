// Package httpsig implements the exact subset of RFC 9421 HTTP Message
// Signatures that the NoCert backend and its agents speak: Ed25519 over a fixed
// set of covered components, with an RFC 9530 Content-Digest. It exists so the
// platform depends on the standard library alone for this path instead of a
// JOSE stack - the covered-component set is frozen by the wire contract, so a
// focused implementation is auditable end to end.
//
// Requests cover ("@method" "@target-uri" "@authority" "content-digest") with
// params created, nonce, alg, keyid. Responses cover ("@status" "content-digest")
// with params created, alg, tag, keyid, where tag binds the response to the
// request's nonce. The signature label is always "sig1".
package httpsig

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// Label is the sf-dictionary key under which Signature-Input and Signature are
// written. Backend and agents must agree on it.
const Label = "sig1"

const algEd25519 = "ed25519"

// RequestComponents and ResponseComponents are the covered components, in the
// order they appear in the signature base. Frozen by the OpenAPI contract.
var (
	RequestComponents  = []string{"@method", "@target-uri", "@authority", "content-digest"}
	ResponseComponents = []string{"@status", "content-digest"}
)

// SchemeResolver lets a verifier behind a TLS-terminating proxy supply the
// original request scheme (from e.g. X-Forwarded-Proto). Returning "" falls
// back to req.TLS. It never weakens authentication - it only selects which
// @target-uri string the base is rebuilt with; a wrong value fails the signature.
type SchemeResolver func(*http.Request) string

// ContentDigest returns the RFC 9530 Content-Digest header value for body,
// using SHA-256: `sha-256=:<base64>:`.
func ContentDigest(body []byte) string {
	sum := sha256.Sum256(body)
	return "sha-256=:" + base64.StdEncoding.EncodeToString(sum[:]) + ":"
}

// GenerateNonce returns 16 random bytes hex-encoded (32 chars).
func GenerateNonce() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("nonce: %w", err)
	}
	return hex.EncodeToString(b), nil
}

// SignRequest sets Content-Digest, Signature-Input and Signature on req, signing
// the fixed request components with priv under keyID and a freshly generated
// nonce. body is the exact bytes the request will send.
func SignRequest(req *http.Request, body []byte, priv ed25519.PrivateKey, keyID string) error {
	nonce, err := GenerateNonce()
	if err != nil {
		return err
	}
	digest := ContentDigest(body)
	req.Header.Set("Content-Digest", digest)

	created := time.Now().Unix()
	params := serializeParams(RequestComponents, created, nonce, algEd25519, "", keyID)
	base, err := requestBase(req, "", digest, params)
	if err != nil {
		return err
	}
	setSignature(req.Header, priv, base, params)
	return nil
}

// VerifyRequest checks the RFC 9421 signature on req against pub, requiring the
// keyid inside Signature-Input to equal keyID. It verifies only the signature -
// timestamp skew and nonce replay are the caller's responsibility. scheme may be
// nil; when set it supplies the @target-uri scheme for a proxied request.
func VerifyRequest(req *http.Request, pub ed25519.PublicKey, keyID string, scheme SchemeResolver) error {
	// ed25519.Verify panics on a wrong-length key; return an error instead so a
	// caller that forgets to validate the key gets a rejection, not a crash.
	if len(pub) != ed25519.PublicKeySize {
		return fmt.Errorf("invalid public key length")
	}
	sig, err := parseSignature(req.Header)
	if err != nil {
		return err
	}
	if sig.keyID != keyID {
		return fmt.Errorf("keyid mismatch")
	}
	if err := sig.checkComponents(RequestComponents); err != nil {
		return err
	}
	schemeOverride := ""
	if scheme != nil {
		schemeOverride = scheme(req)
	}
	digest := req.Header.Get("Content-Digest")
	base, err := requestBase(req, schemeOverride, digest, sig.params)
	if err != nil {
		return err
	}
	if !ed25519.Verify(pub, []byte(base), sig.signature) {
		return fmt.Errorf("signature verification failed")
	}
	return nil
}

// SignResponse returns the Content-Digest, Signature-Input and Signature header
// values for a response with the given status and body, signed by priv under
// keyID. When requestNonce is non-empty the response is bound to it via the tag
// parameter. The caller writes the three headers (kept separate so it can commit
// them atomically).
func SignResponse(statusCode int, body []byte, requestNonce string, priv ed25519.PrivateKey, keyID string) (digest, sigInput, signature string) {
	digest = ContentDigest(body)
	created := time.Now().Unix()
	params := serializeParams(ResponseComponents, created, "", algEd25519, requestNonce, keyID)
	base := responseBase(statusCode, digest, params)
	sig := ed25519.Sign(priv, []byte(base))
	return digest, Label + "=" + params, Label + "=:" + base64.StdEncoding.EncodeToString(sig) + ":"
}

// VerifyResponse checks the signature on resp against pub, requiring the keyid to
// equal keyID and the tag parameter to equal requestNonce (binding the response
// to the request that produced requestNonce).
func VerifyResponse(resp *http.Response, requestNonce string, pub ed25519.PublicKey, keyID string) error {
	if len(pub) != ed25519.PublicKeySize {
		return fmt.Errorf("invalid public key length")
	}
	sig, err := parseSignature(resp.Header)
	if err != nil {
		return err
	}
	if sig.keyID != keyID {
		return fmt.Errorf("keyid mismatch")
	}
	if sig.tag != requestNonce {
		return fmt.Errorf("response tag does not match request nonce")
	}
	if err := sig.checkComponents(ResponseComponents); err != nil {
		return err
	}
	digest := resp.Header.Get("Content-Digest")
	base := responseBase(resp.StatusCode, digest, sig.params)
	if !ed25519.Verify(pub, []byte(base), sig.signature) {
		return fmt.Errorf("signature verification failed")
	}
	return nil
}

// Details holds the Signature-Input parameters a caller may need before (or
// without) cryptographic verification - the middleware reads keyid to look up
// the sentinel, created for skew, and nonce for replay defense.
type Details struct {
	KeyID   string
	Created int64 // 0 if absent
	Nonce   string
	Tag     string
}

// RequestDetails parses the Signature-Input header on req without verifying the
// signature.
func RequestDetails(req *http.Request) (*Details, error) {
	sig, err := parseSignature(req.Header)
	if err != nil {
		return nil, err
	}
	return &Details{KeyID: sig.keyID, Created: sig.created, Nonce: sig.nonce, Tag: sig.tag}, nil
}

// --- signature base construction ---

func requestBase(req *http.Request, schemeOverride, digest, params string) (string, error) {
	if digest == "" {
		return "", fmt.Errorf("missing Content-Digest")
	}
	var b strings.Builder
	b.WriteString(`"@method": ` + req.Method + "\n")
	b.WriteString(`"@target-uri": ` + targetURI(req, schemeOverride) + "\n")
	b.WriteString(`"@authority": ` + authority(req) + "\n")
	b.WriteString(`"content-digest": ` + digest + "\n")
	b.WriteString(`"@signature-params": ` + params)
	return b.String(), nil
}

func responseBase(statusCode int, digest, params string) string {
	var b strings.Builder
	b.WriteString(`"@status": ` + strconv.Itoa(statusCode) + "\n")
	b.WriteString(`"content-digest": ` + digest + "\n")
	b.WriteString(`"@signature-params": ` + params)
	return b.String()
}

func targetURI(req *http.Request, schemeOverride string) string {
	scheme := schemeOverride
	if scheme == "" {
		switch {
		case req.URL.Scheme != "":
			scheme = req.URL.Scheme
		case req.TLS != nil:
			scheme = "https"
		default:
			scheme = "http"
		}
	}
	return scheme + "://" + authority(req) + req.URL.RequestURI()
}

// authority returns the @authority component value. It is taken verbatim (no
// case normalization), matching what the peer signs: the client sends Host =
// URL.Host, so the server sees the same string the signer used. Real server_urls
// are lowercase, so this only matters for byte-for-byte parity with the wire.
func authority(req *http.Request) string {
	if req.Host != "" {
		return req.Host
	}
	return req.URL.Host
}

// serializeParams builds the RFC 8941 inner-list-with-parameters shared by the
// signature base's @signature-params line and the Signature-Input header value.
// Parameters are emitted in httpsign's order: created, nonce, alg, tag, keyid;
// nonce is empty for responses and tag is empty for requests.
func serializeParams(components []string, created int64, nonce, alg, tag, keyID string) string {
	quoted := make([]string, len(components))
	for i, c := range components {
		quoted[i] = `"` + c + `"`
	}
	var b strings.Builder
	b.WriteString("(" + strings.Join(quoted, " ") + ")")
	b.WriteString(";created=" + strconv.FormatInt(created, 10))
	if nonce != "" {
		b.WriteString(`;nonce="` + nonce + `"`)
	}
	if alg != "" {
		b.WriteString(`;alg="` + alg + `"`)
	}
	if tag != "" {
		b.WriteString(`;tag="` + tag + `"`)
	}
	b.WriteString(`;keyid="` + keyID + `"`)
	return b.String()
}

func setSignature(h http.Header, priv ed25519.PrivateKey, base, params string) {
	sig := ed25519.Sign(priv, []byte(base))
	h.Set("Signature-Input", Label+"="+params)
	h.Set("Signature", Label+"=:"+base64.StdEncoding.EncodeToString(sig)+":")
}

// --- Signature-Input / Signature parsing ---

type parsedSignature struct {
	components []string
	params     string // verbatim ";..." + inner list, as re-serialized for the base
	keyID      string
	created    int64
	nonce      string
	tag        string
	alg        string
	signature  []byte
}

func (s *parsedSignature) checkComponents(want []string) error {
	if len(s.components) != len(want) {
		return fmt.Errorf("unexpected covered components")
	}
	for i := range want {
		if s.components[i] != want[i] {
			return fmt.Errorf("unexpected covered component %q", s.components[i])
		}
	}
	return nil
}

// parseSignature reads the Signature-Input and Signature headers under Label and
// returns the covered components, the raw params (re-serialized so the verifier
// reconstructs the exact base the signer used), the individual parameters, and
// the decoded signature bytes.
func parseSignature(h http.Header) (*parsedSignature, error) {
	rawInput := h.Get("Signature-Input")
	if rawInput == "" {
		return nil, fmt.Errorf("missing Signature-Input")
	}
	value, err := dictValue(rawInput, Label)
	if err != nil {
		return nil, fmt.Errorf("signature-input header: %w", err)
	}
	s := &parsedSignature{params: value}

	inner, rest, ok := strings.Cut(value, ")")
	if !ok || !strings.HasPrefix(inner, "(") {
		return nil, fmt.Errorf("malformed covered-component list")
	}
	for _, c := range strings.Fields(inner[1:]) {
		name, err := unquote(c)
		if err != nil {
			return nil, fmt.Errorf("covered component: %w", err)
		}
		s.components = append(s.components, name)
	}

	for _, p := range splitParams(rest) {
		key, val, _ := strings.Cut(p, "=")
		switch key {
		case "keyid":
			s.keyID, err = unquote(val)
		case "nonce":
			s.nonce, err = unquote(val)
		case "tag":
			s.tag, err = unquote(val)
		case "alg":
			s.alg, err = unquote(val)
		case "created":
			s.created, err = strconv.ParseInt(val, 10, 64)
		}
		if err != nil {
			return nil, fmt.Errorf("parameter %q: %w", key, err)
		}
	}

	rawSig := h.Get("Signature")
	sigValue, err := dictValue(rawSig, Label)
	if err != nil {
		return nil, fmt.Errorf("signature header: %w", err)
	}
	enc := strings.TrimPrefix(strings.TrimSuffix(sigValue, ":"), ":")
	if enc == sigValue {
		return nil, fmt.Errorf("signature is not a byte-sequence")
	}
	s.signature, err = base64.StdEncoding.DecodeString(enc)
	if err != nil {
		return nil, fmt.Errorf("signature base64: %w", err)
	}
	return s, nil
}

// dictValue returns the value of the given key from an RFC 8941 dictionary
// header, requiring exactly the one entry we produce (no other members).
func dictValue(header, key string) (string, error) {
	prefix := key + "="
	if !strings.HasPrefix(header, prefix) {
		return "", fmt.Errorf("missing %q member", key)
	}
	return header[len(prefix):], nil
}

// splitParams splits a leading ";k=v;k=v..." string into its k=v members,
// respecting quoted-string values (which never contain ';' here).
func splitParams(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ";") {
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

func unquote(s string) (string, error) {
	if len(s) < 2 || s[0] != '"' || s[len(s)-1] != '"' {
		return "", fmt.Errorf("not a quoted string: %q", s)
	}
	return s[1 : len(s)-1], nil
}
