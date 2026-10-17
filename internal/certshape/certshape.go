// Package certshape is a bounded, allocation-free structural gate that tells
// whether a DER blob has the outer shape of an X.509 certificate, WITHOUT
// parsing it.
//
// The sentinel ships raw DER to the backend, which is
// the sole X.509 parser. This gate exists only to refuse standard private-key
// encodings (PKCS#1, PKCS#8, SEC1) and obviously non-certificate ASN.1 before
// they ever leave the host, honouring the hard rule that a private key is
// never transmitted: a filesystem or Kubernetes file that happens to start
// with an ASN.1 SEQUENCE tag (0x30), or a PEM block mislabelled CERTIFICATE
// whose body is really a key, must not be forwarded as a "certificate".
//
// It is deliberately NOT a validator: it inspects only the first-level DER
// tags and lengths. Nothing inside the TBSCertificate (SANs, algorithms,
// signature) is examined.
package certshape

const (
	tagSequence  = 0x30 // universal, constructed SEQUENCE
	tagBitString = 0x03 // universal, primitive BIT STRING
)

// LooksLikeCertificateDER reports whether der has the outer TLV shape of an
// X.509 Certificate: SEQUENCE { SEQUENCE (tbsCertificate), SEQUENCE
// (signatureAlgorithm), BIT STRING (signatureValue) }, with definite, minimal
// DER lengths, the outer SEQUENCE spanning the whole input (no trailing
// bytes), and the signature BIT STRING ending the certificate.
//
// A private key (PKCS#1, PKCS#8, SEC1) opens its inner SEQUENCE with an
// INTEGER version, so it fails the first inner-element check; a random or
// truncated blob fails the length/structure checks. This is a shape gate, not
// a parser.
func LooksLikeCertificateDER(der []byte) bool {
	// Outer SEQUENCE must span the whole input exactly.
	tag, contentStart, contentEnd, next, ok := readTLV(der, 0)
	if !ok || tag != tagSequence || next != len(der) {
		return false
	}
	body := der[contentStart:contentEnd]

	// Element 1: tbsCertificate - a SEQUENCE.
	tag, _, _, n1, ok := readTLV(body, 0)
	if !ok || tag != tagSequence {
		return false
	}
	// Element 2: signatureAlgorithm - a SEQUENCE.
	tag, _, _, n2, ok := readTLV(body, n1)
	if !ok || tag != tagSequence {
		return false
	}
	// Element 3: signatureValue - a BIT STRING that ends the certificate.
	tag, cs3, ce3, n3, ok := readTLV(body, n2)
	if !ok || tag != tagBitString || n3 != len(body) {
		return false
	}
	// A signature BIT STRING is byte-aligned, so its first content octet (the
	// unused-bit count) is 0. This also rejects an empty BIT STRING.
	if ce3-cs3 < 1 || body[cs3] != 0x00 {
		return false
	}
	return true
}

// readTLV decodes one definite-length DER TLV starting at off within b. It
// returns the tag byte, the content bounds [contentStart, contentEnd), and
// next (the offset just past this TLV). ok is false on any malformed,
// indefinite, non-minimal, truncated, or overflowing length, or a high-tag
// number. It never allocates and never recurses.
func readTLV(b []byte, off int) (tag byte, contentStart, contentEnd, next int, ok bool) {
	if off < 0 || off >= len(b) {
		return 0, 0, 0, 0, false
	}
	tag = b[off]
	// Reject the high-tag-number form (low 5 bits all set): certificates use
	// only low-tag universal tags, and supporting multi-byte tags would add
	// parsing this gate does not need.
	if tag&0x1f == 0x1f {
		return 0, 0, 0, 0, false
	}
	i := off + 1
	if i >= len(b) {
		return 0, 0, 0, 0, false
	}
	lb := b[i]
	i++

	var length int
	if lb < 0x80 {
		length = int(lb) // short form
	} else {
		numBytes := int(lb & 0x7f)
		if numBytes == 0 {
			return 0, 0, 0, 0, false // 0x80 = indefinite length, forbidden in DER
		}
		// Bound the length-of-length. Four bytes cover any certificate this
		// agent handles and keep the accumulation below within a 64-bit int.
		if numBytes > 4 {
			return 0, 0, 0, 0, false
		}
		if i+numBytes > len(b) {
			return 0, 0, 0, 0, false
		}
		if b[i] == 0x00 {
			return 0, 0, 0, 0, false // non-minimal: leading zero length byte
		}
		for j := 0; j < numBytes; j++ {
			length = length<<8 | int(b[i+j])
		}
		i += numBytes
		if length < 0x80 {
			return 0, 0, 0, 0, false // non-minimal: should have used short form
		}
	}

	contentStart = i
	contentEnd = i + length
	// Content must lie within the buffer. contentEnd < contentStart also
	// catches any pathological overflow.
	if contentEnd < contentStart || contentEnd > len(b) {
		return 0, 0, 0, 0, false
	}
	return tag, contentStart, contentEnd, contentEnd, true
}
