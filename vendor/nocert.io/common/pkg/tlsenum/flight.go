package tlsenum

import (
	"encoding/binary"
	"errors"
	"io"
	"math/bits"

	"nocert.io/common/pkg/tlsconst"
	"nocert.io/common/pkg/tlsprobe"
)

const (
	maxFlightBytes        = 1 << 20
	maxFlightRecords      = 256
	maxFlightMessages     = 16
	maxCertificateMessage = 3 + tlsprobe.MaxChainDepth*(3+tlsprobe.MaxCertSize)
)

// flightReader reassembles handshake messages across records. Limits apply to
// bytes, record count and message count independently of the socket deadline.
type flightReader struct {
	r        io.Reader
	fragment []byte
	records  int
}

func (r *flightReader) readFull(dst []byte) error {
	for len(dst) > 0 {
		if len(r.fragment) == 0 {
			r.records++
			if r.records > maxFlightRecords {
				return errors.New("tlsenum: record limit")
			}
			var hdr [5]byte
			if _, err := io.ReadFull(r.r, hdr[:]); err != nil {
				return err
			}
			n := int(binary.BigEndian.Uint16(hdr[3:]))
			if hdr[1] != 3 || hdr[2] > 3 || n == 0 || n > 16384 {
				return errors.New("tlsenum: invalid plaintext record")
			}
			if hdr[0] != recordHandshake {
				return errors.New("tlsenum: server flight interrupted")
			}
			r.fragment = make([]byte, n)
			if _, err := io.ReadFull(r.r, r.fragment); err != nil {
				return err
			}
		}
		n := copy(dst, r.fragment)
		dst, r.fragment = dst[n:], r.fragment[n:]
	}
	return nil
}

func (r *flightReader) message() (byte, []byte, error) {
	var hdr [4]byte
	if err := r.readFull(hdr[:]); err != nil {
		return 0, nil, err
	}
	n := u24(hdr[1:])
	limit := maxResponseBytes
	if hdr[0] == 11 {
		limit = maxCertificateMessage
	}
	if n > limit {
		return 0, nil, errors.New("tlsenum: handshake message limit")
	}
	b := make([]byte, n)
	return hdr[0], b, r.readFull(b)
}

func readServerFlight(src io.Reader, offeredVersion uint16, offered []uint16) (*Collection, error) {
	r := &flightReader{r: io.LimitReader(src, maxFlightBytes)}
	typ, body, err := r.message()
	if err != nil {
		return nil, err
	}
	if typ != hsServerHello {
		return nil, errors.New("tlsenum: expected ServerHello")
	}
	frame := appendU24([]byte{typ}, len(body))
	cipher, version, err := parseServerHello(append(frame, body...), versionSSL30)
	if err != nil {
		return nil, err
	}
	if err = validateSelection(version, cipher, offeredVersion, offered); err != nil {
		return nil, err
	}
	result := &Collection{Version: version, Cipher: cipher}
	seenCert, seenKey, seenRequest := false, false, false
	for i := 1; i < maxFlightMessages; i++ {
		typ, body, err = r.message()
		if err != nil {
			return result, err
		}
		switch typ {
		case 11: // Certificate
			if seenCert || seenKey || seenRequest {
				return result, errors.New("tlsenum: unexpected Certificate")
			}
			seenCert = true
			certs, err := readCertificates(body)
			if err != nil {
				return result, err
			}
			result.Certificates = certs
		case 12: // ServerKeyExchange
			if seenKey || seenRequest {
				return result, errors.New("tlsenum: unexpected ServerKeyExchange")
			}
			seenKey = true
			if dhe, signed := tlsconst.FiniteFieldDHE(cipher); dhe {
				n, err := readDHBits(body, version, signed)
				if err != nil {
					return result, err
				}
				result.DHBits = n
			}
		case 13: // CertificateRequest; never supply a client certificate.
			if seenRequest || len(body) < 3 {
				return result, errors.New("tlsenum: invalid CertificateRequest")
			}
			seenRequest = true
		case 14: // ServerHelloDone
			if len(body) != 0 {
				return result, errors.New("tlsenum: invalid ServerHelloDone")
			}
			return result, nil
		default:
			return result, errors.New("tlsenum: unexpected handshake message")
		}
	}
	return result, errors.New("tlsenum: handshake message count limit")
}

func readCertificates(body []byte) ([][]byte, error) {
	if len(body) < 3 || u24(body) != len(body)-3 {
		return nil, errors.New("tlsenum: invalid certificate list")
	}
	body = body[3:]
	var out [][]byte
	for len(body) > 0 {
		if len(body) < 3 || len(out) >= tlsprobe.MaxChainDepth {
			return nil, errors.New("tlsenum: certificate chain limit")
		}
		n := u24(body)
		body = body[3:]
		if n == 0 || n > tlsprobe.MaxCertSize || n > len(body) {
			return nil, errors.New("tlsenum: invalid certificate length")
		}
		out = append(out, body[:n:n])
		body = body[n:]
	}
	if len(out) == 0 {
		return nil, errors.New("tlsenum: empty certificate chain")
	}
	return out, nil
}

func readDHBits(body []byte, version uint16, signed bool) (int, error) {
	p, rest, ok := readVector16(body)
	if !ok || len(p) > 2048 {
		return 0, errors.New("tlsenum: invalid DH modulus")
	}
	for len(p) > 0 && p[0] == 0 {
		p = p[1:]
	}
	if len(p) == 0 {
		return 0, errors.New("tlsenum: zero DH modulus")
	}
	n := (len(p)-1)*8 + bits.Len8(p[0])
	for i := 0; i < 2; i++ {
		value, tail, ok := readVector16(rest)
		if !ok || len(value) > 2048 {
			return 0, errors.New("tlsenum: invalid DH parameter")
		}
		rest = tail
	}
	if signed {
		if version >= versionTLS12 {
			if len(rest) < 2 {
				return 0, errors.New("tlsenum: missing DH signature algorithm")
			}
			rest = rest[2:]
		}
		_, tail, ok := readVector16(rest)
		if !ok {
			return 0, errors.New("tlsenum: invalid DH signature")
		}
		rest = tail
	}
	if len(rest) != 0 {
		return 0, errors.New("tlsenum: trailing DH data")
	}
	return n, nil
}
