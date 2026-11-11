package tlsenum

import (
	"encoding/binary"
	"errors"
	"io"
	"slices"
)

// SSLv2 cipher specs are 24-bit values in their own namespace.
var ssl2Ciphers = []uint32{0x010080, 0x020080, 0x030080, 0x040080, 0x050080, 0x060040, 0x0700C0}

func ssl2ClientHello(random [32]byte) []byte {
	body := []byte{1, 0, versionSSL20}
	body = appendU16(body, uint16(3*len(ssl2Ciphers)))
	body = append(body, 0, 0, 0, 32) // no session resumption; fresh challenge
	for _, cipher := range ssl2Ciphers {
		body = appendU24(body, int(cipher))
	}
	body = append(body, random[:]...)
	return append([]byte{0x80 | byte(len(body)>>8), byte(len(body))}, body...)
}

func readSSL2Hello(r io.Reader) (*Collection, error) {
	var hdr [2]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return nil, err
	}
	n, padding := int(hdr[0]&0x7f)<<8|int(hdr[1]), 0
	if hdr[0]&0x80 == 0 {
		if hdr[0]&0x40 != 0 {
			return nil, errors.New("tlsenum: SSLv2 escape record")
		}
		var pad [1]byte
		if _, err := io.ReadFull(r, pad[:]); err != nil {
			return nil, err
		}
		n, padding = int(hdr[0]&0x3f)<<8|int(hdr[1]), int(pad[0])
	}
	if n < 11 || padding != 0 {
		return nil, errors.New("tlsenum: invalid SSLv2 plaintext length")
	}
	body := make([]byte, n) // bounded by the 15-bit record length
	if _, err := io.ReadFull(r, body); err != nil {
		return nil, err
	}
	if body[0] != 4 || body[1] != 0 || body[2] != 1 || binary.BigEndian.Uint16(body[3:5]) != versionSSL20 {
		return nil, errors.New("tlsenum: invalid SSLv2 ServerHello")
	}
	certLen := int(binary.BigEndian.Uint16(body[5:7]))
	cipherLen := int(binary.BigEndian.Uint16(body[7:9]))
	idLen := int(binary.BigEndian.Uint16(body[9:11]))
	if certLen == 0 || cipherLen == 0 || cipherLen%3 != 0 || cipherLen > 3*len(ssl2Ciphers) || idLen < 16 || idLen > 32 || 11+certLen+cipherLen+idLen != len(body) {
		return nil, errors.New("tlsenum: invalid SSLv2 fields")
	}
	result := &Collection{Version: versionSSL20, Certificates: [][]byte{body[11 : 11+certLen : 11+certLen]}}
	for off := 11 + certLen; off < 11+certLen+cipherLen; off += 3 {
		cipher := uint32(u24(body[off:]))
		if !slices.Contains(ssl2Ciphers, cipher) || slices.Contains(result.SSL2Ciphers, cipher) {
			return nil, errors.New("tlsenum: unoffered or duplicate SSLv2 cipher")
		}
		result.SSL2Ciphers = append(result.SSL2Ciphers, cipher)
	}
	return result, nil
}
