package scanner

import (
	"bufio"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"strconv"
	"strings"
	"time"

	"nocert.io/common/pkg/tlsprobe"
)

var errTLSUpgrade = errors.New("TLS upgrade refused or invalid response")

// upgradeDialer runs only the unauthenticated preamble for a known service port.
// Every reconnect, including raw collection and enumeration, uses the same path.
type upgradeDialer struct{ base tlsprobe.ContextDialer }

func (d upgradeDialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	return d.DialContextWithTimeout(ctx, network, addr, tlsprobe.DefaultConnectTimeout)
}

func (d upgradeDialer) DialContextWithTimeout(ctx context.Context, network, addr string, timeout time.Duration) (net.Conn, error) {
	conn, err := tlsprobe.DialContext(ctx, d.base, network, addr, timeout)
	if err != nil {
		return nil, err
	}
	_, textPort, err := net.SplitHostPort(addr)
	if err != nil {
		conn.Close()
		return nil, errTLSUpgrade
	}
	port, _ := strconv.Atoi(textPort)
	if !upgradePort(port) {
		return conn, nil
	}
	if timeout <= 0 {
		timeout = tlsprobe.DefaultHandshakeTimeout
	}
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()
	if err = conn.SetDeadline(time.Now().Add(timeout)); err == nil {
		err = upgradeTLS(conn, port)
	}
	if err == nil {
		err = conn.SetDeadline(time.Time{})
	}
	if err != nil {
		conn.Close()
		return nil, errTLSUpgrade
	}
	return conn, nil
}

func upgradePort(port int) bool {
	switch port {
	case 21, 25, 110, 143, 389, 587, 3389, 5432:
		return true
	}
	return false
}

func upgradeTLS(conn net.Conn, port int) error {
	switch port {
	case 3389:
		return upgradeRDP(conn)
	case 389:
		return upgradeLDAP(conn)
	case 5432:
		// PostgreSQL SSLRequest: length and protocol code 1234/5679.
		if _, err := conn.Write([]byte{0, 0, 0, 8, 4, 210, 22, 47}); err != nil {
			return err
		}
		var response [1]byte
		if _, err := io.ReadFull(conn, response[:]); err != nil {
			return err
		}
		if response[0] != 'S' {
			return errTLSUpgrade
		}
		return nil
	default:
		r := &upgradeReader{r: bufio.NewReaderSize(conn, 4096)}
		var err error
		switch port {
		case 25, 587:
			_, err = r.reply("220", false)
			if err == nil {
				_, err = io.WriteString(conn, "EHLO sentinel.invalid\r\n")
			}
			var startTLS bool
			if err == nil {
				startTLS, err = r.reply("250", false)
			}
			if err == nil && !startTLS {
				err = errTLSUpgrade
			}
			if err == nil {
				_, err = io.WriteString(conn, "STARTTLS\r\n")
			}
			if err == nil {
				_, err = r.reply("220", false)
			}
		case 21:
			_, err = r.reply("220", true)
			if err == nil {
				_, err = io.WriteString(conn, "AUTH TLS\r\n")
			}
			if err == nil {
				_, err = r.reply("234", true)
			}
		case 110:
			err = r.expect("+OK")
			if err == nil {
				_, err = io.WriteString(conn, "STLS\r\n")
			}
			if err == nil {
				err = r.expect("+OK")
			}
		case 143:
			err = r.expect("* OK")
			if err == nil {
				_, err = io.WriteString(conn, "a001 STARTTLS\r\n")
			}
			if err == nil {
				for {
					var line string
					line, err = r.line()
					if err != nil {
						break
					}
					if tokenPrefix(line, "a001 OK") {
						break
					}
					if !strings.HasPrefix(line, "* ") || tokenPrefix(line, "* BYE") {
						err = errTLSUpgrade
						break
					}
				}
			}
		default:
			return errTLSUpgrade
		}
		// The peer must wait for ClientHello after accepting the upgrade. Never
		// discard buffered plaintext and accidentally cross a protocol boundary.
		if err == nil && r.r.Buffered() != 0 {
			return errTLSUpgrade
		}
		return err
	}
}

type upgradeReader struct {
	r            *bufio.Reader
	bytes, lines int
}

func (r *upgradeReader) line() (string, error) {
	line, err := r.r.ReadSlice('\n')
	r.bytes += len(line)
	r.lines++
	if err != nil || r.bytes > 16384 || r.lines > 64 || !strings.HasSuffix(string(line), "\r\n") {
		return "", errTLSUpgrade
	}
	return string(line[:len(line)-2]), nil
}

func tokenPrefix(line, prefix string) bool {
	return strings.EqualFold(line, prefix) || (len(line) > len(prefix) && line[len(prefix)] == ' ' && strings.EqualFold(line[:len(prefix)], prefix))
}

func (r *upgradeReader) expect(prefix string) error {
	line, err := r.line()
	if err != nil || !tokenPrefix(line, prefix) {
		return errTLSUpgrade
	}
	return nil
}

// FTP permits unprefixed intermediate lines; SMTP requires the same reply code.
func (r *upgradeReader) reply(code string, ftp bool) (bool, error) {
	advertised := false
	for first := true; ; first = false {
		line, err := r.line()
		if err != nil {
			return false, err
		}
		if !ftp && line == code {
			return advertised, nil
		}
		if len(line) < 4 || line[:3] != code || (line[3] != ' ' && line[3] != '-') {
			if ftp && !first {
				continue
			}
			return false, errTLSUpgrade
		}
		if !first && strings.EqualFold(line[4:], "STARTTLS") {
			advertised = true
		}
		if line[3] == ' ' {
			return advertised, nil
		}
	}
}

func upgradeRDP(conn net.Conn) error {
	// X.224 CR + RDP_NEG_REQ, offering TLS, CredSSP and CredSSP with early auth.
	// Collection stops at TLS; no credentials or RDP session are sent.
	if _, err := conn.Write([]byte{3, 0, 0, 19, 14, 0xe0, 0, 0, 0, 0, 0, 1, 0, 8, 0, 11, 0, 0, 0}); err != nil {
		return err
	}
	var header [4]byte
	if _, err := io.ReadFull(conn, header[:]); err != nil {
		return err
	}
	if header != [4]byte{3, 0, 0, 19} {
		return errTLSUpgrade
	}
	var response [15]byte
	if _, err := io.ReadFull(conn, response[:]); err != nil {
		return err
	}
	if response[0] != 14 || response[1] != 0xd0 || response[2] != 0 || response[3] != 0 || response[6] != 0 || response[7] != 2 || binary.LittleEndian.Uint16(response[9:11]) != 8 {
		return errTLSUpgrade
	}
	switch binary.LittleEndian.Uint32(response[11:]) {
	case 1, 2, 8:
		return nil
	}
	return errTLSUpgrade
}

func upgradeLDAP(conn net.Conn) error {
	// RFC 4511 StartTLS ExtendedRequest, messageID 1. No bind or directory query.
	const oid = "1.3.6.1.4.1.1466.20037"
	request := append([]byte{0x30, 29, 2, 1, 1, 0x77, 24, 0x80, 22}, []byte(oid)...)
	if _, err := conn.Write(request); err != nil {
		return err
	}
	var header [2]byte
	if _, err := io.ReadFull(conn, header[:]); err != nil {
		return err
	}
	if header[0] != 0x30 {
		return errTLSUpgrade
	}
	size := int(header[1])
	if size >= 128 {
		n := size & 127
		if n == 0 || n > 2 {
			return errTLSUpgrade
		}
		var length [2]byte
		if _, err := io.ReadFull(conn, length[:n]); err != nil {
			return err
		}
		size = 0
		for _, b := range length[:n] {
			size = size*256 + int(b)
		}
	}
	if size == 0 || size > 4096 {
		return errTLSUpgrade
	}
	body := make([]byte, size)
	if _, err := io.ReadFull(conn, body); err != nil {
		return err
	}
	return parseLDAPUpgrade(body)
}

// LDAP uses BER, which permits non-minimal definite lengths. Decode only the
// bounded envelope and ExtendedResponse fields; never certificate contents.
func ldapField(data []byte, tag byte) (value, rest []byte, ok bool) {
	if len(data) < 2 || data[0] != tag {
		return nil, nil, false
	}
	size, off := int(data[1]), 2
	if size >= 128 {
		n := size & 127
		if n == 0 || n > 2 || len(data) < 2+n {
			return nil, nil, false
		}
		size = 0
		off += n
		for _, b := range data[2:off] {
			size = size*256 + int(b)
		}
	}
	if size > len(data)-off {
		return nil, nil, false
	}
	return data[off : off+size], data[off+size:], true
}

func parseLDAPUpgrade(body []byte) error {
	id, rest, ok := ldapField(body, 2)
	if !ok || len(id) != 1 || id[0] != 1 {
		return errTLSUpgrade
	}
	response, rest, ok := ldapField(rest, 0x78)
	if !ok || len(rest) != 0 {
		return errTLSUpgrade
	}
	code, response, ok := ldapField(response, 0x0a)
	if !ok || len(code) != 1 || code[0] != 0 {
		return errTLSUpgrade
	}
	for i := 0; i < 2; i++ { // matchedDN and diagnosticMessage
		_, response, ok = ldapField(response, 4)
		if !ok {
			return errTLSUpgrade
		}
	}
	if len(response) != 0 {
		var name []byte
		name, response, ok = ldapField(response, 0x8a)
		if !ok || string(name) != "1.3.6.1.4.1.1466.20037" {
			return errTLSUpgrade
		}
	}
	if len(response) != 0 {
		return errTLSUpgrade
	}
	return nil
}
