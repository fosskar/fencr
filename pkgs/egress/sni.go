package main

import (
	"errors"
	"io"
	"net"
)

// a connection whose first bytes have already been read, so the client
// hello can be replayed to whoever ends up serving it
type prefixed struct {
	net.Conn
	reader io.Reader
}

func (p prefixed) Read(b []byte) (int, error) { return p.reader.Read(b) }

// whole tls records until the client hello is complete, kept for the replay
func readClientHello(conn net.Conn) ([]byte, string, error) {
	var raw, handshake []byte
	want := -1
	for {
		header := make([]byte, 5)
		if _, err := io.ReadFull(conn, header); err != nil {
			return raw, "", err
		}
		if header[0] != 0x16 {
			return raw, "", errors.New("not a tls handshake")
		}
		body := make([]byte, int(header[3])<<8|int(header[4]))
		if _, err := io.ReadFull(conn, body); err != nil {
			return raw, "", err
		}
		raw = append(raw, header...)
		raw = append(raw, body...)
		handshake = append(handshake, body...)
		if want < 0 && len(handshake) >= 4 {
			want = 4 + int(handshake[1])<<16 | int(handshake[2])<<8 | int(handshake[3])
		}
		if want >= 0 && len(handshake) >= want {
			name, err := serverName(handshake[:want])
			return raw, name, err
		}
		if len(raw) > 65536 {
			return raw, "", errors.New("client hello too large")
		}
	}
}

// the server name of a tls client hello, or why there is none
func serverName(hello []byte) (string, error) {
	at := 0
	take := func(n int) ([]byte, error) {
		if n < 0 || at+n > len(hello) {
			return nil, errors.New("short hello")
		}
		slice := hello[at : at+n]
		at += n
		return slice, nil
	}
	kind, err := take(1)
	if err != nil {
		return "", err
	}
	if kind[0] != 0x01 {
		return "", errors.New("not a client hello")
	}
	for _, n := range []int{3, 2, 32} { // length, version, random
		if _, err := take(n); err != nil {
			return "", err
		}
	}
	for _, sized := range []int{1, 2, 1} { // session, cipher suites, compression
		size, err := take(sized)
		if err != nil {
			return "", err
		}
		length := int(size[0])
		if sized == 2 {
			length = int(size[0])<<8 | int(size[1])
		}
		if _, err := take(length); err != nil {
			return "", err
		}
	}
	block, err := take(2)
	if err != nil {
		return "", err
	}
	extensions := int(block[0])<<8 | int(block[1])
	for extensions >= 4 {
		head, err := take(4)
		if err != nil {
			return "", err
		}
		length := int(head[2])<<8 | int(head[3])
		extensions -= 4 + length
		if extensions < 0 {
			return "", errors.New("short hello")
		}
		body, err := take(length)
		if err != nil {
			return "", err
		}
		if head[0] != 0 || head[1] != 0 {
			continue
		}
		// server_name list: length(2), then entries of type(1) length(2) name
		if len(body) < 5 || body[2] != 0 {
			return "", errors.New("server_name is not a host name")
		}
		size := int(body[3])<<8 | int(body[4])
		if len(body) < 5+size {
			return "", errors.New("short server_name")
		}
		return hostName(body[5 : 5+size])
	}
	return "", errors.New("no server_name")
}

// the name is echoed into the journal, where a newline would forge a line
func hostName(raw []byte) (string, error) {
	if len(raw) == 0 {
		return "", errors.New("server_name is not a host name")
	}
	for _, b := range raw {
		letter := b >= 'a' && b <= 'z' || b >= 'A' && b <= 'Z'
		digit := b >= '0' && b <= '9'
		if !letter && !digit && b != '-' && b != '.' {
			return "", errors.New("server_name is not a host name")
		}
	}
	return string(raw), nil
}
