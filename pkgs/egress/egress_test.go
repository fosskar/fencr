package main

import (
	"bytes"
	"net"
	"testing"
)

func hello(extensions []byte) []byte {
	body := []byte{3, 3}
	body = append(body, make([]byte, 32)...)
	body = append(body, 0)                // session
	body = append(body, 0, 2, 0x13, 0x01) // cipher suites
	body = append(body, 1, 0)             // compression
	body = append(body, byte(len(extensions)>>8), byte(len(extensions)))
	body = append(body, extensions...)
	out := []byte{1, byte(len(body) >> 16), byte(len(body) >> 8), byte(len(body))}
	return append(out, body...)
}

func serverNameExtension(name string) []byte {
	entry := len(name) + 3
	out := []byte{0, 0, byte((entry + 2) >> 8), byte(entry + 2), byte(entry >> 8), byte(entry), 0}
	out = append(out, byte(len(name)>>8), byte(len(name)))
	return append(out, name...)
}

func TestServerNameIsFoundBehindOtherExtensions(t *testing.T) {
	extensions := append([]byte{0, 0x17, 0, 0}, serverNameExtension("api.github.com")...)
	name, err := serverName(hello(extensions))
	if err != nil || name != "api.github.com" {
		t.Fatalf("got %q, %v", name, err)
	}
}

func TestHelloWithoutANameOrCutShortIsRefused(t *testing.T) {
	cut := hello(serverNameExtension("x"))
	for _, c := range []struct {
		hello  []byte
		reason string
	}{
		{hello(nil), "no server_name"},
		{[]byte{2, 0, 0, 0}, "not a client hello"},
		{cut[:20], "short hello"},
		{hello([]byte{0, 0, 0xff, 0xff}), "short hello"},
		// a newline would forge a line in the journal
		{hello(serverNameExtension("x\nallow evil.test")), "server_name is not a host name"},
	} {
		name, err := serverName(c.hello)
		if err == nil || err.Error() != c.reason {
			t.Errorf("got %q, %v; want %s", name, err, c.reason)
		}
	}
}

func TestWildcardMatchesSubdomainsOnly(t *testing.T) {
	patterns := []string{"*.github.com", "example.com"}
	for host, want := range map[string]bool{
		"api.github.com":  true,
		"API.GitHub.com":  true,
		"example.com":     true,
		"github.com":      false,
		"evilgithub.com":  false,
		"www.example.com": false,
	} {
		if got := allowedName(patterns, nil, host); got != want {
			t.Errorf("%s: got %v", host, got)
		}
	}
}

func TestDenyWinsInsideAGrant(t *testing.T) {
	patterns := []string{"*.github.com"}
	denied := []string{"gist.github.com", "*.raw.github.com"}
	for host, want := range map[string]bool{
		"api.github.com":   true,
		"gist.github.com":  false,
		"GIST.github.com":  false,
		"raw.github.com":   true,
		"x.raw.github.com": false,
	} {
		if got := allowedName(patterns, denied, host); got != want {
			t.Errorf("%s: got %v", host, got)
		}
	}
}

func TestEveryAQueryIsAnsweredWithTheBridgeAddress(t *testing.T) {
	query := []byte{0xab, 0xcd, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0}
	query = append(query, 3, 'a', 'p', 'i', 4, 't', 'e', 's', 't', 0, 0, 1, 0, 1)
	reply := answerA(query, net.IPv4(10, 11, 0, 1))
	if !bytes.Equal(reply[:2], query[:2]) {
		t.Fatal("the reply does not carry the query's id")
	}
	if reply[7] != 1 || !bytes.HasSuffix(reply, []byte{10, 11, 0, 1}) {
		t.Fatalf("no answer of the bridge address: %v", reply)
	}
	// an AAAA query gets the question back with no answer, not an address
	query[len(query)-3] = 28
	reply = answerA(query, net.IPv4(10, 11, 0, 1))
	if reply[7] != 0 {
		t.Fatalf("an AAAA query was answered: %v", reply)
	}
	// a reply is never sent to a reply
	if answerA([]byte{0, 0, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0}, net.IPv4(10, 11, 0, 1)) != nil {
		t.Fatal("a response was answered")
	}
}
