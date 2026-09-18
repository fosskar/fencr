package main

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

// the only address a granted name must never reach: the loopback the unit
// allows for a credential's upstream
func TestLoopbackAddressesAreNotDialled(t *testing.T) {
	for _, test := range []struct {
		resolved []string
		want     []string
	}{
		{[]string{"127.0.0.1"}, nil},
		{[]string{"127.0.0.53", "127.1.2.3"}, nil},
		{[]string{"127.0.0.1", "93.184.215.14"}, []string{"93.184.215.14"}},
		{[]string{"93.184.215.14"}, []string{"93.184.215.14"}},
	} {
		var resolved []net.IP
		for _, address := range test.resolved {
			resolved = append(resolved, net.ParseIP(address))
		}
		var got []string
		for _, address := range publicAddresses(resolved) {
			got = append(got, address.String())
		}
		if strings.Join(got, ",") != strings.Join(test.want, ",") {
			t.Errorf("%v: got %v, want %v", test.resolved, got, test.want)
		}
	}
	if _, err := dialPublic("localhost", "443"); err == nil {
		t.Fatal("a name on loopback was dialled")
	}
}

func TestSpliceReleasesUpstreamOnDisconnect(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	if err := listener.(*net.TCPListener).SetDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	client, proxy := net.Pipe()
	defer client.Close()
	defer proxy.Close()
	upstream, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer upstream.Close()
	server, err := listener.Accept()
	if err != nil {
		t.Fatal(err)
	}
	// the direction splice runs on the goroutine's side: the guest hangs up
	// and the upstream must hear it
	go copyStream(upstream, prefixed{Conn: proxy, reader: proxy})
	defer server.Close()
	client.Close()
	if err := server.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	var buffer [1]byte
	if _, err := server.Read(buffer[:]); err != io.EOF {
		t.Fatalf("upstream held open after the guest disconnected: %v", err)
	}
}

// the handshake length is three bytes; reading it wrong refuses a hello
// that is merely the wrong size
func TestClientHelloOfEveryLengthIsRead(t *testing.T) {
	for n := 1; n <= 24; n++ {
		t.Run(fmt.Sprint(n), func(t *testing.T) {
			name := strings.Repeat("a", n) + ".test"
			handshake := hello(serverNameExtension(name))
			length := len(handshake) - 4
			handshake[1] = byte(length >> 16)
			handshake[2] = byte(length >> 8)
			handshake[3] = byte(length)
			record := []byte{0x16, 3, 3, 0, 0}
			binary.BigEndian.PutUint16(record[3:], uint16(len(handshake)))
			record = append(record, handshake...)
			client, server := net.Pipe()
			defer client.Close()
			defer server.Close()
			if err := server.SetDeadline(time.Now().Add(2 * time.Second)); err != nil {
				t.Fatal(err)
			}
			go func() {
				_, _ = client.Write(record)
				client.Close()
			}()
			_, got, err := readClientHello(server)
			if err != nil || got != name {
				t.Fatalf("hello body of %d bytes: got %q, %v", length, got, err)
			}
		})
	}
}
