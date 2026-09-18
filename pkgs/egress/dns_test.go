package main

import (
	"io"
	"net"
	"testing"
	"time"
)

func dnsRelayPair(t *testing.T) (*net.TCPConn, *net.TCPConn) {
	t.Helper()
	upstream, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { upstream.Close() })
	relay, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { relay.Close() })
	go forwardDNSStream(relay, upstream.Addr().String())
	client, err := net.DialTCP("tcp", nil, relay.Addr().(*net.TCPAddr))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { client.Close() })
	if err := upstream.SetDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	server, err := upstream.AcceptTCP()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { server.Close() })
	for _, conn := range []*net.TCPConn{client, server} {
		if err := conn.SetDeadline(time.Now().Add(2 * time.Second)); err != nil {
			t.Fatal(err)
		}
	}
	return client, server
}

func TestDNSRelayClientDisconnect(t *testing.T) {
	client, server := dnsRelayPair(t)
	client.Close()
	var buffer [1]byte
	if _, err := server.Read(buffer[:]); err != io.EOF {
		t.Fatalf("disconnected client did not propagate EOF: %v", err)
	}
}

func TestDNSRelayHalfClose(t *testing.T) {
	client, server := dnsRelayPair(t)
	if _, err := client.Write([]byte("query")); err != nil {
		t.Fatal(err)
	}
	if err := client.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	query, err := io.ReadAll(server)
	if err != nil || string(query) != "query" {
		t.Fatalf("query: %q, %v", query, err)
	}
	if _, err := server.Write([]byte("answer")); err != nil {
		t.Fatal(err)
	}
	if err := server.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	answer, err := io.ReadAll(client)
	if err != nil || string(answer) != "answer" {
		t.Fatalf("answer: %q, %v", answer, err)
	}
}

func TestDNSRelayIdleTimeout(t *testing.T) {
	client, server := dnsRelayPair(t)
	for _, conn := range []*net.TCPConn{client, server} {
		if err := conn.SetDeadline(time.Now().Add(35 * time.Second)); err != nil {
			t.Fatal(err)
		}
	}
	var buffer [1]byte
	for _, conn := range []*net.TCPConn{client, server} {
		if _, err := conn.Read(buffer[:]); err != io.EOF {
			t.Fatalf("idle relay did not close connection: %v", err)
		}
	}
}

func TestDNSRelayUpstreamDisconnect(t *testing.T) {
	client, server := dnsRelayPair(t)
	server.Close()
	var buffer [1]byte
	if _, err := client.Read(buffer[:]); err != io.EOF {
		t.Fatalf("disconnected upstream did not propagate EOF: %v", err)
	}
}
