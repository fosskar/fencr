package main

import (
	"bytes"
	"encoding/binary"
	"io"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"
)

// ::ffff:0:0/96 is in the rendered list, and a careless match of it covers
// every IPv4 address
var private = func() []netip.Prefix {
	var networks []netip.Prefix
	for _, entry := range []string{"10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "192.168.0.0/16", "::ffff:0:0/96", "fc00::/7"} {
		networks = append(networks, netip.MustParsePrefix(entry))
	}
	return networks
}()

var rules = &screen{private: private, reachable: []netip.Prefix{netip.MustParsePrefix("192.168.10.50/32")}}

func dnsQuery(name string, kind uint16) []byte {
	message := []byte{0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0}
	for _, label := range strings.Split(name, ".") {
		message = append(message, byte(len(label)))
		message = append(message, label...)
	}
	message = append(message, 0)
	message = binary.BigEndian.AppendUint16(message, kind)
	return binary.BigEndian.AppendUint16(message, 1)
}

// the resolver's answer to query: one record pointing at the question
func dnsAnswer(query []byte, kind uint16, data []byte) []byte {
	answer := append([]byte(nil), query...)
	answer[2], answer[3] = 0x81, 0x80
	answer[7] = 1
	answer = append(answer, 0xc0, 0x0c)
	answer = binary.BigEndian.AppendUint16(answer, kind)
	answer = append(answer, 0, 1, 0, 0, 0, 30)
	answer = binary.BigEndian.AppendUint16(answer, uint16(len(data)))
	return append(answer, data...)
}

func refused(message []byte) bool { return len(message) >= 4 && message[3]&0x0f == 5 }

func TestScreenedAnswers(t *testing.T) {
	for _, test := range []struct {
		name    string
		kind    uint16
		data    []byte
		refused bool
	}{
		{"public.test", 1, net.IPv4(93, 184, 216, 34).To4(), false},
		{"_gateway", 1, net.IPv4(192, 168, 20, 1).To4(), true},
		{"host.nb.example", 1, net.IPv4(100, 116, 129, 183).To4(), true},
		{"myhost", 1, net.IPv4(127, 0, 0, 2).To4(), true},
		{"ula.test", 28, net.ParseIP("fdde::1"), true},
		{"text.test", 16, []byte("\x05hello"), false},
		// a destination the sandbox is granted resolves by name
		{"granted.lan", 1, net.IPv4(192, 168, 10, 50).To4(), false},
	} {
		query := dnsQuery(test.name, test.kind)
		answer := dnsAnswer(query, test.kind, test.data)
		got := screened(query, answer, rules)
		if refused(got) != test.refused {
			t.Errorf("%s: refused %v, want %v", test.name, refused(got), test.refused)
		}
		if !test.refused && !bytes.Equal(got, answer) {
			t.Errorf("%s: the answer was changed", test.name)
		}
		if test.refused && (got[0] != 0x12 || got[1] != 0x34 || binary.BigEndian.Uint16(got[6:]) != 0) {
			t.Errorf("%s: refusal %x", test.name, got)
		}
	}
	query := dnsQuery("broken.test", 1)
	if !refused(screened(query, dnsAnswer(query, 1, net.IPv4(1, 1, 1, 1).To4())[:len(query)+5], rules)) {
		t.Error("a truncated answer passed")
	}
}

// a host:<port> grant reaches the host on its own addresses, never loopback
func TestHostAddressesPassOnlyWithAHostGrant(t *testing.T) {
	for _, test := range []struct {
		rules *screen
		want  bool
	}{
		{&screen{private: private}, false},
		{&screen{private: private, host: true}, false},
	} {
		if got := test.rules.allows(netip.MustParseAddr("127.0.0.1")); got != test.want {
			t.Errorf("loopback with host %v: got %v", test.rules.host, got)
		}
	}
	if (&screen{private: private, host: true}).allows(netip.MustParseAddr("192.168.254.254")) {
		t.Error("an address the host does not hold passed")
	}
}

func TestReverseLookupsOfPrivateAddressesAreRefused(t *testing.T) {
	for name, want := range map[string]bool{
		"1.20.168.192.in-addr.arpa":                true,
		"168.192.in-addr.arpa":                     true,
		"in-addr.arpa":                             true,
		"x.1.168.192.in-addr.arpa":                 true,
		"183.129.116.100.in-addr.arpa":             true,
		"34.216.184.93.in-addr.arpa":               false,
		"1.0.0.0.0.0.0.0.0.0.0.0.e.d.d.f.ip6.arpa": true,
		"8.b.d.0.1.0.0.2.ip6.arpa":                 false,
		"example.com":                              false,
	} {
		if got := reversesPrivate(dnsQuery(name, 12), rules); got != want {
			t.Errorf("%s: got %v, want %v", name, got, want)
		}
	}
}

func TestTheUDPRelayScreens(t *testing.T) {
	resolver, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer resolver.Close()
	asked := make(chan string, 4)
	go func() {
		buffer := make([]byte, 512)
		for {
			n, peer, err := resolver.ReadFrom(buffer)
			if err != nil {
				return
			}
			query := append([]byte(nil), buffer[:n]...)
			asked <- questionName(query)
			address := net.IPv4(93, 184, 216, 34).To4()
			if questionName(query) == "router.lan" {
				address = net.IPv4(192, 168, 20, 1).To4()
			}
			resolver.WriteTo(dnsAnswer(query, 1, address), peer)
		}
	}()
	relay, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer relay.Close()
	go forwardDNS(relay, resolver.LocalAddr().String(), rules, newBucket())
	client, err := net.Dial("udp", relay.LocalAddr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	for _, test := range []struct {
		name      string
		kind      uint16
		refused   bool
		forwarded bool
	}{
		{"public.test", 1, false, true},
		{"router.lan", 1, true, true},
		{"1.20.168.192.in-addr.arpa", 12, true, false},
	} {
		if _, err := client.Write(dnsQuery(test.name, test.kind)); err != nil {
			t.Fatal(err)
		}
		client.SetReadDeadline(time.Now().Add(2 * time.Second))
		reply := make([]byte, 512)
		n, err := client.Read(reply)
		if err != nil {
			t.Fatalf("%s: %v", test.name, err)
		}
		if refused(reply[:n]) != test.refused {
			t.Errorf("%s: refused %v, want %v", test.name, refused(reply[:n]), test.refused)
		}
		select {
		case name := <-asked:
			if !test.forwarded || name != test.name {
				t.Errorf("%s: the resolver was asked %s", test.name, name)
			}
		default:
			if test.forwarded {
				t.Errorf("%s: never reached the resolver", test.name)
			}
		}
	}
}

// a guest connection to the relay, and the resolver's end of the
// connection the relay opens once the guest has asked something
func dnsRelayPair(t *testing.T) (*net.TCPConn, func() (*net.TCPConn, error)) {
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
	go forwardDNSStream(relay, upstream.Addr().String(), rules, newBucket())
	client, err := net.DialTCP("tcp", nil, relay.Addr().(*net.TCPAddr))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { client.Close() })
	if err := client.SetDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	accept := func() (*net.TCPConn, error) {
		if err := upstream.SetDeadline(time.Now().Add(2 * time.Second)); err != nil {
			return nil, err
		}
		server, err := upstream.AcceptTCP()
		if err != nil {
			return nil, err
		}
		t.Cleanup(func() { server.Close() })
		return server, server.SetDeadline(time.Now().Add(2 * time.Second))
	}
	return client, accept
}

// a connection that asks nothing costs the shared resolver nothing
func TestDNSRelayDialsOnlyForAQuery(t *testing.T) {
	client, accept := dnsRelayPair(t)
	client.Close()
	if server, err := accept(); err == nil {
		server.Close()
		t.Fatal("the relay dialled the resolver for a connection that sent no query")
	}
}

func TestDNSRelayScreensStreams(t *testing.T) {
	client, accept := dnsRelayPair(t)
	var server *net.TCPConn
	for _, test := range []struct {
		name    string
		address net.IP
		refused bool
	}{
		{"public.test", net.IPv4(93, 184, 216, 34), false},
		{"router.lan", net.IPv4(192, 168, 20, 1), true},
	} {
		query := dnsQuery(test.name, 1)
		if err := writeMessage(client, query); err != nil {
			t.Fatal(err)
		}
		if server == nil {
			var err error
			if server, err = accept(); err != nil {
				t.Fatal(err)
			}
		}
		asked, err := readMessage(server)
		if err != nil || !bytes.Equal(asked, query) {
			t.Fatalf("query: %x, %v", asked, err)
		}
		if err := writeMessage(server, dnsAnswer(query, 1, test.address.To4())); err != nil {
			t.Fatal(err)
		}
		answer, err := readMessage(client)
		if err != nil || refused(answer) != test.refused {
			t.Fatalf("%s: %x, %v", test.name, answer, err)
		}
	}
	// a reverse lookup of a private address never reaches the resolver
	if err := writeMessage(client, dnsQuery("1.20.168.192.in-addr.arpa", 12)); err != nil {
		t.Fatal(err)
	}
	answer, err := readMessage(client)
	if err != nil || !refused(answer) {
		t.Fatalf("reverse: %x, %v", answer, err)
	}
}

func TestDNSRelayIdleTimeout(t *testing.T) {
	client, _ := dnsRelayPair(t)
	if err := client.SetDeadline(time.Now().Add(35 * time.Second)); err != nil {
		t.Fatal(err)
	}
	var buffer [1]byte
	if _, err := client.Read(buffer[:]); err != io.EOF {
		t.Fatalf("idle relay did not close connection: %v", err)
	}
}

func TestDNSRelayUpstreamDisconnect(t *testing.T) {
	client, accept := dnsRelayPair(t)
	if err := writeMessage(client, dnsQuery("public.test", 1)); err != nil {
		t.Fatal(err)
	}
	server, err := accept()
	if err != nil {
		t.Fatal(err)
	}
	server.Close()
	var buffer [1]byte
	if _, err := client.Read(buffer[:]); err != io.EOF {
		t.Fatalf("disconnected upstream did not propagate EOF: %v", err)
	}
}

// past the cap the connection is closed rather than queued
func TestDNSRelayCapsStreams(t *testing.T) {
	relay, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer relay.Close()
	go forwardDNSStream(relay, "127.0.0.1:1", rules, newBucket())
	var held []net.Conn
	defer func() {
		for _, conn := range held {
			conn.Close()
		}
	}()
	for range maxStreams {
		conn, err := net.Dial("tcp", relay.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		held = append(held, conn)
	}
	extra, err := net.Dial("tcp", relay.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer extra.Close()
	extra.SetDeadline(time.Now().Add(2 * time.Second))
	var buffer [1]byte
	if _, err := extra.Read(buffer[:]); err != io.EOF {
		t.Fatalf("a connection past the cap was kept: %v", err)
	}
}

// a burst passes, then the steady rate, whatever the resolver behind
func TestTheQueryRateIsTheSandboxs(t *testing.T) {
	clock := time.Unix(0, 0)
	limit := newBucket()
	limit.last, limit.now = clock, func() time.Time { return clock }
	for at := range queryBurst {
		if !limit.take() {
			t.Fatalf("query %d of the burst was refused", at)
		}
	}
	if limit.take() {
		t.Fatal("a query past the burst passed")
	}
	clock = clock.Add(time.Second)
	for at := range queryRate {
		if !limit.take() {
			t.Fatalf("query %d a second later was refused", at)
		}
	}
	if limit.take() {
		t.Fatal("more than the rate passed in a second")
	}
}

// the bridge drops ipv6, so an AAAA answer could only leak the host's
// overlay names; it is answered empty, over either road, without asking
func TestAAAAIsAnsweredEmpty(t *testing.T) {
	query := dnsQuery("overlay.test", 28)
	empty := noAddress(query)
	if empty == nil || empty[3]&0x0f != 0 || binary.BigEndian.Uint16(empty[6:]) != 0 || empty[0] != 0x12 {
		t.Fatalf("got %x", empty)
	}
	if asksAAAA(dnsQuery("overlay.test", 1)) || !asksAAAA(query) {
		t.Fatal("asksAAAA misreads the question type")
	}
	client, accept := dnsRelayPair(t)
	if err := writeMessage(client, query); err != nil {
		t.Fatal(err)
	}
	answer, err := readMessage(client)
	if err != nil || answer[3]&0x0f != 0 || binary.BigEndian.Uint16(answer[6:]) != 0 {
		t.Fatalf("stream: %x, %v", answer, err)
	}
	if server, err := accept(); err == nil {
		server.Close()
		t.Fatal("an AAAA query reached the resolver")
	}
}
