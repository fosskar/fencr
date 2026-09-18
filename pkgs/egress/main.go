// the vm's road out and its credentials, one process per vm. on the bridge
// address it answers every dns name with itself, so every tls connection
// the guest opens lands here and is judged by the server name in its client
// hello: a credential's domain is ended here and the credential put where
// the request needs it, an allowed name is spliced to the real host unread,
// the rest is refused. the vm never holds a credential's value.
package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"syscall"
	"time"
)

// what nix writes beside the binary; no value is in it, the credentials
// arrive as systemd credentials
type config struct {
	Bridge  string `json:"bridge"`
	DNSPort int    `json:"dnsPort"`
	TLSPort int    `json:"tlsPort"`
	// where a query goes when there is no name to judge; empty means every
	// name is answered with the bridge address instead
	Resolver string `json:"resolver"`
	// the vm's own subnet: IPAddressAllow must carry it for the guest to be
	// reachable, so IPAddressDeny cannot refuse it and this check must
	Blocked     []string     `json:"blocked"`
	Domains     []string     `json:"domains"`
	Denied      []string     `json:"denied"`
	Credentials []credential `json:"credentials"`

	blocked []*net.IPNet
}

func main() {
	log.SetFlags(0)
	if len(os.Args) != 2 {
		log.Fatal("usage: fencr-egress <config.json>")
	}
	cfg, err := load(os.Args[1])
	if err != nil {
		log.Fatal(err)
	}
	if err := run(cfg); err != nil {
		log.Fatal(err)
	}
}

// nix renders this file and the fields are typed out on both sides, so a
// key neither side recognizes means the two have drifted apart. an
// unmarshal that filled in the zero value would leave a unit that starts
// and serves nothing: no resolver, or a listener on port 0
func load(path string) (*config, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	decoder := json.NewDecoder(file)
	decoder.DisallowUnknownFields()
	cfg := &config{}
	if err := decoder.Decode(cfg); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	if decoder.More() {
		return nil, fmt.Errorf("%s: more than one configuration", path)
	}
	// resolver, domains, denied and a credential's placeholder are empty in
	// configurations that are exactly right: a domain grant answers every
	// name itself, and a credential may refuse substitution
	if net.ParseIP(cfg.Bridge) == nil {
		return nil, fmt.Errorf("%s: bridge %q is not an address", path, cfg.Bridge)
	}
	for _, port := range []struct {
		name  string
		value int
	}{{"dnsPort", cfg.DNSPort}, {"tlsPort", cfg.TLSPort}} {
		if port.value < 1 || port.value > 65535 {
			return nil, fmt.Errorf("%s: %s %d is not a port", path, port.name, port.value)
		}
	}
	// an empty list would leave a granted name free to name the bridge
	if len(cfg.Blocked) == 0 {
		return nil, fmt.Errorf("%s: no blocked ranges", path)
	}
	for _, entry := range cfg.Blocked {
		_, network, err := net.ParseCIDR(entry)
		if err != nil {
			return nil, fmt.Errorf("%s: blocked %q is not a network", path, entry)
		}
		cfg.blocked = append(cfg.blocked, network)
	}
	for _, c := range cfg.Credentials {
		for _, field := range []struct {
			name  string
			value string
		}{{"name", c.Name}, {"domain", c.Domain}, {"upstream", c.Upstream}, {"header", c.Header}} {
			if field.value == "" {
				return nil, fmt.Errorf("%s: credential %q has no %s", path, c.Name, field.name)
			}
		}
	}
	return cfg, nil
}

func run(cfg *config) error {
	bridge := net.ParseIP(cfg.Bridge)

	intercept := map[string][]*credential{}
	for i := range cfg.Credentials {
		domain := strings.ToLower(cfg.Credentials[i].Domain)
		intercept[domain] = append(intercept[domain], &cfg.Credentials[i])
	}
	var terminator *http.Server
	if len(intercept) > 0 {
		authority, err := loadAuthority()
		if err != nil {
			return err
		}
		terminator = &http.Server{
			Handler:           handler(intercept),
			TLSConfig:         &tls.Config{GetCertificate: authority.certificate, MinVersion: tls.VersionTLS12},
			ReadHeaderTimeout: 30 * time.Second,
			IdleTimeout:       120 * time.Second,
			ErrorLog:          log.New(io.Discard, "", 0),
		}
	}

	// the guest's resolver is this unit whenever it may resolve at all: with
	// domain grants every name is answered with the bridge address, with an
	// open grant the query is relayed to the host's stub
	if len(cfg.Domains) > 0 || cfg.Resolver != "" {
		conn, err := listenDNS(bridge, cfg.DNSPort)
		if err != nil {
			return err
		}
		if cfg.Resolver == "" {
			go answerDNS(conn, bridge)
		} else {
			stream, err := net.ListenTCP("tcp", &net.TCPAddr{IP: bridge, Port: cfg.DNSPort})
			if err != nil {
				return err
			}
			go forwardDNS(conn, cfg.Resolver)
			go forwardDNSStream(stream, cfg.Resolver)
		}
	}

	// an open grant needs no tls door: there is no name to judge and the
	// firewall lets the guest reach the internet itself
	if len(cfg.Domains) == 0 && len(intercept) == 0 {
		select {}
	}
	listener, err := net.ListenTCP("tcp", &net.TCPAddr{IP: bridge, Port: cfg.TLSPort})
	if err != nil {
		return err
	}
	// terminated connections are handed over one at a time, so the http
	// server gets a listener it can accept from
	handover := make(chan net.Conn)
	if terminator != nil {
		go func() {
			log.Print(terminator.ServeTLS(channelListener{conns: handover, addr: listener.Addr()}, "", ""))
		}()
	}
	for {
		conn, err := listener.Accept()
		if err != nil {
			return err
		}
		go route(cfg, intercept, handover, conn)
	}
}

// the bridge gets its address from networkd, which may not have run yet
func listenDNS(bridge net.IP, port int) (net.PacketConn, error) {
	for range 120 {
		conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: bridge, Port: port})
		if err == nil {
			return conn, nil
		}
		if !errors.Is(err, syscall.EADDRNOTAVAIL) {
			return nil, err
		}
		time.Sleep(500 * time.Millisecond)
	}
	return nil, fmt.Errorf("the bridge never got its address")
}

func route(cfg *config, intercept map[string][]*credential, handover chan net.Conn, conn net.Conn) {
	if err := conn.SetReadDeadline(time.Now().Add(10 * time.Second)); err != nil {
		conn.Close()
		return
	}
	hello, name, err := readClientHello(conn)
	if err != nil {
		log.Printf("deny: %v", err)
		conn.Close()
		return
	}
	if err := conn.SetReadDeadline(time.Time{}); err != nil {
		conn.Close()
		return
	}
	replayed := prefixed{Conn: conn, reader: io.MultiReader(bytes.NewReader(hello), conn)}

	if _, ok := intercept[strings.ToLower(name)]; ok {
		log.Printf("intercept %s", name)
		handover <- replayed
		return
	}
	if !allowedName(cfg.Domains, cfg.Denied, name) {
		log.Printf("deny %s", name)
		conn.Close()
		return
	}
	log.Printf("allow %s", name)
	splice(replayed, name, cfg.blocked)
}

// the unit's IPAddressDeny is what keeps an allowed name out of the lan, so
// a refused destination shows up as a dial that never completes. only that
// is worth a line; a copy ends when one side hangs up, which is not news
func splice(client net.Conn, name string, blocked []*net.IPNet) {
	defer client.Close()
	upstream, err := dialPublic(name, "443", blocked)
	if err != nil {
		log.Printf("relay: %v", err)
		return
	}
	defer upstream.Close()
	done := make(chan struct{})
	go func() {
		copyStream(client, upstream)
		close(done)
	}()
	copyStream(upstream, client)
	<-done
}

// the address that passed the check is the one connected to. IPAddressDeny
// stops the special-use ranges, but IPAddressAllow has to carry the vm's own
// subnet so the guest stays reachable, and that /26 outranks the /8; a
// granted name resolving onto the bridge or the guest is refused here
func dialPublic(name, port string, blocked []*net.IPNet) (net.Conn, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	resolved, err := net.DefaultResolver.LookupIP(ctx, "ip4", name)
	if err != nil {
		return nil, err
	}
	addresses := publicAddresses(resolved, blocked)
	if len(addresses) == 0 {
		return nil, fmt.Errorf("dial %s: every address is loopback or on the vm's own subnet", name)
	}
	var failure error
	for _, address := range addresses {
		conn, err := net.DialTimeout("tcp4", net.JoinHostPort(address.String(), port), 10*time.Second)
		if err == nil {
			return conn, nil
		}
		failure = err
	}
	return nil, failure
}

func publicAddresses(resolved []net.IP, blocked []*net.IPNet) []net.IP {
	var addresses []net.IP
	for _, address := range resolved {
		if address.IsLoopback() || withinAny(blocked, address) {
			continue
		}
		addresses = append(addresses, address)
	}
	return addresses
}

func withinAny(networks []*net.IPNet, address net.IP) bool {
	for _, network := range networks {
		if network.Contains(address) {
			return true
		}
	}
	return false
}

type halfCloser interface{ CloseWrite() error }

// a direction that ends must reach the other side, or a peer that says
// nothing holds both connections open
func copyStream(destination, source net.Conn) {
	_, err := io.Copy(destination, source)
	if closer, ok := destination.(halfCloser); ok && err == nil {
		err = closer.CloseWrite()
	}
	if err != nil {
		source.Close()
		destination.Close()
	}
}

// `*.example.com` covers the names below example.com, not example.com
// itself; a denied name is refused even inside a granted wildcard
func allowedName(domains, denied []string, host string) bool {
	return !matchesAny(denied, host) && matchesAny(domains, host)
}

func matchesAny(patterns []string, host string) bool {
	for _, pattern := range patterns {
		if covers(pattern, host) {
			return true
		}
	}
	return false
}

// the http server accepts from this instead of a socket of its own
type channelListener struct {
	conns chan net.Conn
	addr  net.Addr
}

func (l channelListener) Accept() (net.Conn, error) { return <-l.conns, nil }
func (l channelListener) Close() error              { return nil }
func (l channelListener) Addr() net.Addr            { return l.addr }
