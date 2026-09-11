// the vm's road out and its credentials, one process per vm. on the bridge
// address it answers every dns name with itself, so every tls connection
// the guest opens lands here and is judged by the server name in its client
// hello: a credential's domain is ended here and the credential put where
// the request needs it, an allowed name is spliced to the real host unread,
// the rest is refused. the vm never holds a credential's value.
package main

import (
	"bytes"
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
	Resolver    string       `json:"resolver"`
	Domains     []string     `json:"domains"`
	Denied      []string     `json:"denied"`
	Credentials []credential `json:"credentials"`
}

func main() {
	log.SetFlags(0)
	if len(os.Args) != 2 {
		log.Fatal("usage: fencr-egress <config.json>")
	}
	raw, err := os.ReadFile(os.Args[1])
	if err != nil {
		log.Fatal(err)
	}
	cfg := &config{}
	if err := json.Unmarshal(raw, cfg); err != nil {
		log.Fatal(err)
	}
	if err := run(cfg); err != nil {
		log.Fatal(err)
	}
}

func run(cfg *config) error {
	bridge := net.ParseIP(cfg.Bridge)
	if bridge == nil {
		return fmt.Errorf("%q is not an address", cfg.Bridge)
	}

	intercept := map[string]*credential{}
	for i := range cfg.Credentials {
		intercept[strings.ToLower(cfg.Credentials[i].Domain)] = &cfg.Credentials[i]
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

func route(cfg *config, intercept map[string]*credential, handover chan net.Conn, conn net.Conn) {
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
	splice(replayed, net.JoinHostPort(name, "443"))
}

// the unit's IPAddressDeny is what keeps an allowed name out of the lan, so
// a refused destination shows up as a dial that never completes. only that
// is worth a line; a copy ends when one side hangs up, which is not news
func splice(client net.Conn, address string) {
	defer client.Close()
	upstream, err := net.DialTimeout("tcp4", address, 10*time.Second)
	if err != nil {
		log.Printf("relay: %v", err)
		return
	}
	defer upstream.Close()
	done := make(chan struct{})
	go func() {
		_, _ = io.Copy(client, upstream)
		close(done)
	}()
	_, _ = io.Copy(upstream, client)
	<-done
}

// `*.example.com` covers the names below example.com, not example.com
// itself; a denied name is refused even inside a granted wildcard
func allowedName(domains, denied []string, host string) bool {
	return !matchesAny(denied, host) && matchesAny(domains, host)
}

func matchesAny(patterns []string, host string) bool {
	host = strings.ToLower(host)
	for _, pattern := range patterns {
		pattern = strings.ToLower(pattern)
		if suffix, wildcard := strings.CutPrefix(pattern, "*."); wildcard {
			if strings.HasSuffix(host, "."+suffix) {
				return true
			}
			continue
		}
		if host == pattern {
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
