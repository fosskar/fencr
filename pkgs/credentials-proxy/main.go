// the credential proxy: one per vm, reached only over its unix socket by
// that vm's egress proxy. it ends the tls for each granted domain with a
// certificate from the host's authority, puts the credential where the
// request needs it, and sends the request on. the vm never holds a value.
package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"
)

// what nix writes beside the binary; the values themselves arrive as
// systemd credentials, never through this file
type config struct {
	Socket      string       `json:"socket"`
	Credentials []credential `json:"credentials"`
}

type credential struct {
	Name        string `json:"name"`
	Domain      string `json:"domain"`
	Upstream    string `json:"upstream"`
	Header      string `json:"header"`
	Placeholder string `json:"placeholder"`
	Allow       []rule `json:"allow"`
}

type rule struct {
	Methods []string `json:"methods"`
	Path    string   `json:"path"`
}

// a request body is substituted only when it is small enough to hold; a
// larger or unmeasured one is forwarded untouched rather than buffered
const maxBody = 1 << 20

func main() {
	log.SetFlags(0)
	if len(os.Args) != 2 {
		log.Fatal("usage: fencr-credentials-proxy <config.json>")
	}
	cfg, err := load(os.Args[1])
	if err != nil {
		log.Fatal(err)
	}
	if err := serve(cfg); err != nil {
		log.Fatal(err)
	}
}

func load(path string) (*config, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	cfg := &config{}
	if err := json.Unmarshal(raw, cfg); err != nil {
		return nil, err
	}
	if len(cfg.Credentials) == 0 {
		return nil, fmt.Errorf("no credentials configured")
	}
	return cfg, nil
}

// the credential's value, read per request so a rotated file is served
// without a restart; the path watcher restarts the unit for LoadCredential,
// this keeps the window short
func secret(name string) (string, error) {
	dir := os.Getenv("CREDENTIALS_DIRECTORY")
	if dir == "" {
		return "", fmt.Errorf("CREDENTIALS_DIRECTORY is unset")
	}
	raw, err := os.ReadFile(dir + "/" + name)
	if err != nil {
		return "", err
	}
	return strings.TrimRight(string(raw), "\r\n"), nil
}

func serve(cfg *config) error {
	authority, err := loadAuthority()
	if err != nil {
		return err
	}
	byDomain := map[string]*credential{}
	for i := range cfg.Credentials {
		byDomain[strings.ToLower(cfg.Credentials[i].Domain)] = &cfg.Credentials[i]
	}

	if err := os.Remove(cfg.Socket); err != nil && !os.IsNotExist(err) {
		return err
	}
	listener, err := net.Listen("unix", cfg.Socket)
	if err != nil {
		return err
	}
	// the vm's egress proxy reaches it through group kvm and nothing else
	if err := os.Chmod(cfg.Socket, 0o660); err != nil {
		return err
	}

	server := &http.Server{
		Handler:           handler(byDomain),
		TLSConfig:         &tls.Config{GetCertificate: authority.certificate, MinVersion: tls.VersionTLS12},
		ReadHeaderTimeout: 30 * time.Second,
		IdleTimeout:       120 * time.Second,
		ErrorLog:          log.New(io.Discard, "", 0),
	}
	// ServeTLS, not a tls listener: it is what turns on http/2
	return server.ServeTLS(listener, "", "")
}

func handler(byDomain map[string]*credential) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host := strings.ToLower(r.Host)
		if i := strings.IndexByte(host, ':'); i >= 0 {
			host = host[:i]
		}
		c, ok := byDomain[host]
		if !ok {
			record(r, http.StatusNotFound)
			http.Error(w, "fencr: no credential for this domain", http.StatusNotFound)
			return
		}
		if !allowed(c, r) {
			record(r, http.StatusForbidden)
			http.Error(w, "fencr: request not allowed for credential "+c.Name, http.StatusForbidden)
			return
		}
		value, err := secret(c.Name)
		if err != nil {
			log.Printf("fencr: %s: %v", c.Name, err)
			record(r, http.StatusBadGateway)
			http.Error(w, "fencr: credential unavailable", http.StatusBadGateway)
			return
		}
		if err := substitute(r, c.Placeholder, value); err != nil {
			log.Printf("fencr: %s: %v", c.Name, err)
			record(r, http.StatusBadGateway)
			http.Error(w, "fencr: request too large to carry a credential", http.StatusBadGateway)
			return
		}
		forward(c, value, w, r)
	})
}

// a request is admitted when some allow entry covers it, or when none is
// declared at all
func allowed(c *credential, r *http.Request) bool {
	if len(c.Allow) == 0 {
		return true
	}
	for _, entry := range c.Allow {
		if entry.covers(r) {
			return true
		}
	}
	return false
}

func (entry rule) covers(r *http.Request) bool {
	if len(entry.Methods) > 0 {
		method := false
		for _, m := range entry.Methods {
			if strings.EqualFold(m, r.Method) {
				method = true
				break
			}
		}
		if !method {
			return false
		}
	}
	if entry.Path == "" {
		return true
	}
	return pathPattern(entry.Path).MatchString(r.URL.Path)
}

var patterns sync.Map

// "*" stands for any characters, "/" included, as caddy's path matcher did
func pathPattern(pattern string) *regexp.Regexp {
	if cached, ok := patterns.Load(pattern); ok {
		return cached.(*regexp.Regexp)
	}
	var b strings.Builder
	b.WriteString("^")
	for _, part := range strings.Split(pattern, "*") {
		if b.Len() > 1 {
			b.WriteString(".*")
		}
		b.WriteString(regexp.QuoteMeta(part))
	}
	b.WriteString("$")
	compiled := regexp.MustCompile(b.String())
	patterns.Store(pattern, compiled)
	return compiled
}

// the guest may carry the placeholder where a header has no room: in the
// uri, or in the body of a request small enough to hold
func substitute(r *http.Request, placeholder, value string) error {
	if placeholder == "" {
		return nil
	}
	if strings.Contains(r.URL.RawQuery, placeholder) {
		r.URL.RawQuery = strings.ReplaceAll(r.URL.RawQuery, placeholder, url.QueryEscape(value))
	}
	if strings.Contains(r.URL.Path, placeholder) {
		r.URL.Path = strings.ReplaceAll(r.URL.Path, placeholder, value)
		r.URL.RawPath = ""
	}
	if r.Body == nil || r.ContentLength <= 0 || r.ContentLength > maxBody {
		return nil
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, maxBody+1))
	if closeErr := r.Body.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	if int64(len(body)) > maxBody {
		return fmt.Errorf("body over %d bytes", maxBody)
	}
	body = bytes.ReplaceAll(body, []byte(placeholder), []byte(value))
	r.Body = io.NopCloser(bytes.NewReader(body))
	r.ContentLength = int64(len(body))
	return nil
}

func forward(c *credential, value string, w http.ResponseWriter, r *http.Request) {
	upstream, err := url.Parse(c.Upstream)
	if err != nil {
		log.Printf("fencr: %s: %v", c.Name, err)
		record(r, http.StatusBadGateway)
		http.Error(w, "fencr: bad upstream", http.StatusBadGateway)
		return
	}
	status := http.StatusBadGateway
	proxy := &httputil.ReverseProxy{
		// server-sent events and other long-lived streams must not be held
		FlushInterval: -1,
		Rewrite: func(p *httputil.ProxyRequest) {
			p.SetURL(upstream)
			p.Out.Host = upstream.Host
			p.Out.Header.Set(c.Header, value)
		},
		ModifyResponse: func(resp *http.Response) error {
			status = resp.StatusCode
			return nil
		},
		ErrorHandler: func(w http.ResponseWriter, _ *http.Request, err error) {
			log.Printf("fencr: %s: %v", c.Name, err)
			w.WriteHeader(http.StatusBadGateway)
		},
		ErrorLog: log.New(io.Discard, "", 0),
	}
	proxy.ServeHTTP(w, r)
	record(r, status)
}

// one line per request in the journal: what it was and how it ended, never
// a header, since the credential and whatever the guest sent live there
func record(r *http.Request, status int) {
	line, err := json.Marshal(struct {
		Msg    string `json:"msg"`
		Method string `json:"method"`
		Host   string `json:"host"`
		URI    string `json:"uri"`
		Status int    `json:"status"`
	}{"handled request", r.Method, r.Host, r.URL.RequestURI(), status})
	if err != nil {
		return
	}
	log.Print(string(line))
}

// the host's authority, signing one certificate per domain the vm calls,
// kept for the life of the process
type authority struct {
	cert  *x509.Certificate
	key   any
	mu    sync.Mutex
	certs map[string]*tls.Certificate
}

func loadAuthority() (*authority, error) {
	dir := os.Getenv("CREDENTIALS_DIRECTORY")
	if dir == "" {
		return nil, fmt.Errorf("CREDENTIALS_DIRECTORY is unset")
	}
	pair, err := tls.LoadX509KeyPair(dir+"/ca.crt", dir+"/ca.key")
	if err != nil {
		return nil, err
	}
	cert, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		return nil, err
	}
	return &authority{cert: cert, key: pair.PrivateKey, certs: map[string]*tls.Certificate{}}, nil
}

func (a *authority) certificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	name := strings.ToLower(hello.ServerName)
	if name == "" {
		return nil, fmt.Errorf("no server name")
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if cached, ok := a.certs[name]; ok {
		return cached, nil
	}
	issued, err := a.issue(name)
	if err != nil {
		return nil, err
	}
	a.certs[name] = issued
	return issued, nil
}

func (a *authority) issue(name string) (*tls.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, err
	}
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: name},
		DNSNames:     []string{name},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().AddDate(1, 0, 0),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, a.cert, &key.PublicKey, a.key)
	if err != nil {
		return nil, err
	}
	return &tls.Certificate{
		Certificate: [][]byte{der},
		PrivateKey:  key,
		Leaf:        template,
	}, nil
}
