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
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

type credential struct {
	Name        string `json:"name"`
	Domain      string `json:"domain"`
	Upstream    string `json:"upstream"`
	Header      string `json:"header"`
	Bearer      bool   `json:"bearer"`
	Placeholder string `json:"placeholder"`
	Substitute  bool   `json:"substitute"`
	Allow       []rule `json:"allow"`

	// everything below is fixed by the configuration and the credentials
	// systemd delivered at start, so it is derived once in prepare()
	value    string
	upstream *url.URL
}

type rule struct {
	Methods []string `json:"methods"`
	Path    string   `json:"path"`

	pattern *regexp.Regexp
}

// LoadCredential copies the source once, at start, and the path unit
// restarts this unit when a watched file is written; so the value cannot
// change under a running process and is read here rather than per request
func prepare(c *credential) error {
	value, err := secret(c.Name)
	if err != nil {
		return fmt.Errorf("credential %q: %w", c.Name, err)
	}
	c.value = value
	upstream, err := url.Parse(c.Upstream)
	if err != nil {
		return fmt.Errorf("credential %q: %w", c.Name, err)
	}
	c.upstream = upstream
	for at := range c.Allow {
		if c.Allow[at].Path != "" {
			c.Allow[at].pattern = pathPattern(c.Allow[at].Path)
		}
	}
	return nil
}

// a request body is substituted only when it is small enough to hold; a
// larger or unmeasured one is forwarded untouched rather than buffered
const maxBody = 1 << 20

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

func handler(byDomain map[string][]*credential) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host := strings.ToLower(r.Host)
		if i := strings.IndexByte(host, ':'); i >= 0 {
			host = host[:i]
		}
		// what the guest sent: substitute puts the credential in the uri, and
		// the journal must carry the placeholder it replaced, not the value
		uri := r.URL.RequestURI()
		// the journal and the guest must never disagree on how a request ended
		refuse := func(status int, message string) {
			record(r, uri, status)
			http.Error(w, message, status)
		}
		candidates, ok := byDomain[host]
		if !ok {
			refuse(http.StatusNotFound, "fencr: no credential for this domain")
			return
		}
		var c *credential
		for _, candidate := range candidates {
			if !allowed(candidate, r) {
				continue
			}
			if c != nil {
				refuse(http.StatusForbidden, "fencr: request matches multiple credentials")
				return
			}
			c = candidate
		}
		if c == nil {
			refuse(http.StatusForbidden, "fencr: request not allowed for any credential")
			return
		}
		if err := substitute(r, c, c.value); err != nil {
			log.Printf("fencr: %s: %v", c.Name, err)
			refuse(http.StatusBadGateway, "fencr: the request body could not be read")
			return
		}
		forward(c, uri, w, r)
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
	if entry.pattern == nil {
		return true
	}
	return entry.pattern.MatchString(r.URL.Path)
}

// "*" stands for any characters, "/" included: an allow entry scopes a
// credential by path, and a path is not a place to be subtle
func pathPattern(pattern string) *regexp.Regexp {
	var b strings.Builder
	b.WriteString("^")
	for _, part := range strings.Split(pattern, "*") {
		if b.Len() > 1 {
			b.WriteString(".*")
		}
		b.WriteString(regexp.QuoteMeta(part))
	}
	b.WriteString("$")
	return regexp.MustCompile(b.String())
}

// the header is injected either way; this pass is for an api that wants the
// key in the uri or a body instead, and only a credential that asks for it
func substitute(r *http.Request, c *credential, value string) error {
	placeholder := c.Placeholder
	if !c.Substitute || placeholder == "" {
		return nil
	}
	if strings.Contains(r.URL.RawQuery, placeholder) {
		r.URL.RawQuery = strings.ReplaceAll(r.URL.RawQuery, placeholder, url.QueryEscape(value))
	}
	if strings.Contains(r.URL.Path, placeholder) {
		r.URL.Path = strings.ReplaceAll(r.URL.Path, placeholder, value)
		r.URL.RawPath = ""
	}
	return rewriteBody(&r.Body, &r.ContentLength, placeholder, value)
}

// net/http stops a measured body at its length, so the guard is the whole
// bound: a streamed or oversized body is forwarded untouched rather than held
func rewriteBody(body *io.ReadCloser, length *int64, from, to string) error {
	if *body == nil || *length <= 0 || *length > maxBody {
		return nil
	}
	raw, err := io.ReadAll(*body)
	if closeErr := (*body).Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	raw = bytes.ReplaceAll(raw, []byte(from), []byte(to))
	*body, *length = io.NopCloser(bytes.NewReader(raw)), int64(len(raw))
	return nil
}

// an upstream that echoes a request back would hand the guest the real
// value, which is the one way a credential leaks through a proxy that never
// gives it out. the placeholder goes back where it came from. bounded like
// the request pass: a streamed or unmeasured body is forwarded untouched
func scrub(resp *http.Response, value, placeholder string) error {
	if placeholder == "" || value == "" {
		return nil
	}
	for name, values := range resp.Header {
		for at, text := range values {
			resp.Header[name][at] = strings.ReplaceAll(text, value, placeholder)
		}
	}
	if err := rewriteBody(&resp.Body, &resp.ContentLength, value, placeholder); err != nil {
		return err
	}
	if resp.ContentLength > 0 {
		resp.Header.Set("Content-Length", strconv.FormatInt(resp.ContentLength, 10))
	}
	return nil
}

func forward(c *credential, uri string, w http.ResponseWriter, r *http.Request) {
	value, upstream := c.value, c.upstream
	status := http.StatusBadGateway
	proxy := &httputil.ReverseProxy{
		// server-sent events and other long-lived streams must not be held
		FlushInterval: -1,
		Rewrite: func(p *httputil.ProxyRequest) {
			p.SetURL(upstream)
			p.Out.Host = upstream.Host
			headerValue := value
			if c.Bearer && !strings.HasPrefix(strings.ToLower(value), "bearer ") {
				headerValue = "Bearer " + value
			}
			p.Out.Header.Set(c.Header, headerValue)
		},
		ModifyResponse: func(resp *http.Response) error {
			status = resp.StatusCode
			return scrub(resp, value, c.Placeholder)
		},
		ErrorHandler: func(w http.ResponseWriter, _ *http.Request, err error) {
			log.Printf("fencr: %s: %v", c.Name, err)
			w.WriteHeader(http.StatusBadGateway)
		},
		ErrorLog: log.New(io.Discard, "", 0),
	}
	proxy.ServeHTTP(w, r)
	record(r, uri, status)
}

// one line per request in the journal: what it was and how it ended, never
// a header, since the credential and whatever the guest sent live there
func record(r *http.Request, uri string, status int) {
	line, err := json.Marshal(struct {
		Msg    string `json:"msg"`
		Method string `json:"method"`
		Host   string `json:"host"`
		URI    string `json:"uri"`
		Status int    `json:"status"`
	}{"handled request", r.Method, r.Host, uri, status})
	if err != nil {
		return
	}
	log.Print(string(line))
}

// the host's authority, signing one certificate per domain the sandbox calls,
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
