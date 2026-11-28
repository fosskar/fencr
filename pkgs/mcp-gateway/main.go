// fencr-mcp-gateway serves each mcp-enabled sandbox, named by the socket it
// arrives on, the tools its allow patterns grant from explicit backends.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"maps"
	"net"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type server struct {
	URL             string   `json:"url,omitempty"`
	TokenCredential string   `json:"token_credential,omitempty"`
	Socket          string   `json:"socket,omitempty"`
	HiddenTools     []string `json:"hidden_tools"`
}

type principal struct {
	Socket string   `json:"socket"`
	Allow  []string `json:"allow"`
	// a server with per-sandbox credentials has a socket per principal
	BackendSockets map[string]string `json:"backend_sockets"`
}

type config struct {
	Servers    map[string]*server    `json:"servers"`
	Principals map[string]*principal `json:"principals"`
}

func matches(name string, patterns []string) bool {
	for _, pattern := range patterns {
		// newGateway refused malformed patterns
		if ok, _ := path.Match(pattern, name); ok {
			return true
		}
	}
	return false
}

func secret(name string) (string, error) {
	value, err := os.ReadFile(filepath.Join(os.Getenv("CREDENTIALS_DIRECTORY"), name))
	if err != nil {
		return "", err
	}
	if token := strings.TrimSpace(string(value)); token != "" {
		return token, nil
	}
	return "", fmt.Errorf("credential is empty: %s", name)
}

type bearer struct {
	token string
	next  http.RoundTripper
}

func (b bearer) RoundTrip(request *http.Request) (*http.Response, error) {
	request = request.Clone(request.Context())
	request.Header.Set("Authorization", "Bearer "+b.token)
	return b.next.RoundTrip(request)
}

// no Proxy: url backends are on host loopback, whatever the environment says
var loopback = &http.Transport{
	DialContext:           (&net.Dialer{Timeout: 30 * time.Second}).DialContext,
	ResponseHeaderTimeout: 300 * time.Second,
}

// the gateway forwards no server-initiated message, so it opens no
// standalone stream, and it pins the version whose initialize handshake
// opens the session it reuses
func downstream(ctx context.Context, backend *server) (*mcp.ClientSession, error) {
	var transport mcp.Transport
	if backend.Socket != "" {
		// systemd accepts each connection and hands it to a fresh backend
		// process as its stdin and stdout, so this is the stdio transport
		conn, err := (&net.Dialer{}).DialContext(ctx, "unix", backend.Socket)
		if err != nil {
			return nil, err
		}
		transport = &mcp.IOTransport{Reader: conn, Writer: conn}
	} else {
		token, err := secret(backend.TokenCredential)
		if err != nil {
			return nil, err
		}
		transport = &mcp.StreamableClientTransport{
			Endpoint: backend.URL,
			HTTPClient: &http.Client{
				Transport:     bearer{token, loopback},
				CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
			},
			DisableStandaloneSSE: true,
		}
	}
	client := mcp.NewClient(&mcp.Implementation{Name: "fencr-mcp-gateway", Version: "0"}, nil)
	return client.Connect(ctx, transport, &mcp.ClientSessionOptions{ProtocolVersion: "2025-11-25"})
}

// the handshake costs more than the call it carries: a fresh session per
// tool call spends about 100ms on the transport, the initialize and the
// teardown before the backend sees anything. reuse one inside a window
const idleWindow = 30 * time.Second

type key struct{ principal, server string }

type slot struct {
	sync.Mutex
	session *mcp.ClientSession
	used    time.Time
}

// sessions holds one downstream session per principal per backend. keyed by
// principal, so a session never carries one sandbox's state to another.
// opened on first use, so a backend that is down cannot keep the gateway
// from starting and every mcp-enabled sandbox from its other backends.
// dropped on the first call past the window, so a restarted backend heals
// without any reconnect logic of its own
type sessions struct {
	mu    sync.Mutex
	slots map[key]*slot
}

func (s *sessions) slot(k key) *slot {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.slots[k] == nil {
		s.slots[k] = &slot{}
	}
	return s.slots[k]
}

func (s *sessions) acquire(ctx context.Context, k key, backend *server) (*mcp.ClientSession, error) {
	slot := s.slot(k)
	slot.Lock()
	defer slot.Unlock()
	if slot.session != nil && time.Since(slot.used) < idleWindow {
		slot.used = time.Now()
		return slot.session, nil
	}
	if slot.session != nil {
		slot.session.Close()
		slot.session = nil
	}
	session, err := downstream(ctx, backend)
	if err != nil {
		return nil, err
	}
	slot.session, slot.used = session, time.Now()
	return session, nil
}

func (s *sessions) discard(k key, session *mcp.ClientSession) {
	slot := s.slot(k)
	slot.Lock()
	defer slot.Unlock()
	if slot.session == session {
		slot.session = nil
		session.Close()
	}
}

// call runs action against the session, once more on a fresh one if it
// fails and retry is set. a session can die between two calls without
// anything noticing, so a listing retries rather than reports the first
// failure; a tool call may have acted on the backend before it failed
func (s *sessions) call(ctx context.Context, k key, backend *server, retry bool, action func(*mcp.ClientSession) error) error {
	for attempt := 0; ; attempt++ {
		session, err := s.acquire(ctx, k, backend)
		if err != nil {
			return err
		}
		if err = action(session); err == nil {
			return nil
		}
		s.discard(k, session)
		if !retry || attempt == 1 {
			return err
		}
	}
}

// sessions one principal may hold at once; the gateway is shared by every
// mcp-enabled sandbox, and each session is a transport and a server task
const maxSessions = 16

type front struct {
	server  *mcp.Server
	handler http.Handler
	mu      sync.Mutex
	opening int
}

type gateway struct {
	config   *config
	sessions *sessions
	// keyed by socket path: each sandbox reaches the gateway through a
	// socket in its own run directory, which only its hypervisor enters
	fronts map[string]*front
}

func failed(message string) *mcp.CallToolResult {
	return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: message}}, IsError: true}
}

func (g *gateway) permitted(p *principal, serverName, tool string) bool {
	return !matches(tool, g.config.Servers[serverName].HiddenTools) && matches(serverName+"."+tool, p.Allow)
}

// reachable says whether any allow pattern could match one of the server's
// tools. a backend no pattern reaches is never opened for this principal: it
// would run, or be asked for its tools, only to have all of them dropped. a
// glob before the first dot could match any server, so such a pattern counts
// as reaching every one
func reachable(p *principal, serverName string) bool {
	for _, pattern := range p.Allow {
		head, _, dot := strings.Cut(pattern, ".")
		if strings.ContainsAny(head, "*?[") || dot && head == serverName {
			return true
		}
	}
	return false
}

func (g *gateway) backend(p *principal, serverName string) *server {
	backend := g.config.Servers[serverName]
	if socket, ok := p.BackendSockets[serverName]; ok {
		own := *backend
		own.Socket = socket
		return &own
	}
	return backend
}

func (g *gateway) listTools(ctx context.Context, name string, p *principal) (*mcp.ListToolsResult, error) {
	tools := []*mcp.Tool{}
	for _, serverName := range slices.Sorted(maps.Keys(g.config.Servers)) {
		if !reachable(p, serverName) {
			continue
		}
		var found []*mcp.Tool
		err := g.sessions.call(ctx, key{name, serverName}, g.backend(p, serverName), true, func(session *mcp.ClientSession) error {
			found = nil
			params := &mcp.ListToolsParams{}
			for {
				result, err := session.ListTools(ctx, params)
				if err != nil {
					return err
				}
				for _, tool := range result.Tools {
					if g.permitted(p, serverName, tool.Name) {
						renamed := *tool
						renamed.Name = serverName + "__" + tool.Name
						found = append(found, &renamed)
					}
				}
				if result.NextCursor == "" {
					return nil
				}
				params.Cursor = result.NextCursor
			}
		})
		if err != nil {
			return nil, err
		}
		tools = append(tools, found...)
	}
	return &mcp.ListToolsResult{Tools: tools}, nil
}

func (g *gateway) callTool(ctx context.Context, name string, p *principal, params *mcp.CallToolParamsRaw) *mcp.CallToolResult {
	serverName, tool, separator := strings.Cut(params.Name, "__")
	if !separator || g.config.Servers[serverName] == nil || tool == "" || !g.permitted(p, serverName, tool) {
		log.Printf("%s: refused %q", name, params.Name)
		return failed("unknown MCP gateway tool")
	}
	var arguments any = map[string]any{}
	if len(params.Arguments) > 0 && string(params.Arguments) != "null" {
		arguments = params.Arguments
	}
	var result *mcp.CallToolResult
	err := g.sessions.call(ctx, key{name, serverName}, g.backend(p, serverName), false, func(session *mcp.ClientSession) (err error) {
		result, err = session.CallTool(ctx, &mcp.CallToolParams{Name: tool, Arguments: arguments})
		return err
	})
	if err != nil {
		log.Printf("%s: called %s.%s: failed: %v", name, serverName, tool, err)
		return failed(err.Error())
	}
	if result.IsError {
		log.Printf("%s: called %s.%s: error", name, serverName, tool)
	} else {
		log.Printf("%s: called %s.%s", name, serverName, tool)
	}
	return result
}

func (g *gateway) serverFor(name string, p *principal) *mcp.Server {
	server := mcp.NewServer(
		&mcp.Implementation{Name: "fencr-mcp-gateway", Version: "0"},
		&mcp.ServerOptions{Capabilities: &mcp.ServerCapabilities{Tools: &mcp.ToolCapabilities{}}},
	)
	server.AddReceivingMiddleware(func(next mcp.MethodHandler) mcp.MethodHandler {
		return func(ctx context.Context, method string, request mcp.Request) (mcp.Result, error) {
			switch method {
			case "tools/list":
				return g.listTools(ctx, name, p)
			case "tools/call":
				return g.callTool(ctx, name, p, request.(*mcp.CallToolRequest).Params), nil
			}
			return next(ctx, method, request)
		}
	})
	return server
}

func newGateway(c *config) (http.Handler, error) {
	for _, backend := range c.Servers {
		for _, pattern := range backend.HiddenTools {
			if _, err := path.Match(pattern, ""); err != nil {
				return nil, fmt.Errorf("hidden_tools pattern %q: %w", pattern, err)
			}
		}
	}
	g := &gateway{config: c, sessions: &sessions{slots: map[key]*slot{}}, fronts: map[string]*front{}}
	for name, p := range c.Principals {
		for _, pattern := range p.Allow {
			if _, err := path.Match(pattern, ""); err != nil {
				return nil, fmt.Errorf("%s: allow pattern %q: %w", name, pattern, err)
			}
		}
		server := g.serverFor(name, p)
		g.fronts[p.Socket] = &front{
			server: server,
			handler: mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return server }, &mcp.StreamableHTTPOptions{
				JSONResponse:   true,
				SessionTimeout: 30 * time.Minute,
			}),
		}
	}
	mux := http.NewServeMux()
	mux.Handle("/mcp/", g)
	return mux, nil
}

func (g *gateway) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	var f *front
	if addr, ok := r.Context().Value(http.LocalAddrContextKey).(net.Addr); ok {
		f = g.fronts[addr.String()]
	}
	if f == nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	// each principal owns a separate session registry, so the sdk finds
	// the principal's own session or answers 404
	if r.Header.Get("Mcp-Session-Id") != "" {
		f.handler.ServeHTTP(w, r)
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "Bad Request: missing session id", http.StatusBadRequest)
		return
	}
	// the slot is taken before the sdk connects the session, so concurrent
	// opens cannot all pass the check
	f.mu.Lock()
	live := 0
	for range f.server.Sessions() {
		live++
	}
	if live+f.opening >= maxSessions {
		f.mu.Unlock()
		http.Error(w, "Too Many Requests: session limit", http.StatusTooManyRequests)
		return
	}
	f.opening++
	f.mu.Unlock()
	defer func() {
		f.mu.Lock()
		f.opening--
		f.mu.Unlock()
	}()
	f.handler.ServeHTTP(w, r)
}

func run() error {
	data, err := os.ReadFile(os.Getenv("MCP_GATEWAY_CONFIG"))
	if err != nil {
		return err
	}
	var c config
	if err := json.Unmarshal(data, &c); err != nil {
		return fmt.Errorf("MCP_GATEWAY_CONFIG: %w", err)
	}
	// pid 1 holds the sockets while this process restarts, so a request
	// never finds the path free for another listener
	if os.Getenv("LISTEN_PID") != strconv.Itoa(os.Getpid()) {
		return errors.New("no socket from systemd: run from fencr-mcp-gateway.socket")
	}
	count, err := strconv.Atoi(os.Getenv("LISTEN_FDS"))
	if err != nil {
		return fmt.Errorf("LISTEN_FDS: %w", err)
	}
	var listeners []net.Listener
	var paths, sockets []string
	for fd := 3; fd < 3+count; fd++ {
		file := os.NewFile(uintptr(fd), "listen")
		listener, err := net.FileListener(file)
		file.Close()
		if err != nil {
			return fmt.Errorf("fd %d: %w", fd, err)
		}
		listeners = append(listeners, listener)
		paths = append(paths, listener.Addr().String())
	}
	for _, p := range c.Principals {
		sockets = append(sockets, p.Socket)
	}
	slices.Sort(paths)
	slices.Sort(sockets)
	if !slices.Equal(paths, sockets) {
		return fmt.Errorf("systemd passed sockets %v, not one per principal", paths)
	}
	handler, err := newGateway(&c)
	if err != nil {
		return err
	}
	server := &http.Server{Handler: handler}
	errs := make(chan error)
	for _, listener := range listeners {
		go func() { errs <- server.Serve(listener) }()
	}
	return <-errs
}

func main() {
	log.SetFlags(0)
	if err := run(); err != nil {
		log.Fatal(err)
	}
}
