package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

// each test runs the gateway as its own process, handed its sockets the way
// systemd hands them. FENCR_MCP_GATEWAY names another executable to run in
// its place, so the same cases can hold another implementation to account
const helper = "FENCR_MCP_GATEWAY_TEST_HELPER"

func TestMain(m *testing.M) {
	if os.Getenv(helper) != "" {
		os.Setenv("LISTEN_PID", strconv.Itoa(os.Getpid()))
		if external := os.Getenv("FENCR_MCP_GATEWAY"); external != "" {
			log.Fatal(syscall.Exec(external, []string{external}, os.Environ()))
		}
		main()
		return
	}
	os.Exit(m.Run())
}

const token = "backend-secret"

// httpBackend is a url backend: plain JSON-RPC over POST, no session id
type httpBackend struct {
	*httptest.Server
	mu sync.Mutex
	// the path of every initialize, which names the backend
	opened   []string
	calls    []string
	tokens   map[string]bool
	failList int
	dropCall bool
}

func newHTTPBackend(t *testing.T) *httpBackend {
	b := &httpBackend{tokens: map[string]bool{}}
	b.Server = httptest.NewServer(http.HandlerFunc(b.serve))
	t.Cleanup(b.Close)
	return b
}

func (b *httpBackend) serve(w http.ResponseWriter, r *http.Request) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.tokens[r.Header.Get("Authorization")] = true
	if r.Header.Get("Authorization") != "Bearer "+token {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	switch r.Method {
	case http.MethodDelete:
		return
	case http.MethodPost:
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	var request struct {
		ID     json.RawMessage `json:"id"`
		Method string          `json:"method"`
		Params struct {
			Name      string          `json:"name"`
			Arguments json.RawMessage `json:"arguments"`
			Cursor    string          `json:"cursor"`
		} `json:"params"`
	}
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	if request.ID == nil {
		w.WriteHeader(http.StatusAccepted)
		return
	}
	reply := map[string]any{"jsonrpc": "2.0", "id": request.ID}
	switch request.Method {
	case "initialize":
		b.opened = append(b.opened, r.URL.Path)
		reply["result"] = initializeResult
	case "tools/list":
		if b.failList > 0 {
			b.failList--
			reply["error"] = map[string]any{"code": -32603, "message": "the backend went away"}
		} else if request.Params.Cursor == "" {
			reply["result"] = map[string]any{"tools": tools("read", "write"), "nextCursor": "second"}
		} else {
			reply["result"] = map[string]any{"tools": tools("hidden")}
		}
	case "tools/call":
		b.calls = append(b.calls, request.Params.Name+" "+string(request.Params.Arguments))
		if b.dropCall {
			b.dropCall = false
			conn, _, err := http.NewResponseController(w).Hijack()
			if err == nil {
				conn.Close()
			}
			return
		}
		reply["result"] = map[string]any{"content": []any{map[string]any{"type": "text", "text": "done"}}}
	default:
		reply["error"] = map[string]any{"code": -32601, "message": "method not found"}
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(reply)
}

func (b *httpBackend) state() (opened, calls []string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return slices.Clone(b.opened), slices.Clone(b.calls)
}

var initializeResult = map[string]any{
	"protocolVersion": "2025-03-26",
	"capabilities":    map[string]any{"tools": map[string]any{}},
	"serverInfo":      map[string]any{"name": "backend", "version": "1"},
}

func tools(names ...string) []any {
	var found []any
	for _, name := range names {
		found = append(found, map[string]any{"name": name, "inputSchema": map[string]any{"type": "object"}})
	}
	return found
}

type harness struct {
	t       *testing.T
	dir     string
	backend *httpBackend
	config  config
}

func setup(t *testing.T) *harness {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "backend"), []byte(token), 0o600); err != nil {
		t.Fatal(err)
	}
	h := &harness{t: t, dir: dir, backend: newHTTPBackend(t)}
	h.config = config{
		Servers: map[string]*server{"calendar": h.url("calendar")},
		Principals: map[string]*principal{
			"agent":  {Socket: filepath.Join(dir, "agent"), Allow: []string{"calendar.*"}},
			"reader": {Socket: filepath.Join(dir, "reader"), Allow: []string{"calendar.read"}},
		},
	}
	return h
}

func (h *harness) url(name string) *server {
	return &server{URL: h.backend.URL + "/" + name + "/", TokenCredential: "backend", HiddenTools: []string{"hidden"}}
}

// launch runs the gateway with a listener bound at each path until the test
// ends. exited is closed when the process exits, and status is its Wait
// result from then on
func (h *harness) launch(paths ...string) (exited <-chan struct{}, status func() error) {
	t := h.t
	data, err := json.Marshal(h.config)
	if err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(h.dir, "config.json")
	if err := os.WriteFile(configPath, data, 0o600); err != nil {
		t.Fatal(err)
	}
	command := exec.Command(os.Args[0])
	for _, path := range paths {
		listener, err := net.Listen("unix", path)
		if err != nil {
			t.Fatal(err)
		}
		// the gateway, not this process, owns the path from here on
		listener.(*net.UnixListener).SetUnlinkOnClose(false)
		file, err := listener.(*net.UnixListener).File()
		if err != nil {
			t.Fatal(err)
		}
		listener.Close()
		command.ExtraFiles = append(command.ExtraFiles, file)
	}
	var output bytes.Buffer
	command.Stdout = &output
	command.Stderr = &output
	command.Env = append(os.Environ(),
		helper+"=1",
		"MCP_GATEWAY_CONFIG="+configPath,
		"CREDENTIALS_DIRECTORY="+h.dir,
		"LISTEN_FDS="+strconv.Itoa(len(paths)),
	)
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	for _, file := range command.ExtraFiles {
		file.Close()
	}
	done := make(chan struct{})
	var waitErr error
	go func() {
		waitErr = command.Wait()
		close(done)
	}()
	t.Cleanup(func() {
		command.Process.Kill()
		<-done
		if t.Failed() {
			t.Logf("gateway output:\n%s", output.String())
		}
	})
	return done, func() error { return waitErr }
}

// start runs the gateway on the principals' sockets and returns a client
// for each principal
func (h *harness) start() map[string]*client {
	var paths []string
	clients := map[string]*client{}
	for name, p := range h.config.Principals {
		paths = append(paths, p.Socket)
		clients[name] = dial(h.t, p.Socket)
	}
	h.launch(paths...)
	return clients
}

type client struct {
	t    *testing.T
	http *http.Client
}

func dial(t *testing.T, path string) *client {
	transport := &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "unix", path)
	}}
	t.Cleanup(transport.CloseIdleConnections)
	return &client{t: t, http: &http.Client{Transport: transport, Timeout: 30 * time.Second}}
}

func (c *client) send(method, session string, message any) (int, string) {
	c.t.Helper()
	var body io.Reader
	if message != nil {
		data, err := json.Marshal(message)
		if err != nil {
			c.t.Fatal(err)
		}
		body = bytes.NewReader(data)
	}
	request, err := http.NewRequest(method, "http://gateway/mcp/", body)
	if err != nil {
		c.t.Fatal(err)
	}
	request.Header.Set("Accept", "application/json, text/event-stream")
	request.Header.Set("Content-Type", "application/json")
	if session != "" {
		request.Header.Set("Mcp-Session-Id", session)
		request.Header.Set("MCP-Protocol-Version", "2025-03-26")
	}
	response, err := c.http.Do(request)
	if err != nil {
		c.t.Fatal(err)
	}
	defer response.Body.Close()
	data, err := io.ReadAll(response.Body)
	if err != nil {
		c.t.Fatal(err)
	}
	if session == "" && response.StatusCode == http.StatusOK {
		return response.StatusCode, response.Header.Get("Mcp-Session-Id")
	}
	return response.StatusCode, string(data)
}

func (c *client) initialize() string {
	c.t.Helper()
	status, session := c.send(http.MethodPost, "", map[string]any{
		"jsonrpc": "2.0", "id": 1, "method": "initialize",
		"params": map[string]any{
			"protocolVersion": "2025-03-26", "capabilities": map[string]any{},
			"clientInfo": map[string]any{"name": "test", "version": "1"},
		},
	})
	if status != http.StatusOK || session == "" {
		c.t.Fatalf("initialize: %d %q", status, session)
	}
	status, body := c.send(http.MethodPost, session, map[string]any{"jsonrpc": "2.0", "method": "notifications/initialized"})
	if status != http.StatusAccepted {
		c.t.Fatalf("initialized: %d %s", status, body)
	}
	return session
}

type result struct {
	Tools []struct {
		Name string `json:"name"`
	} `json:"tools"`
	IsError bool `json:"isError"`
	Content []struct {
		Text string `json:"text"`
	} `json:"content"`
}

func (r result) names() []string {
	names := []string{}
	for _, tool := range r.Tools {
		names = append(names, tool.Name)
	}
	return names
}

func (c *client) request(session, method string, params any) result {
	c.t.Helper()
	if params == nil {
		params = map[string]any{}
	}
	status, body := c.send(http.MethodPost, session, map[string]any{"jsonrpc": "2.0", "id": 2, "method": method, "params": params})
	if status != http.StatusOK {
		c.t.Fatalf("%s: %d %s", method, status, body)
	}
	if strings.Contains(body, token) {
		c.t.Fatalf("%s: the backend token reached the client: %s", method, body)
	}
	var response struct {
		Result *result `json:"result"`
	}
	if err := json.Unmarshal([]byte(body), &response); err != nil || response.Result == nil {
		c.t.Fatalf("%s: %v %s", method, err, body)
	}
	return *response.Result
}

func (c *client) call(session, tool string) result {
	c.t.Helper()
	return c.request(session, "tools/call", map[string]any{"name": tool})
}

func TestListingAndInvocationAreScoped(t *testing.T) {
	h := setup(t)
	clients := h.start()
	agent := clients["agent"].initialize()
	reader := clients["reader"].initialize()
	// the socket a request arrives on names the principal
	if got := clients["agent"].request(agent, "tools/list", nil).names(); !slices.Equal(got, []string{"calendar__read", "calendar__write"}) {
		t.Fatalf("agent lists %v", got)
	}
	if got := clients["reader"].request(reader, "tools/list", nil).names(); !slices.Equal(got, []string{"calendar__read"}) {
		t.Fatalf("reader lists %v", got)
	}
	for _, name := range []string{"calendar__write", "calendar__hidden", "other__read", "calendar", "calendar__"} {
		if !clients["reader"].call(reader, name).IsError {
			t.Fatalf("reader called %s", name)
		}
	}
	if _, calls := h.backend.state(); len(calls) != 0 {
		t.Fatalf("refused calls reached the backend: %v", calls)
	}
	clients["reader"].call(reader, "calendar__read")
	if _, calls := h.backend.state(); !slices.Equal(calls, []string{"read {}"}) {
		t.Fatalf("calls %v", calls)
	}
}

func TestOneSessionPerPrincipalIsReused(t *testing.T) {
	h := setup(t)
	clients := h.start()
	agent := clients["agent"].initialize()
	reader := clients["reader"].initialize()
	clients["agent"].call(agent, "calendar__read")
	clients["agent"].call(agent, "calendar__read")
	// the handshake costs more than the call, so the second one reuses the
	// session the first opened
	if opened, _ := h.backend.state(); len(opened) != 1 {
		t.Fatalf("opened %v", opened)
	}
	clients["reader"].call(reader, "calendar__read")
	// and a second principal opens its own: a session must never carry one
	// sandbox's state to another
	opened, calls := h.backend.state()
	if len(opened) != 2 || len(calls) != 3 {
		t.Fatalf("opened %v, calls %v", opened, calls)
	}
}

func TestADeadSessionIsRetriedOnAFreshOneForAListing(t *testing.T) {
	h := setup(t)
	clients := h.start()
	agent := clients["agent"].initialize()
	clients["agent"].request(agent, "tools/list", nil)
	// a backend may go away between two calls with nothing noticing
	h.backend.mu.Lock()
	h.backend.failList = 1
	h.backend.mu.Unlock()
	if got := clients["agent"].request(agent, "tools/list", nil).names(); len(got) != 2 {
		t.Fatalf("listed %v", got)
	}
	if opened, _ := h.backend.state(); len(opened) != 2 {
		t.Fatalf("opened %v", opened)
	}
}

// the backend may have acted before the failure, so a call is never sent twice
func TestAToolCallIsNotRetried(t *testing.T) {
	h := setup(t)
	clients := h.start()
	agent := clients["agent"].initialize()
	h.backend.mu.Lock()
	h.backend.dropCall = true
	h.backend.mu.Unlock()
	if !clients["agent"].call(agent, "calendar__write").IsError {
		t.Fatal("a call whose response never arrived succeeded")
	}
	if _, calls := h.backend.state(); !slices.Equal(calls, []string{"write {}"}) {
		t.Fatalf("calls %v", calls)
	}
	// the next call opens a fresh session
	if clients["agent"].call(agent, "calendar__read").IsError {
		t.Fatal("the call after a failure failed")
	}
	if opened, _ := h.backend.state(); len(opened) != 2 {
		t.Fatalf("opened %v", opened)
	}
}

func TestABackendNoPatternReachesIsNeverOpened(t *testing.T) {
	for _, test := range []struct {
		allow    []string
		expected []string
	}{
		{[]string{"calendar.read", "calendar"}, []string{"/calendar/"}},
		{[]string{"grafana.read"}, []string{"/grafana/"}},
		{[]string{"graf*.read"}, []string{"/calendar/", "/grafana/"}},
		{[]string{"*"}, []string{"/calendar/", "/grafana/"}},
		{[]string{}, nil},
	} {
		t.Run(strings.Join(test.allow, ","), func(t *testing.T) {
			h := setup(t)
			h.config.Servers["grafana"] = h.url("grafana")
			h.config.Principals["reader"].Allow = test.allow
			reader := h.start()["reader"]
			reader.request(reader.initialize(), "tools/list", nil)
			if opened, _ := h.backend.state(); !slices.Equal(opened, test.expected) {
				t.Fatalf("opened %v, want %v", opened, test.expected)
			}
		})
	}
}

func TestEmptyAllowDeniesEveryTool(t *testing.T) {
	h := setup(t)
	h.config.Principals["reader"].Allow = []string{}
	reader := h.start()["reader"]
	session := reader.initialize()
	if got := reader.request(session, "tools/list", nil).names(); len(got) != 0 {
		t.Fatalf("listed %v", got)
	}
	if !reader.call(session, "calendar__read").IsError {
		t.Fatal("called calendar__read")
	}
	if _, calls := h.backend.state(); len(calls) != 0 {
		t.Fatalf("calls %v", calls)
	}
}

func TestSessionCannotCrossPrincipals(t *testing.T) {
	h := setup(t)
	clients := h.start()
	session := clients["agent"].initialize()
	for _, method := range []string{http.MethodGet, http.MethodDelete, http.MethodPost} {
		if status, body := clients["reader"].send(method, session, nil); status != http.StatusNotFound {
			t.Fatalf("%s on another principal's session: %d %s", method, status, body)
		}
	}
	clients["agent"].request(session, "tools/list", nil)
	// systemd passes no socket outside the principals', so only a request
	// handed in by hand can arrive on one
	if os.Getenv("FENCR_MCP_GATEWAY") != "" {
		return
	}
	handler, err := newGateway(&h.config)
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPost, "/mcp/", strings.NewReader("{}"))
	request = request.WithContext(context.WithValue(request.Context(), http.LocalAddrContextKey, &net.UnixAddr{Name: filepath.Join(h.dir, "unknown"), Net: "unix"}))
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusUnauthorized {
		t.Fatalf("unknown socket: %d", recorder.Code)
	}
}

func TestSessionsPerPrincipalAreCapped(t *testing.T) {
	h := setup(t)
	clients := h.start()
	var sessions []string
	for range maxSessions {
		sessions = append(sessions, clients["agent"].initialize())
	}
	if status, body := clients["agent"].send(http.MethodPost, "", map[string]any{}); status != http.StatusTooManyRequests {
		t.Fatalf("past the cap: %d %s", status, body)
	}
	// the cap is the principal's own; another one still opens
	clients["reader"].initialize()
	for _, method := range []string{http.MethodGet, http.MethodDelete, http.MethodPut} {
		if status, body := clients["reader"].send(method, "", nil); status != http.StatusBadRequest {
			t.Fatalf("%s without a session: %d %s", method, status, body)
		}
	}
	// a session closed with DELETE gives its slot back
	if status, body := clients["agent"].send(http.MethodDelete, sessions[0], nil); status/100 != 2 {
		t.Fatalf("DELETE: %d %s", status, body)
	}
	clients["agent"].initialize()
}

func TestSharedPrincipalSocketRefused(t *testing.T) {
	h := setup(t)
	h.config.Principals["reader"].Socket = h.config.Principals["agent"].Socket
	exited, status := h.launch(h.config.Principals["agent"].Socket)
	select {
	case <-exited:
		if status() == nil {
			t.Fatal("the gateway exited cleanly")
		}
	case <-time.After(30 * time.Second):
		t.Fatal("the gateway started with a shared socket")
	}
}

func TestRealBackendTransportKeepsTokenHostSide(t *testing.T) {
	h := setup(t)
	clients := h.start()
	agent := clients["agent"].initialize()
	if got := clients["agent"].call(agent, "calendar__read").Content; len(got) != 1 || got[0].Text != "done" {
		t.Fatalf("content %v", got)
	}
	h.backend.mu.Lock()
	defer h.backend.mu.Unlock()
	if len(h.backend.tokens) != 1 || !h.backend.tokens["Bearer "+token] {
		t.Fatalf("authorization headers %v", h.backend.tokens)
	}
}

// systemd hands each accepted connection to a fresh backend process as its
// stdin and stdout; a goroutine per connection stands in for that process
func TestSocketTransportSpeaksStdioOneConnectionPerSession(t *testing.T) {
	h := setup(t)
	path := filepath.Join(h.dir, "backend.sock")
	listener, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { listener.Close() })
	var mu sync.Mutex
	connections := 0
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			mu.Lock()
			connections++
			index := connections
			mu.Unlock()
			go stdioBackend(conn, index)
		}
	}()
	h.config.Servers = map[string]*server{"local": {Socket: path, HiddenTools: []string{}}}
	h.config.Principals["agent"].Allow = []string{"local.*"}
	h.config.Principals["reader"].Allow = []string{"local.*"}
	clients := h.start()
	for _, step := range []struct{ principal, expected string }{
		{"agent", "connection 1"},
		{"reader", "connection 2"},
		{"agent", "connection 1"},
	} {
		c := clients[step.principal]
		session := c.initialize()
		if got := c.call(session, "local__read").Content; len(got) != 1 || got[0].Text != step.expected {
			t.Fatalf("%s: content %v, want %s", step.principal, got, step.expected)
		}
	}
	mu.Lock()
	defer mu.Unlock()
	if connections != 2 {
		t.Fatalf("connections %d", connections)
	}
}

func stdioBackend(conn net.Conn, index int) {
	defer conn.Close()
	lines := bufio.NewScanner(conn)
	for lines.Scan() {
		var request struct {
			ID     json.RawMessage `json:"id"`
			Method string          `json:"method"`
		}
		if json.Unmarshal(lines.Bytes(), &request) != nil || request.ID == nil {
			continue
		}
		var out []byte
		var result any
		switch request.Method {
		case "initialize":
			result = initializeResult
		case "tools/list":
			result = map[string]any{"tools": tools("read")}
		default:
			// two messages in one write must still arrive as two
			notification, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "method": "notifications/message",
				"params": map[string]any{"level": "info", "data": "x"}})
			out = append(notification, '\n')
			result = map[string]any{"content": []any{map[string]any{"type": "text", "text": fmt.Sprintf("connection %d", index)}}}
		}
		reply, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": request.ID, "result": result})
		if _, err := conn.Write(append(append(out, reply...), '\n')); err != nil {
			return
		}
	}
}
