package main

import (
	"bytes"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSharedDomainCredentials(t *testing.T) {
	directory := t.TempDir()
	t.Setenv("CREDENTIALS_DIRECTORY", directory)
	for _, name := range []string{"zen", "go"} {
		if err := os.WriteFile(filepath.Join(directory, name), []byte(name+"-secret\n"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "%s %s %s", r.Method, r.RequestURI, r.Header.Get("Authorization"))
	}))
	defer upstream.Close()
	zen := &credential{Name: "zen", Upstream: upstream.URL, Header: "Authorization", Bearer: true, Allow: []rule{{Path: "/zen/v1/*"}}}
	goProvider := &credential{Name: "go", Upstream: upstream.URL, Header: "Authorization", Bearer: true, Allow: []rule{{Path: "/zen/go/v1/*"}}}
	for _, candidates := range [][]*credential{{zen, goProvider}, {goProvider, zen}, {zen}, {goProvider}} {
		proxy := handler(map[string][]*credential{"opencode.ai": prepared(t, candidates...)})
		for _, test := range []struct {
			path string
			name string
		}{
			{"/zen/v1/chat/completions?stream=true", "zen"},
			{"/zen/go/v1/chat/completions?stream=true", "go"},
			{"/zen/v1/models/a%2Fb?name=a%2Fb", "zen"},
			{"/zen/go/v1/models", "go"},
			{"/zen/v10/chat/completions", ""},
			{"/zen/go/v10/chat/completions", ""},
			{"/other", ""},
		} {
			request := httptest.NewRequest(http.MethodPost, "https://opencode.ai"+test.path, nil)
			request.Header.Set("Authorization", "Bearer wrong-placeholder")
			response := httptest.NewRecorder()
			proxy.ServeHTTP(response, request)
			wantStatus := http.StatusForbidden
			for _, candidate := range candidates {
				if candidate.Name == test.name {
					wantStatus = http.StatusOK
				}
			}
			if response.Code != wantStatus {
				t.Fatalf("%s: got status %d, want %d", test.path, response.Code, wantStatus)
			}
			if wantStatus == http.StatusOK {
				want := "POST " + test.path + " Bearer " + test.name + "-secret"
				if got := response.Body.String(); got != want {
					t.Errorf("got %q, want %q", got, want)
				}
			}
		}
	}
}

func TestAmbiguousCredentialsAreRefused(t *testing.T) {
	directory := t.TempDir()
	t.Setenv("CREDENTIALS_DIRECTORY", directory)
	for _, name := range []string{"first", "second"} {
		if err := os.WriteFile(filepath.Join(directory, name), []byte(name), 0600); err != nil {
			t.Fatal(err)
		}
	}
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("ambiguous request reached upstream")
	}))
	defer upstream.Close()
	for _, candidates := range [][]*credential{
		{{Name: "first", Upstream: upstream.URL}, {Name: "second", Upstream: upstream.URL}},
		{{Name: "first", Upstream: upstream.URL, Allow: []rule{{Path: "/zen/*"}}}, {Name: "second", Upstream: upstream.URL, Allow: []rule{{Path: "/zen/go/v1/*"}}}},
	} {
		response := httptest.NewRecorder()
		handler(map[string][]*credential{"opencode.ai": prepared(t, candidates...)}).ServeHTTP(response,
			httptest.NewRequest(http.MethodGet, "https://opencode.ai/zen/go/v1/models", nil))
		if response.Code != http.StatusForbidden {
			t.Fatalf("got status %d, want 403", response.Code)
		}
	}
}

// run() prepares every credential before serving: the value systemd
// delivered, the parsed upstream and the compiled allow patterns
func prepared(t *testing.T, credentials ...*credential) []*credential {
	t.Helper()
	for _, c := range credentials {
		if err := prepare(c); err != nil {
			t.Fatal(err)
		}
	}
	return credentials
}

func TestCredentialHeaderFormatting(t *testing.T) {
	directory := t.TempDir()
	t.Setenv("CREDENTIALS_DIRECTORY", directory)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, r.Header.Get("Authorization")+r.Header.Get("x-api-key"))
	}))
	defer upstream.Close()
	for _, test := range []struct {
		name, header, value, want string
		bearer                    bool
	}{
		{"bare key", "Authorization", "api-key\n", "Bearer api-key", true},
		{"legacy prefix", "Authorization", "Bearer api-key\r\n", "Bearer api-key", true},
		{"case insensitive prefix", "Authorization", "bearer api-key", "bearer api-key", true},
		{"anthropic", "x-api-key", "api-key\n", "api-key", false},
		{"custom authorization", "Authorization", "Basic custom", "Basic custom", false},
		{"custom header", "x-api-key", "custom", "custom", false},
	} {
		t.Run(test.name, func(t *testing.T) {
			if err := os.WriteFile(filepath.Join(directory, "key"), []byte(test.value), 0600); err != nil {
				t.Fatal(err)
			}
			proxy := handler(map[string][]*credential{"api.test": prepared(t,
				&credential{Name: "key", Upstream: upstream.URL, Header: test.header, Bearer: test.bearer})})
			response := httptest.NewRecorder()
			proxy.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "https://api.test/v1/models", nil))
			if response.Code != http.StatusOK || response.Body.String() != test.want {
				t.Fatalf("got %d %q, want 200 %q", response.Code, response.Body.String(), test.want)
			}
		})
	}
}

// the placeholder rides in the uri, and the journal is the one place the
// substituted value must not land
func TestTheAccessLogCarriesThePlaceholder(t *testing.T) {
	directory := t.TempDir()
	t.Setenv("CREDENTIALS_DIRECTORY", directory)
	if err := os.WriteFile(filepath.Join(directory, "key"), []byte("api-secret"), 0600); err != nil {
		t.Fatal(err)
	}
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer upstream.Close()
	var logged bytes.Buffer
	previous := log.Writer()
	log.SetOutput(&logged)
	defer log.SetOutput(previous)
	proxy := handler(map[string][]*credential{"api.test": prepared(t,
		&credential{Name: "key", Upstream: upstream.URL, Header: "Authorization", Placeholder: "fencr-placeholder"})})
	proxy.ServeHTTP(httptest.NewRecorder(),
		httptest.NewRequest(http.MethodGet, "https://api.test/v1/models/fencr-placeholder?key=fencr-placeholder", nil))
	if strings.Contains(logged.String(), "api-secret") {
		t.Fatalf("the credential reached the journal: %s", logged.String())
	}
	if !strings.Contains(logged.String(), "/v1/models/fencr-placeholder?key=fencr-placeholder") {
		t.Fatalf("the request the guest sent is not on record: %s", logged.String())
	}
}

// the path is judged as sent and forwarded as sent, so a dot segment is
// the one way a request could match an allow entry and land outside it
func TestDotSegmentsNeverReachTheUpstream(t *testing.T) {
	directory := t.TempDir()
	t.Setenv("CREDENTIALS_DIRECTORY", directory)
	if err := os.WriteFile(filepath.Join(directory, "go"), []byte("go-secret"), 0600); err != nil {
		t.Fatal(err)
	}
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("%s reached upstream", r.RequestURI)
	}))
	defer upstream.Close()
	proxy := handler(map[string][]*credential{"opencode.ai": prepared(t,
		&credential{Name: "go", Upstream: upstream.URL, Header: "Authorization", Allow: []rule{{Path: "/zen/go/v1/*"}}})})
	for _, path := range []string{
		"/zen/go/v1/../../v1/chat",
		"/zen/go/v1/%2e%2e/%2e%2e/v1/chat",
		"/zen/go/v1/./models",
	} {
		response := httptest.NewRecorder()
		proxy.ServeHTTP(response, httptest.NewRequest(http.MethodPost, "https://opencode.ai"+path, nil))
		if response.Code != http.StatusForbidden {
			t.Errorf("%s: got status %d, want 403", path, response.Code)
		}
	}
}

// an upstream that echoes the value hands it back compressed if the guest
// asks for that, and the scrub reads bytes; so the guest's ask is dropped
func TestTheScrubSeesAnEchoInTheClear(t *testing.T) {
	directory := t.TempDir()
	t.Setenv("CREDENTIALS_DIRECTORY", directory)
	if err := os.WriteFile(filepath.Join(directory, "key"), []byte("api-secret"), 0600); err != nil {
		t.Fatal(err)
	}
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if encoding := r.Header.Get("Accept-Encoding"); encoding != "" {
			t.Errorf("the upstream was asked for %q", encoding)
		}
		echo := "bad token " + r.Header.Get("Authorization")
		w.Header().Set("Content-Length", fmt.Sprint(len(echo)))
		io.WriteString(w, echo)
	}))
	defer upstream.Close()
	proxy := handler(map[string][]*credential{"api.test": prepared(t,
		&credential{Name: "key", Upstream: upstream.URL, Header: "Authorization", Placeholder: "fencr-placeholder"})})
	request := httptest.NewRequest(http.MethodGet, "https://api.test/v1/models", nil)
	request.Header.Set("Accept-Encoding", "gzip")
	response := httptest.NewRecorder()
	proxy.ServeHTTP(response, request)
	if response.Code != http.StatusOK || response.Body.String() != "bad token fencr-placeholder" {
		t.Fatalf("got %d %q", response.Code, response.Body.String())
	}
}

func TestSingleCredentialStillAllowsEveryPath(t *testing.T) {
	directory := t.TempDir()
	t.Setenv("CREDENTIALS_DIRECTORY", directory)
	if err := os.WriteFile(filepath.Join(directory, "legacy"), []byte("legacy-secret"), 0600); err != nil {
		t.Fatal(err)
	}
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, r.Header.Get("x-api-key"))
	}))
	defer upstream.Close()
	proxy := handler(map[string][]*credential{"api.test": prepared(t,
		&credential{Name: "legacy", Upstream: upstream.URL, Header: "x-api-key"})})
	response := httptest.NewRecorder()
	proxy.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "https://api.test/any/path", nil))
	if response.Code != http.StatusOK || response.Body.String() != "legacy-secret" {
		t.Fatalf("got %d %q", response.Code, response.Body.String())
	}
}
