package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// the shape modules/core/egress.nix renders: a domain grant answers every
// name itself, so resolver is empty and that is not a fault
const rendered = `{"bridge":"10.11.0.1","dnsPort":33053,"tlsPort":33443,"resolver":"",` +
	`"domains":["allowed.test"],"denied":[],"credentials":[{"name":"api","domain":"api.test",` +
	`"upstream":"http://127.0.0.1:8765","header":"Authorization","bearer":true,"placeholder":"",` +
	`"allow":[{"methods":["GET"],"path":"/"}]}]}`

func write(t *testing.T, text string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "fencr-egress.json")
	if err := os.WriteFile(path, []byte(text), 0600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestTheRenderedConfigLoads(t *testing.T) {
	cfg, err := load(write(t, rendered))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Bridge != "10.11.0.1" || cfg.DNSPort != 33053 || cfg.Resolver != "" || len(cfg.Credentials) != 1 {
		t.Fatalf("got %+v", cfg)
	}
}

func TestADriftedConfigIsRefused(t *testing.T) {
	for _, test := range []struct {
		name, text, reason string
	}{
		{"renamed field", strings.Replace(rendered, `"resolver"`, `"stub"`, 1), "unknown field"},
		{"no bridge", strings.Replace(rendered, `"10.11.0.1"`, `""`, 1), "is not an address"},
		{"port zero", strings.Replace(rendered, `33053`, `0`, 1), "is not a port"},
		{"credential without a header", strings.Replace(rendered, `"Authorization"`, `""`, 1), "has no header"},
		{"two configurations", rendered + rendered, "more than one configuration"},
	} {
		t.Run(test.name, func(t *testing.T) {
			_, err := load(write(t, test.text))
			if err == nil || !strings.Contains(err.Error(), test.reason) {
				t.Fatalf("got %v, want %s", err, test.reason)
			}
		})
	}
}
