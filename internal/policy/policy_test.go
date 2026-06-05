package policy

import (
	"net"
	"os"
	"path/filepath"
	"testing"
)

func TestMatchDomain(t *testing.T) {
	cases := []struct {
		pattern string
		domain  string
		want    bool
	}{
		{"github.com", "github.com", true},
		{"github.com", "api.github.com", false},
		{"*.github.com", "api.github.com", true},
		{"*.github.com", "github.com", false},
		{"*.github.com", "sub.api.github.com", false},
		{"*.npmjs.org", "registry.npmjs.org", true},
		{"*.npmjs.org", "npmjs.org", false},
		{"example.com", "EXAMPLE.COM", true},
	}
	for _, tc := range cases {
		got := matchDomain(tc.pattern, tc.domain)
		if got != tc.want {
			t.Errorf("matchDomain(%q, %q) = %v, want %v", tc.pattern, tc.domain, got, tc.want)
		}
	}
}

func TestEngineAllow(t *testing.T) {
	cfg := Config{
		Mode:      ModeAudit,
		Allowlist: []string{"github.com", "*.npmjs.org", "1.2.3.4"},
	}
	e, err := newEngine(cfg)
	if err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		domain string
		ip     string
		want   bool
	}{
		{"github.com", "140.82.121.4", true},
		{"api.github.com", "140.82.121.5", false},
		{"registry.npmjs.org", "104.16.1.1", true},
		{"npmjs.org", "104.16.1.2", false},
		{"evil.com", "1.2.3.4", true}, // IP explicitly allowed
		{"evil.com", "9.9.9.9", false},
		{"", "1.2.3.4", true}, // no domain, IP allowed
		{"", "9.9.9.9", false},
	}
	for _, tc := range cases {
		ip := net.ParseIP(tc.ip)
		got := e.Allow(tc.domain, ip)
		if got != tc.want {
			t.Errorf("Allow(%q, %q) = %v, want %v", tc.domain, tc.ip, got, tc.want)
		}
	}
}

func TestLoadFile(t *testing.T) {
	yaml := `
mode: block
allowlist:
  - github.com
  - "*.actions.githubusercontent.com"
`
	f := filepath.Join(t.TempDir(), "policy.yml")
	if err := os.WriteFile(f, []byte(yaml), 0o600); err != nil {
		t.Fatal(err)
	}

	e, err := LoadFile(f)
	if err != nil {
		t.Fatal(err)
	}
	if e.Mode() != ModeBlock {
		t.Errorf("mode = %q, want %q", e.Mode(), ModeBlock)
	}
	if !e.Allow("github.com", net.ParseIP("140.82.121.4")) {
		t.Error("expected github.com to be allowed")
	}
	if !e.Allow("codeload.actions.githubusercontent.com", net.ParseIP("185.199.108.1")) {
		t.Error("expected *.actions.githubusercontent.com to be allowed")
	}
	if e.Allow("evil.com", net.ParseIP("1.2.3.4")) {
		t.Error("expected evil.com to be denied")
	}
}

func TestInvalidMode(t *testing.T) {
	_, err := newEngine(Config{Mode: "invalid"})
	if err == nil {
		t.Error("expected error for invalid mode")
	}
}
