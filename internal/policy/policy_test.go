package policy

import (
	"net"
	"os"
	"path/filepath"
	"testing"
)

func TestEngineAllowDomain(t *testing.T) {
	cfg := Config{
		Mode:      ModeAudit,
		Allowlist: []string{"github.com", "api.github.com", "registry.npmjs.org", "1.2.3.4"},
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
		// exact domain matches
		{"github.com", "140.82.121.4", true},
		{"api.github.com", "140.82.121.5", true},
		{"registry.npmjs.org", "104.16.1.1", true},
		// subdomains are NOT matched (no wildcard support)
		{"sub.github.com", "140.82.121.6", false},
		{"other.npmjs.org", "104.16.1.2", false},
		// IP explicitly allowed regardless of domain
		{"evil.com", "1.2.3.4", true},
		{"evil.com", "9.9.9.9", false},
		// case-insensitive domain match
		{"GITHUB.COM", "140.82.121.4", true},
		// no domain, IP only
		{"", "1.2.3.4", true},
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
  - codeload.github.com
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
	if !e.Allow("codeload.github.com", net.ParseIP("185.199.108.1")) {
		t.Error("expected codeload.github.com to be allowed")
	}
	// wildcard-style entries are treated as literal domain names and won't match
	if e.Allow("api.github.com", net.ParseIP("140.82.121.5")) {
		t.Error("expected api.github.com to be denied (not in allowlist)")
	}
	if e.Allow("evil.com", net.ParseIP("1.2.3.4")) {
		t.Error("expected evil.com to be denied")
	}
}

func TestIPCanonicalization(t *testing.T) {
	cfg := Config{
		Mode:      ModeAudit,
		Allowlist: []string{"  1.2.3.4  "}, // leading/trailing whitespace
	}
	e, err := newEngine(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if !e.Allow("", net.ParseIP("1.2.3.4")) {
		t.Error("expected 1.2.3.4 to be allowed after whitespace trim")
	}
}

func TestInvalidMode(t *testing.T) {
	_, err := newEngine(Config{Mode: "invalid"})
	if err == nil {
		t.Error("expected error for invalid mode")
	}
}
