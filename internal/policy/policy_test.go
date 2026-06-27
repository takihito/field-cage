package policy

import (
	"net"
	"os"
	"path/filepath"
	"strings"
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

func TestDomainWithPortStripped(t *testing.T) {
	// Allowlist entries like "kayac.com:443" must be normalised to "kayac.com".
	// Ports are not part of DNS names; keeping them broke seed resolution and
	// domain matching (IsAllowedDomain("kayac.com") returned false).
	cfg := Config{
		Mode:      ModeBlock,
		Allowlist: []string{"kayac.com:443", "api.github.com:443"},
	}
	e, err := newEngine(cfg)
	if err != nil {
		t.Fatal(err)
	}

	// IsAllowedDomain must match without the port.
	if !e.IsAllowedDomain("kayac.com") {
		t.Error("IsAllowedDomain(kayac.com) = false, want true")
	}
	if !e.IsAllowedDomain("api.github.com") {
		t.Error("IsAllowedDomain(api.github.com) = false, want true")
	}

	// Domains() must return plain hostnames so seed resolution succeeds.
	for _, d := range e.Domains() {
		if strings.Contains(d, ":") {
			t.Errorf("Domains() returned %q — port was not stripped", d)
		}
	}
}

func TestInvalidMode(t *testing.T) {
	_, err := newEngine(Config{Mode: "invalid"})
	if err == nil {
		t.Error("expected error for invalid mode")
	}
}

func TestDomainsAndIPs(t *testing.T) {
	cfg := Config{
		Mode:      ModeBlock,
		Allowlist: []string{"GitHub.com", "api.github.com", "1.2.3.4", "5.6.7.8"},
	}
	e, err := newEngine(cfg)
	if err != nil {
		t.Fatal(err)
	}

	domains := e.Domains()
	wantDomains := map[string]bool{"github.com": true, "api.github.com": true}
	if len(domains) != len(wantDomains) {
		t.Errorf("Domains() returned %d entries, want %d: %v", len(domains), len(wantDomains), domains)
	}
	for _, d := range domains {
		if !wantDomains[d] {
			t.Errorf("unexpected domain %q (should be lowercased and IP-free)", d)
		}
	}

	ips := e.IPs()
	wantIPs := map[string]bool{"1.2.3.4": true, "5.6.7.8": true}
	if len(ips) != len(wantIPs) {
		t.Errorf("IPs() returned %d entries, want %d: %v", len(ips), len(wantIPs), ips)
	}
	for _, ip := range ips {
		if !wantIPs[ip.String()] {
			t.Errorf("unexpected IP %q", ip)
		}
	}
}

func TestIsAllowedDomain(t *testing.T) {
	e, err := newEngine(Config{Mode: ModeBlock, Allowlist: []string{"github.com", "1.2.3.4"}})
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		domain string
		want   bool
	}{
		{"github.com", true},
		{"GITHUB.COM", true}, // case-insensitive
		{"api.github.com", false},
		{"", false},
		{"1.2.3.4", false}, // IP entries are not domains
	}
	for _, tc := range cases {
		if got := e.IsAllowedDomain(tc.domain); got != tc.want {
			t.Errorf("IsAllowedDomain(%q) = %v, want %v", tc.domain, got, tc.want)
		}
	}
}
