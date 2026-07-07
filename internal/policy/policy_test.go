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
	// unlisted subdomains do not match (exact matching, no wildcards)
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
	// "203.0.113.10:443" must be normalised to an IP entry, not a domain entry.
	cfg := Config{
		Mode:      ModeBlock,
		Allowlist: []string{"kayac.com:443", "api.github.com:443", "203.0.113.10:443"},
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

	// IP with port must end up in allowedIP, not domains.
	if !e.Allow("", net.ParseIP("203.0.113.10")) {
		t.Error("Allow(\"\", 203.0.113.10) = false, want true (IP with port not in allowedIP)")
	}
	if e.IsAllowedDomain("203.0.113.10") {
		t.Error("IsAllowedDomain(203.0.113.10) = true, want false (IP must not be stored as domain)")
	}

	// Domains() must return plain hostnames so seed resolution succeeds.
	for _, d := range e.Domains() {
		if strings.Contains(d, ":") {
			t.Errorf("Domains() returned %q — port was not stripped", d)
		}
	}
}

func TestMalformedPortOnlyEntry(t *testing.T) {
	// ":443" splits to host="" via SplitHostPort; the empty host must be
	// silently skipped rather than stored as e.domains[""].
	cfg := Config{
		Mode:      ModeBlock,
		Allowlist: []string{":443", "github.com"},
	}
	e, err := newEngine(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if e.IsAllowedDomain("") {
		t.Error("IsAllowedDomain(\"\") = true, want false (empty host must not be stored)")
	}
	// Only "github.com" should be in domains; ":443" must have been dropped.
	if got := len(e.Domains()); got != 1 {
		t.Errorf("Domains() len = %d, want 1; got %v", got, e.Domains())
	}
}

func TestAllowAllDNSDefault(t *testing.T) {
	// allow_all_dns defaults to false when unset.
	e, err := newEngine(Config{Mode: ModeBlock, Allowlist: []string{"github.com"}})
	if err != nil {
		t.Fatal(err)
	}
	if e.AllowAllDNS() {
		t.Error("AllowAllDNS() = true, want false by default")
	}
}

func TestAllowAllDNSEnabled(t *testing.T) {
	e, err := newEngine(Config{Mode: ModeBlock, Allowlist: []string{"github.com"}, AllowAllDNS: true})
	if err != nil {
		t.Fatal(err)
	}
	if !e.AllowAllDNS() {
		t.Error("AllowAllDNS() = false, want true when configured")
	}
}

func TestAllowAllDNSFromYAML(t *testing.T) {
	yaml := `
mode: block
allow_all_dns: true
allowlist:
  - github.com
`
	f := filepath.Join(t.TempDir(), "policy.yml")
	if err := os.WriteFile(f, []byte(yaml), 0o600); err != nil {
		t.Fatal(err)
	}
	e, err := LoadFile(f)
	if err != nil {
		t.Fatal(err)
	}
	if !e.AllowAllDNS() {
		t.Error("AllowAllDNS() = false, want true (allow_all_dns: true in YAML)")
	}
}

func TestCIDRAllowlist(t *testing.T) {
	cfg := Config{
		Mode: ModeBlock,
		Allowlist: []string{
			"10.0.0.0/8",         // private range
			"203.0.113.0/24",     // TEST-NET-3 (RFC 5737)
			"192.168.100.0/24",   // private /24
		},
	}
	e, err := newEngine(cfg)
	if err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		ip   string
		want bool
	}{
		// inside 10.0.0.0/8
		{"10.0.0.1", true},
		{"10.255.255.255", true},
		// outside
		{"11.0.0.1", false},
		{"9.255.255.255", false},
		// inside 203.0.113.0/24
		{"203.0.113.0", true},
		{"203.0.113.255", true},
		// outside /24
		{"203.0.114.0", false},
		// inside 192.168.100.0/24
		{"192.168.100.50", true},
		{"192.168.101.1", false},
	}
	for _, tc := range cases {
		ip := net.ParseIP(tc.ip)
		if ip == nil {
			t.Fatalf("bad test IP %q", tc.ip)
		}
		if got := e.Allow("", ip); got != tc.want {
			t.Errorf("Allow(\"\", %q) = %v, want %v", tc.ip, got, tc.want)
		}
	}

	// CIDRs() must return all three parsed networks
	if got := len(e.CIDRs()); got != 3 {
		t.Errorf("CIDRs() len = %d, want 3", got)
	}

	// CIDR entries must not appear as plain domains or IPs
	if e.IsAllowedDomain("10.0.0.0/8") {
		t.Error("CIDR must not be stored as a domain")
	}
}

func TestIPv6CIDRAllowlist(t *testing.T) {
	// IPv6 CIDRs are supported: containment is checked in Allow() and the
	// entry must not leak into the domain store.
	cfg := Config{
		Mode:      ModeBlock,
		Allowlist: []string{"2001:db8::/32", "github.com"},
	}
	e, err := newEngine(cfg)
	if err != nil {
		t.Fatal(err)
	}
	// IPv6 CIDR must not appear in domains
	if e.IsAllowedDomain("2001:db8::/32") {
		t.Error("IPv6 CIDR must not be stored as a domain name")
	}
	if got := len(e.CIDRs()); got != 1 {
		t.Errorf("CIDRs() len = %d, want 1", got)
	}
	if got := len(e.Domains()); got != 1 {
		t.Errorf("Domains() len = %d, want 1; got %v", got, e.Domains())
	}

	cases := []struct {
		ip   string
		want bool
	}{
		{"2001:db8::1", true},                // inside /32
		{"2001:db8:ffff::42", true},          // still inside /32
		{"2001:db9::1", false},               // outside
		{"2606:4700:4700::1111", false},      // unrelated IPv6
		{"192.0.2.1", false},                 // IPv4 does not match an IPv6 CIDR
	}
	for _, tc := range cases {
		ip := net.ParseIP(tc.ip)
		if ip == nil {
			t.Fatalf("bad test IP %q", tc.ip)
		}
		if got := e.Allow("", ip); got != tc.want {
			t.Errorf("Allow(\"\", %q) = %v, want %v", tc.ip, got, tc.want)
		}
	}
}

func TestIPv6SingleIPAllowlist(t *testing.T) {
	// Single IPv6 addresses, with and without a bracketed port.
	cfg := Config{
		Mode:      ModeBlock,
		Allowlist: []string{"2001:db8::1", "[2001:db8::2]:443"},
	}
	e, err := newEngine(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if !e.Allow("", net.ParseIP("2001:db8::1")) {
		t.Error("2001:db8::1 must be allowed")
	}
	if !e.Allow("", net.ParseIP("2001:db8::2")) {
		t.Error("2001:db8::2 (from bracketed host:port) must be allowed")
	}
	if e.Allow("", net.ParseIP("2001:db8::3")) {
		t.Error("2001:db8::3 must be denied")
	}
	// IPs() must include both for seeding.
	if got := len(e.IPs()); got != 2 {
		t.Errorf("IPs() len = %d, want 2", got)
	}
}

func TestCIDRDoesNotMatchDomain(t *testing.T) {
	// A domain alongside a CIDR: the domain must still be required for domain
	// matching; an IP outside the CIDR must not sneak through via domain.
	cfg := Config{
		Mode:      ModeBlock,
		Allowlist: []string{"10.0.0.0/8", "github.com"},
	}
	e, err := newEngine(cfg)
	if err != nil {
		t.Fatal(err)
	}
	// IP in CIDR → allow regardless of domain
	if !e.Allow("evil.com", net.ParseIP("10.1.2.3")) {
		t.Error("IP inside CIDR must be allowed even with an unlisted domain")
	}
	// IP outside CIDR, matching domain → allow via domain
	if !e.Allow("github.com", net.ParseIP("140.82.121.4")) {
		t.Error("listed domain must be allowed even if IP is outside CIDR")
	}
	// IP outside CIDR, unlisted domain → deny
	if e.Allow("evil.com", net.ParseIP("11.0.0.1")) {
		t.Error("IP outside CIDR with unlisted domain must be denied")
	}
}

func TestInvalidMode(t *testing.T) {
	_, err := newEngine(Config{Mode: "invalid"})
	if err == nil {
		t.Error("expected error for invalid mode")
	}
}

func TestModeUnspecified(t *testing.T) {
	// A policy file may omit mode entirely; the effective mode is resolved by
	// the caller (--mode flag, or audit default). Loading must not fail.
	e, err := newEngine(Config{Allowlist: []string{"github.com"}})
	if err != nil {
		t.Fatalf("unexpected error for unspecified mode: %v", err)
	}
	if e.Mode() != "" {
		t.Errorf("Mode() = %q, want empty (unspecified)", e.Mode())
	}
}

func TestWildcardEntryRejected(t *testing.T) {
	// Matching is exact, so a wildcard entry would silently never match —
	// dangerous in block mode. Loading must fail fast instead.
	for _, entry := range []string{"*.github.com", "api.*.com", "*"} {
		_, err := newEngine(Config{Mode: ModeBlock, Allowlist: []string{entry}})
		if err == nil {
			t.Errorf("newEngine with wildcard entry %q: expected error, got nil", entry)
		}
	}
}

func TestUnknownKeyRejected(t *testing.T) {
	// mode is optional, so a misspelled key would silently leave it unset and
	// run audit where block was intended. Strict decoding must fail instead.
	cases := []string{
		"mdoe: block\nallowlist:\n  - github.com\n",  // misspelled mode
		"mode: block\nallowlists:\n  - github.com\n", // misspelled allowlist
	}
	for _, yaml := range cases {
		f := filepath.Join(t.TempDir(), "policy.yml")
		if err := os.WriteFile(f, []byte(yaml), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := LoadFile(f); err == nil {
			t.Errorf("LoadFile with unknown key: expected error, got nil\npolicy:\n%s", yaml)
		}
	}
}

func TestEmptyPolicyFile(t *testing.T) {
	// An empty file is a valid (empty) policy: mode unspecified, no allowlist.
	f := filepath.Join(t.TempDir(), "policy.yml")
	if err := os.WriteFile(f, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	e, err := LoadFile(f)
	if err != nil {
		t.Fatalf("LoadFile with empty file: unexpected error: %v", err)
	}
	if e.Mode() != "" {
		t.Errorf("Mode() = %q, want empty (unspecified)", e.Mode())
	}
}

func TestIPsReturnsDefensiveCopies(t *testing.T) {
	// net.IP is a mutable byte slice; mutating a returned value must not
	// corrupt the engine's stored IPs.
	e, err := newEngine(Config{Mode: ModeBlock, Allowlist: []string{"1.2.3.4"}})
	if err != nil {
		t.Fatal(err)
	}
	ips := e.IPs()
	if len(ips) != 1 {
		t.Fatalf("IPs() len = %d, want 1", len(ips))
	}
	for i := range ips[0] {
		ips[0][i] = 0xff // clobber the returned copy
	}
	if !e.Allow("", net.ParseIP("1.2.3.4")) {
		t.Error("Allow(1.2.3.4) = false after mutating IPs() result — engine state was corrupted")
	}
	if got := e.IPs()[0].String(); got != "1.2.3.4" {
		t.Errorf("IPs()[0] = %q after mutating a previous result, want 1.2.3.4", got)
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
