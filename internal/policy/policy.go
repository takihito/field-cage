package policy

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"slices"
	"strings"

	"gopkg.in/yaml.v3"
)

// Mode controls how policy violations are handled.
type Mode string

const (
	ModeAudit Mode = "audit" // log violations, allow connections
	ModeBlock Mode = "block" // log violations, block connections
)

// Config holds the loaded policy configuration.
type Config struct {
	// Mode may be empty (unspecified): the effective mode is then resolved by
	// the caller — the --mode flag if given, audit otherwise.
	Mode      Mode     `yaml:"mode"`
	Allowlist []string `yaml:"allowlist"`
	// AllowAllDNS opts out of resolver-restricted DNS: when true, any port-53
	// destination is permitted (legacy behavior). Default false, which permits
	// port 53 only to configured resolvers and loopback.
	AllowAllDNS bool `yaml:"allow_all_dns"`
}

// Engine evaluates outbound connections against a policy.
// Domain matching is exact (case-insensitive), except for wildcard entries
// of the form "*.example.com", which match any proper subdomain (but not
// "example.com" itself — list that separately if it must also be allowed).
// A wildcard must anchor at least a second-level domain ("*.example.com" is
// valid; "*.com" is rejected at load time as too broad). This is a simple
// label-count check, not a public-suffix list, so a wildcard like "*.co.jp"
// is accepted even though co.jp is itself a registrable-suffix-like TLD.
// CIDR ranges are supported for IPv4 ("10.0.0.0/8") and IPv6
// ("2001:db8::/32") subnets.
type Engine struct {
	mode        Mode
	domains     map[string]struct{}
	wildcards   []string          // dot-prefixed suffixes, lowercased (e.g. ".example.com" for entry "*.example.com")
	allowedIP   map[string]net.IP // canonical string form → parsed IP
	cidrs       []*net.IPNet
	allowAllDNS bool
}

// LoadFile parses a YAML policy file and returns an Engine.
func LoadFile(path string) (*Engine, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read policy file: %w", err)
	}
	var cfg Config
	// Strict decoding: an unknown key must fail loading. mode is optional, so
	// a misspelled key (e.g. "mdoe: block") would otherwise leave it unset and
	// silently run audit where block was intended — disabling enforcement.
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(&cfg); err != nil && !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("parse policy file: %w", err)
	}
	return newEngine(cfg)
}

func newEngine(cfg Config) (*Engine, error) {
	switch cfg.Mode {
	case ModeAudit, ModeBlock:
	case "": // unspecified: resolved by the caller (--mode flag, or audit default)
	default:
		return nil, fmt.Errorf("invalid mode %q: must be %q or %q", cfg.Mode, ModeAudit, ModeBlock)
	}

	e := &Engine{
		mode:        cfg.Mode,
		domains:     make(map[string]struct{}),
		allowedIP:   make(map[string]net.IP),
		allowAllDNS: cfg.AllowAllDNS,
	}
	for _, entry := range cfg.Allowlist {
		entry = strings.TrimSpace(entry)
		if ip := net.ParseIP(entry); ip != nil {
			e.allowedIP[ip.String()] = ip // canonicalize to prevent representation mismatches
			continue
		}
		// Strip an optional port suffix (e.g. "kayac.com:443" → "kayac.com",
		// "203.0.113.10:443" → "203.0.113.10", "*.example.com:443" →
		// "*.example.com"). Ports are not part of DNS names and field-cage
		// does not enforce per-port policy.
		host := entry
		if h, _, err := net.SplitHostPort(entry); err == nil {
			host = h
		}
		if host == "" {
			// Malformed entry (e.g. ":443") — skip silently.
			continue
		}
		if strings.Contains(host, "*") {
			suffix, ok := strings.CutPrefix(host, "*.")
			if !ok || strings.Contains(suffix, "*") {
				// Only a single leading "*." label is supported. Matching a
				// literal "*" anywhere else would be ambiguous, so reject
				// rather than silently mis-scope the entry.
				return nil, fmt.Errorf("unsupported wildcard allowlist entry %q: only a single leading \"*.\" is supported (e.g. \"*.example.com\")", entry)
			}
			labels := strings.Split(suffix, ".")
			if len(labels) < 2 {
				// "*.com" or "*.jp" would allowlist an entire TLD — refuse
				// anything less specific than a second-level domain.
				return nil, fmt.Errorf("wildcard allowlist entry %q is too broad: must anchor at least a second-level domain (e.g. \"*.example.com\", not a bare TLD)", entry)
			}
			if slices.Contains(labels, "") {
				return nil, fmt.Errorf("wildcard allowlist entry %q has an empty domain label", entry)
			}
			// Store with the leading dot so matching is a single HasSuffix
			// against the full ".example.com" separator — no length check or
			// per-lookup string concatenation needed.
			e.wildcards = append(e.wildcards, "."+strings.ToLower(suffix))
			continue
		}
		// Re-parse: "203.0.113.10:443" strips to an IP and must go to
		// allowedIP, not domains.
		if ip := net.ParseIP(host); ip != nil {
			e.allowedIP[ip.String()] = ip
		} else if _, cidr, err := net.ParseCIDR(host); err == nil {
			// CIDR range, IPv4 (e.g. "10.0.0.0/8") or IPv6 (e.g. "2001:db8::/32").
			// net.ParseCIDR masks the address, so cidr.IP is the network address.
			e.cidrs = append(e.cidrs, cidr)
		} else {
			e.domains[strings.ToLower(host)] = struct{}{}
		}
	}
	return e, nil
}

// Mode returns the configured enforcement mode. It is empty when the policy
// file does not specify one; the caller decides the effective mode then.
func (e *Engine) Mode() Mode { return e.mode }

// AllowAllDNS reports whether port-53 (DNS) connections to any destination are
// permitted. When false (the default), only configured resolvers and loopback
// are allowed on port 53.
func (e *Engine) AllowAllDNS() bool { return e.allowAllDNS }

// Domains returns the exact-match allowlisted domain names (lowercased).
// Wildcard entries are excluded: there is no concrete FQDN to resolve at
// startup for "*.example.com", so they can only be enforced by live DNS
// observation (see IsAllowedDomain), never startup seeding.
// Used to seed the enforcement map at startup by resolving each domain to
// its IP addresses.
func (e *Engine) Domains() []string {
	domains := make([]string, 0, len(e.domains))
	for d := range e.domains {
		domains = append(domains, d)
	}
	return domains
}

// IPs returns the explicitly allowlisted IP addresses (canonicalized). Used to
// seed the enforcement map at startup.
func (e *Engine) IPs() []net.IP {
	ips := make([]net.IP, 0, len(e.allowedIP))
	for _, ip := range e.allowedIP {
		// Defensive copy: net.IP is a mutable byte slice, and handing out the
		// stored ones would let a caller corrupt the engine's state.
		ips = append(ips, append(net.IP(nil), ip...))
	}
	return ips
}

// CIDRs returns the allowlisted CIDR ranges (IPv4 and IPv6). Used to seed
// the enforcement LPM tries at startup.
func (e *Engine) CIDRs() []*net.IPNet {
	out := make([]*net.IPNet, len(e.cidrs))
	copy(out, e.cidrs)
	return out
}

// IsAllowedDomain reports whether the given domain is on the allowlist,
// either as an exact (case-insensitive) match or as a proper subdomain of a
// "*.example.com"-style wildcard entry.
func (e *Engine) IsAllowedDomain(domain string) bool {
	if domain == "" {
		return false
	}
	d := strings.ToLower(domain)
	if _, ok := e.domains[d]; ok {
		return true
	}
	return e.matchesWildcard(d)
}

// matchesWildcard reports whether domain (already lowercased) is a proper
// subdomain of any wildcard suffix. "example.com" itself does not match
// "*.example.com" — it must also be listed exactly if it should be allowed.
func (e *Engine) matchesWildcard(domain string) bool {
	for _, suffix := range e.wildcards {
		if strings.HasSuffix(domain, suffix) {
			return true
		}
	}
	return false
}

// Allow reports whether the given domain and IP are permitted by the policy.
// Domain matching is exact and case-insensitive, or a proper subdomain of a
// wildcard entry (see IsAllowedDomain). CIDR containment is checked for both
// IPv4 and IPv6 addresses. domain may be empty if DNS resolution has not
// occurred yet; in that case only the IP is checked.
func (e *Engine) Allow(domain string, ip net.IP) bool {
	if ip != nil {
		if _, ok := e.allowedIP[ip.String()]; ok {
			return true
		}
		for _, cidr := range e.cidrs {
			if cidr.Contains(ip) {
				return true
			}
		}
	}
	if domain != "" {
		return e.IsAllowedDomain(domain)
	}
	return false
}
