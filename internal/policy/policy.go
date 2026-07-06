package policy

import (
	"fmt"
	"net"
	"os"
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
// Domain matching is exact (case-insensitive). Wildcards are not supported.
// CIDR ranges are supported for IPv4 ("10.0.0.0/8") and IPv6
// ("2001:db8::/32") subnets.
type Engine struct {
	mode        Mode
	domains     map[string]struct{}
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
	if err := yaml.Unmarshal(data, &cfg); err != nil {
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
		if strings.Contains(entry, "*") {
			// Matching is exact, so a wildcard entry would be stored as a
			// literal name that never matches — in block mode that silently
			// denies everything the user meant to allow. Fail fast instead.
			return nil, fmt.Errorf("wildcard allowlist entries are not supported: %q (list each subdomain explicitly)", entry)
		}
		if ip := net.ParseIP(entry); ip != nil {
			e.allowedIP[ip.String()] = ip // canonicalize to prevent representation mismatches
		} else {
			// Strip an optional port suffix (e.g. "kayac.com:443" → "kayac.com",
			// "203.0.113.10:443" → "203.0.113.10"). Ports are not part of DNS
			// names and field-cage does not enforce per-port policy.
			host := entry
			if h, _, err := net.SplitHostPort(entry); err == nil {
				host = h
			}
			if host == "" {
				// Malformed entry (e.g. ":443") — skip silently.
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

// Domains returns the allowlisted domain names (lowercased). Used to seed the
// enforcement map at startup by resolving each domain to its IP addresses.
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
		ips = append(ips, ip)
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

// IsAllowedDomain reports whether the given domain is on the allowlist.
// Matching is exact and case-insensitive; wildcards are not supported.
func (e *Engine) IsAllowedDomain(domain string) bool {
	if domain == "" {
		return false
	}
	_, ok := e.domains[strings.ToLower(domain)]
	return ok
}

// Allow reports whether the given domain and IP are permitted by the policy.
// Domain matching is exact and case-insensitive; wildcards are not supported.
// CIDR containment is checked for both IPv4 and IPv6 addresses.
// domain may be empty if DNS resolution has not occurred yet; in that case
// only the IP is checked.
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
		if _, ok := e.domains[strings.ToLower(domain)]; ok {
			return true
		}
	}
	return false
}
