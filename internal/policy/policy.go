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
	Mode      Mode     `yaml:"mode"`
	Allowlist []string `yaml:"allowlist"`
}

// Engine evaluates outbound connections against a policy.
type Engine struct {
	mode      Mode
	domains   []string // wildcard-aware domain patterns
	allowedIP map[string]struct{}
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
	default:
		return nil, fmt.Errorf("invalid mode %q: must be %q or %q", cfg.Mode, ModeAudit, ModeBlock)
	}

	e := &Engine{
		mode:      cfg.Mode,
		allowedIP: make(map[string]struct{}),
	}
	for _, entry := range cfg.Allowlist {
		entry = strings.TrimSpace(entry)
		if ip := net.ParseIP(entry); ip != nil {
			e.allowedIP[ip.String()] = struct{}{} // canonicalize to prevent representation mismatches
		} else {
			e.domains = append(e.domains, entry)
		}
	}
	return e, nil
}

// Mode returns the configured enforcement mode.
func (e *Engine) Mode() Mode { return e.mode }

// Allow reports whether the given domain and IP are permitted by the policy.
// domain may be empty if DNS resolution has not occurred yet; in that case
// only the IP is checked.
func (e *Engine) Allow(domain string, ip net.IP) bool {
	if ip != nil {
		if _, ok := e.allowedIP[ip.String()]; ok {
			return true
		}
	}
	if domain != "" {
		for _, pattern := range e.domains {
			if matchDomain(pattern, domain) {
				return true
			}
		}
	}
	return false
}

// matchDomain reports whether domain matches pattern.
// A leading "*." wildcard matches exactly one subdomain label.
// Example: "*.github.com" matches "api.github.com" but not "github.com"
// and not "sub.api.github.com".
func matchDomain(pattern, domain string) bool {
	if !strings.HasPrefix(pattern, "*.") {
		return strings.EqualFold(pattern, domain)
	}
	base := strings.ToLower(pattern[2:]) // "github.com"
	d := strings.ToLower(domain)
	suffix := "." + base
	if !strings.HasSuffix(d, suffix) {
		return false
	}
	label := d[:len(d)-len(suffix)]
	return len(label) > 0 && !strings.Contains(label, ".")
}
