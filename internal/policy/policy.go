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
// Domain matching is exact (case-insensitive). Wildcards are not supported.
type Engine struct {
	mode      Mode
	domains   map[string]struct{}
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
		domains:   make(map[string]struct{}),
		allowedIP: make(map[string]struct{}),
	}
	for _, entry := range cfg.Allowlist {
		entry = strings.TrimSpace(entry)
		if ip := net.ParseIP(entry); ip != nil {
			e.allowedIP[ip.String()] = struct{}{} // canonicalize to prevent representation mismatches
		} else {
			e.domains[strings.ToLower(entry)] = struct{}{}
		}
	}
	return e, nil
}

// Mode returns the configured enforcement mode.
func (e *Engine) Mode() Mode { return e.mode }

// Allow reports whether the given domain and IP are permitted by the policy.
// Domain matching is exact and case-insensitive; wildcards are not supported.
// domain may be empty if DNS resolution has not occurred yet; in that case
// only the IP is checked.
func (e *Engine) Allow(domain string, ip net.IP) bool {
	if ip != nil {
		if _, ok := e.allowedIP[ip.String()]; ok {
			return true
		}
	}
	if domain != "" {
		if _, ok := e.domains[strings.ToLower(domain)]; ok {
			return true
		}
	}
	return false
}
