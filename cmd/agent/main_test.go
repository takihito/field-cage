package main

import (
	"net"
	"os"
	"path/filepath"
	"testing"

	"github.com/takihito/field-cage/internal/policy"
	"github.com/takihito/field-cage/internal/report"
)

// allowFunc adapts a function to the report.Allower interface for tests.
type allowFunc func(domain string, ip net.IP) bool

func (f allowFunc) Allow(domain string, ip net.IP) bool { return f(domain, ip) }

// loadEngine writes a minimal policy file and loads it. An empty mode omits
// the mode line entirely (unspecified).
func loadEngine(t *testing.T, mode string) *policy.Engine {
	t.Helper()
	path := filepath.Join(t.TempDir(), "policy.yml")
	data := "allowlist:\n  - example.com\n"
	if mode != "" {
		data = "mode: " + mode + "\n" + data
	}
	if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
		t.Fatal(err)
	}
	engine, err := policy.LoadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return engine
}

func TestResolveMode(t *testing.T) {
	audit := loadEngine(t, "audit")
	block := loadEngine(t, "block")
	unspecified := loadEngine(t, "")

	cases := []struct {
		name     string
		flagMode string
		engine   *policy.Engine
		want     policy.Mode
		wantErr  bool
	}{
		{"default is audit without policy", "", nil, policy.ModeAudit, false},
		{"policy file mode is used", "", block, policy.ModeBlock, false},
		{"flag overrides policy file", "audit", block, policy.ModeAudit, false},
		{"flag escalates to block", "block", audit, policy.ModeBlock, false},
		{"invalid flag mode", "enforce", audit, "", true},
		{"block without policy is refused", "block", nil, "", true},
		{"policy without mode defaults to audit", "", unspecified, policy.ModeAudit, false},
		{"flag sets block on policy without mode", "block", unspecified, policy.ModeBlock, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := resolveMode(tc.flagMode, tc.engine)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("resolveMode(%q) expected error, got mode %q", tc.flagMode, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("resolveMode(%q) unexpected error: %v", tc.flagMode, err)
			}
			if got != tc.want {
				t.Errorf("resolveMode(%q) = %q, want %q", tc.flagMode, got, tc.want)
			}
		})
	}
}

func TestVerdictForEventPrioritizesSelf(t *testing.T) {
	const selfPID = uint32(4242)
	publicIP := net.IPv4(93, 184, 216, 34)

	// Even a destination that would otherwise be denied must classify as
	// SKIP(self) when the event's TGID is the agent's own PID: self-events
	// are never real application traffic, so no other verdict should win.
	denyAll := allowFunc(func(string, net.IP) bool { return false })
	got := verdictForEvent(selfPID, 53, publicIP, "registry.npmjs.org", selfPID, denyAll, nil)
	if got != report.VerdictSkipSelf {
		t.Errorf("verdictForEvent (self, port 53) = %q, want %q", got, report.VerdictSkipSelf)
	}

	got = verdictForEvent(selfPID, 443, publicIP, "evil.example", selfPID, denyAll, nil)
	if got != report.VerdictSkipSelf {
		t.Errorf("verdictForEvent (self, port 443, would-be-denied) = %q, want %q", got, report.VerdictSkipSelf)
	}
}

func TestVerdictForEventFallsThroughForOtherProcesses(t *testing.T) {
	const selfPID = uint32(4242)
	const otherPID = uint32(9999)
	publicIP := net.IPv4(93, 184, 216, 34)

	allowAll := allowFunc(func(string, net.IP) bool { return true })
	got := verdictForEvent(otherPID, 443, publicIP, "example.com", selfPID, allowAll, nil)
	if got != report.VerdictAllow {
		t.Errorf("verdictForEvent (other process) = %q, want %q", got, report.VerdictAllow)
	}

	denyAll := allowFunc(func(string, net.IP) bool { return false })
	got = verdictForEvent(otherPID, 443, publicIP, "evil.example", selfPID, denyAll, nil)
	if got != report.VerdictDenyPolicy {
		t.Errorf("verdictForEvent (other process, denied) = %q, want %q", got, report.VerdictDenyPolicy)
	}
}
