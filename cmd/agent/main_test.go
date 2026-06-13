package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/takihito/field-cage/internal/policy"
)

// loadEngine writes a minimal policy file and loads it.
func loadEngine(t *testing.T, mode string) *policy.Engine {
	t.Helper()
	path := filepath.Join(t.TempDir(), "policy.yml")
	data := "mode: " + mode + "\nallowlist:\n  - example.com\n"
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
