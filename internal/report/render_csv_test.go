package report

import (
	"bytes"
	"encoding/csv"
	"strings"
	"testing"
)

// TestCSVFormulaGuard pins the OWASP "CSV Injection" mitigation: a
// log-derived cell that would otherwise be interpreted as a spreadsheet
// formula (starts with =, +, -, @, a tab, or a CR) must be prefixed so
// opening the exported CSV cannot execute attacker-supplied logic.
func TestCSVFormulaGuard(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"", ""},
		{"github.com", "github.com"},
		{"=cmd|'/c calc'!A0", "'=cmd|'/c calc'!A0"},
		{"+1+1", "'+1+1"},
		{"-1+1", "'-1+1"},
		{"@SUM(A1:A2)", "'@SUM(A1:A2)"},
		{"\tevil", "'\tevil"},
		{"\revil", "'\revil"},
		// a formula character that is not in the first position is not a
		// spreadsheet-recognised formula start and must be left untouched.
		{"github.com=evil", "github.com=evil"},
	}
	for _, tc := range cases {
		if got := csvFormulaGuard(tc.in); got != tc.want {
			t.Errorf("csvFormulaGuard(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

// TestCSVRendererGuardsAggregatedCells checks the guard is actually wired
// into the aggregated CSV renderer's destination and domain columns.
func TestCSVRendererGuardsAggregatedCells(t *testing.T) {
	c := NewCollector()
	if err := c.Add(Event{Verdict: VerdictDenyPolicy, Comm: "sh", Domain: "=cmd", Port: 443}); err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	if err := (csvRenderer{Options{Top: 50}}).Render(&buf, c.Summary()); err != nil {
		t.Fatal(err)
	}
	rows, err := csv.NewReader(strings.NewReader(buf.String())).ReadAll()
	if err != nil {
		t.Fatalf("re-parsing rendered CSV: %v", err)
	}
	if len(rows) != 2 {
		t.Fatalf("got %d rows, want 2 (header + 1 destination): %v", len(rows), rows)
	}
	destCol, domainCol := 1, 2
	if got := rows[1][destCol]; got != "'=cmd" {
		t.Errorf("destination cell = %q, want %q", got, "'=cmd")
	}
	if got := rows[1][domainCol]; got != "'=cmd" {
		t.Errorf("domain cell = %q, want %q", got, "'=cmd")
	}
}
