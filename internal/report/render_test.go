package report

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// update regenerates the golden files: go test ./internal/report/ -run Golden -update
var update = os.Getenv("UPDATE_GOLDEN") == "1"

func loadFixture(t *testing.T, name string) *Summary {
	t.Helper()
	f, err := os.Open(filepath.Join("testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	c := NewCollector()
	mode, malformed, err := ScanLog(f, c.Add)
	if err != nil {
		t.Fatal(err)
	}
	c.SetMode(mode)
	c.SetMalformed(malformed)
	return c.Summary()
}

func checkGolden(t *testing.T, name string, got []byte) {
	t.Helper()
	path := filepath.Join("testdata", name)
	if update {
		if err := os.WriteFile(path, got, 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read golden %s: %v (run with UPDATE_GOLDEN=1 to create)", path, err)
	}
	if !bytes.Equal(want, got) {
		t.Errorf("golden mismatch for %s\n--- want ---\n%s\n--- got ---\n%s", name, want, got)
	}
}

func TestRenderGolden(t *testing.T) {
	summary := loadFixture(t, "agent.log")
	hostile := loadFixture(t, "hostile.log")

	cases := []struct {
		format string
		golden string
		s      *Summary
		opts   Options
	}{
		{FormatText, "agent.text.golden", summary, Options{Top: 50}},
		{FormatJSON, "agent.json.golden", summary, Options{Top: 50}},
		{FormatCSV, "agent.csv.golden", summary, Options{Top: 50}},
		{FormatMarkdown, "agent.md.golden", summary, Options{Top: 50}},
		{FormatAnnotations, "agent.annotations.golden", summary, Options{Top: 50}},
		{FormatText, "agent.text.top1.golden", summary, Options{Top: 1}},
		{FormatJSON, "agent.json.top1.golden", summary, Options{Top: 1}},
		{FormatCSV, "agent.csv.top1.golden", summary, Options{Top: 1}},
		{FormatMarkdown, "agent.md.top1.golden", summary, Options{Top: 1}},
		{FormatText, "hostile.text.golden", hostile, Options{Top: 50}},
		{FormatJSON, "hostile.json.golden", hostile, Options{Top: 50}},
		{FormatCSV, "hostile.csv.golden", hostile, Options{Top: 50}},
		{FormatMarkdown, "hostile.md.golden", hostile, Options{Top: 50}},
		{FormatAnnotations, "hostile.annotations.golden", hostile, Options{Top: 50}},
	}
	for _, tc := range cases {
		t.Run(tc.golden, func(t *testing.T) {
			r, err := RendererFor(tc.format, tc.opts)
			if err != nil {
				t.Fatal(err)
			}
			var buf bytes.Buffer
			if err := r.Render(&buf, tc.s); err != nil {
				t.Fatal(err)
			}
			checkGolden(t, tc.golden, buf.Bytes())
		})
	}
}

// TestMarkdownEscapeNeverLeaksTableStructure checks that no escaped domain or
// comm value can introduce unescaped HTML into the tables. The suggested
// allowlist is rendered inside a fenced ```yaml block, where GitHub's
// renderer does not interpret HTML at all, so raw text there is safe and is
// excluded from this check.
func TestMarkdownEscapeNeverLeaksTableStructure(t *testing.T) {
	hostile := loadFixture(t, "hostile.log")
	r := markdownRenderer{Options{Top: 50}}
	var buf bytes.Buffer
	if err := r.Render(&buf, hostile); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	// Only table rows (lines starting with "|") hold log-derived cells; the
	// surrounding "<details>"/"<summary>" markup is our own literal output and
	// is expected to contain unescaped "<". markdownEscape prefixes "<" with a
	// backslash rather than removing it, so look for one not preceded by "\".
	for _, line := range strings.Split(out, "\n") {
		if !strings.HasPrefix(line, "|") {
			continue
		}
		for i, r := range line {
			if r == '<' && (i == 0 || line[i-1] != '\\') {
				t.Errorf("unescaped '<' leaked into markdown table row: %q", line)
			}
		}
	}
}

// TestAnnotationsEscapeNeverEmitsNestedCommand checks that a log-derived value
// containing a literal newline cannot smuggle in an extra workflow-command
// line. GitHub only recognises a command when "::" starts a physical output
// line, so mid-line "::" (as in the "x::warning::pwn.example" fixture) is
// inert; the real risk is an unescaped newline turning attacker text into a
// new line. annotationMessage maps newlines to "%0A", so the rendered line count must
// equal the number of annotations emitted, with every line still starting
// with a real "::<level>" command.
func TestAnnotationsEscapeNeverEmitsNestedCommand(t *testing.T) {
	hostile := loadFixture(t, "hostile.log")
	r := annotationsRenderer{Options{Top: 50}}
	var buf bytes.Buffer
	if err := r.Render(&buf, hostile); err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimRight(buf.String(), "\n"), "\n")
	wantLines := len(hostile.Denied())
	if len(lines) != wantLines {
		t.Fatalf("got %d output lines, want %d (a log-derived value likely smuggled in an extra line): %q",
			len(lines), wantLines, lines)
	}
	for _, line := range lines {
		if !strings.HasPrefix(line, "::notice ") && !strings.HasPrefix(line, "::warning ") && !strings.HasPrefix(line, "::error ") {
			t.Errorf("line does not start with a recognised workflow command: %q", line)
		}
	}
}

func TestResolveFormat(t *testing.T) {
	cases := []struct {
		name   string
		format string
		env    map[string]string
		want   string
		errStr string
	}{
		{"explicit text", "text", nil, FormatText, ""},
		{"auto outside actions", "auto", nil, FormatText, ""},
		{"auto inside actions", "auto", map[string]string{"GITHUB_ACTIONS": "true"}, FormatMarkdown, ""},
		{"empty defaults to auto", "", map[string]string{"GITHUB_ACTIONS": "true"}, FormatMarkdown, ""},
		{"unknown format", "yaml", nil, "", "unknown format"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			getenv := func(k string) string { return tc.env[k] }
			got, err := ResolveFormat(tc.format, getenv)
			if tc.errStr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.errStr) {
					t.Fatalf("err = %v, want containing %q", err, tc.errStr)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tc.want {
				t.Errorf("ResolveFormat = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestRawRenderers(t *testing.T) {
	for _, format := range []string{FormatText, FormatJSON, FormatCSV} {
		t.Run(format, func(t *testing.T) {
			f, err := os.Open(filepath.Join("testdata", "agent.log"))
			if err != nil {
				t.Fatal(err)
			}
			defer f.Close()
			var buf bytes.Buffer
			rr, err := RawRendererFor(format, &buf, Options{})
			if err != nil {
				t.Fatal(err)
			}
			_, malformed, err := ScanLog(f, rr.WriteEvent)
			if err != nil {
				t.Fatal(err)
			}
			if err := rr.Close(); err != nil {
				t.Fatal(err)
			}
			if malformed != 1 {
				t.Errorf("malformed = %d, want 1", malformed)
			}
			checkGolden(t, "agent.raw."+format+".golden", buf.Bytes())
		})
	}
}

func TestRawRendererForRejectsSummaryFormats(t *testing.T) {
	for _, format := range []string{FormatMarkdown, FormatAnnotations} {
		if _, err := RawRendererFor(format, &bytes.Buffer{}, Options{}); err == nil {
			t.Errorf("RawRendererFor(%q) = nil error, want error", format)
		}
	}
}
