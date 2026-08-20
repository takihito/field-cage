package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeLog(t *testing.T, lines ...string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "agent.log")
	if err := os.WriteFile(path, []byte(strings.Join(lines, "\n")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

const sampleLog1 = `time=2026-08-20T12:00:00Z level=INFO msg="watching outbound connections (Ctrl+C to stop)" version=v0.1.0 mode=block`
const sampleLog2 = `verdict=ALLOW pid=1 tgid=1 comm=curl dst=github.com (140.82.113.4):443`
const sampleLog3 = `verdict=DENY(not-in-policy) pid=2 tgid=2 comm=curl dst=evil.example (203.0.113.9):443`

func TestRunReportFormats(t *testing.T) {
	path := writeLog(t, sampleLog1, sampleLog2, sampleLog3)
	for _, format := range []string{"text", "json", "csv", "markdown", "annotations"} {
		t.Run(format, func(t *testing.T) {
			var out bytes.Buffer
			err := runReport([]string{"--log", path, "--format", format}, nil, &out, func(string) string { return "" })
			if err != nil {
				t.Fatalf("runReport: %v", err)
			}
			if out.Len() == 0 {
				t.Errorf("empty output for format %q", format)
			}
		})
	}
}

func TestRunReportAutoFormat(t *testing.T) {
	path := writeLog(t, sampleLog1, sampleLog2)

	var ci bytes.Buffer
	if err := runReport([]string{"--log", path}, nil, &ci, func(k string) string {
		if k == "GITHUB_ACTIONS" {
			return "true"
		}
		return ""
	}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(ci.String(), "##") {
		t.Errorf("expected markdown heading on a GitHub Actions runner, got: %s", ci.String())
	}

	var local bytes.Buffer
	if err := runReport([]string{"--log", path}, nil, &local, func(string) string { return "" }); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(local.String(), "##") {
		t.Errorf("expected plain text outside a GitHub Actions runner, got: %s", local.String())
	}
}

func TestRunReportReadsStdin(t *testing.T) {
	var out bytes.Buffer
	in := strings.NewReader(sampleLog1 + "\n" + sampleLog2 + "\n")
	if err := runReport([]string{"--format", "text"}, in, &out, func(string) string { return "" }); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "github.com") {
		t.Errorf("expected github.com in output, got: %s", out.String())
	}
}

func TestRunReportRaw(t *testing.T) {
	path := writeLog(t, sampleLog1, sampleLog2, sampleLog3)
	var out bytes.Buffer
	if err := runReport([]string{"--log", path, "--format", "json", "--raw"}, nil, &out, func(string) string { return "" }); err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimRight(out.String(), "\n"), "\n")
	if len(lines) != 2 {
		t.Fatalf("got %d JSON lines, want 2: %q", len(lines), lines)
	}
}

func TestRunReportRawRejectsMarkdown(t *testing.T) {
	path := writeLog(t, sampleLog1, sampleLog2)
	var out bytes.Buffer
	err := runReport([]string{"--log", path, "--format", "markdown", "--raw"}, nil, &out, func(string) string { return "" })
	if err == nil {
		t.Fatal("expected an error for --raw with markdown")
	}
}

func TestRunReportInvalidFormat(t *testing.T) {
	path := writeLog(t, sampleLog1)
	var out bytes.Buffer
	if err := runReport([]string{"--log", path, "--format", "yaml"}, nil, &out, func(string) string { return "" }); err == nil {
		t.Fatal("expected an error for an unknown format")
	}
}

func TestRunReportNegativeTop(t *testing.T) {
	path := writeLog(t, sampleLog1)
	var out bytes.Buffer
	if err := runReport([]string{"--log", path, "--top", "-1"}, nil, &out, func(string) string { return "" }); err == nil {
		t.Fatal("expected an error for a negative --top")
	}
}

func TestRunReportModeOverride(t *testing.T) {
	path := writeLog(t, sampleLog2) // no startup diagnostic in the log
	var out bytes.Buffer
	if err := runReport([]string{"--log", path, "--format", "json", "--mode", "audit"}, nil, &out, func(string) string { return "" }); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), `"mode": "audit"`) {
		t.Errorf("expected mode override to appear, got: %s", out.String())
	}
}
