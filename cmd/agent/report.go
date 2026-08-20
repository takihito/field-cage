package main

import (
	"bufio"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"strings"

	"github.com/takihito/field-cage/internal/report"
)

// reportUsage documents the subcommand; the agent itself takes no subcommand,
// so `report` is dispatched before the top-level flags are parsed.
const reportUsage = `usage: field-cage report [flags]

Aggregate an agent log and render it. Formats: %s
With --format auto (the default) markdown is used on a GitHub Actions runner
and text elsewhere.

flags:
`

// runReport implements the `report` subcommand. It reads an agent log (the
// file the action redirects both streams into, or stdin) and writes the
// requested representation to stdout.
func runReport(args []string, stdin io.Reader, stdout io.Writer, getenv func(string) string) error {
	fs := flag.NewFlagSet("report", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	var (
		logPath = fs.String("log", "", `path to the agent log file ("-" or empty reads stdin)`)
		format  = fs.String("format", report.FormatAuto, "output format: "+strings.Join(report.FormatNames, ", "))
		top     = fs.Int("top", 50, "maximum destinations per table (0 for unlimited)")
		raw     = fs.Bool("raw", false, "emit one row per event instead of aggregating (text, json, csv only)")
		level   = fs.String("annotation-level", report.LevelAuto, "annotation level: auto, off, notice, warning, error")
		mode    = fs.String("mode", "", "override the mode label instead of reading it from the log")
	)
	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, reportUsage, strings.Join(report.FormatNames, ", "))
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() > 0 {
		return fmt.Errorf("unexpected argument %q", fs.Arg(0))
	}
	if *top < 0 {
		return fmt.Errorf("--top must not be negative")
	}

	resolved, err := report.ResolveFormat(*format, getenv)
	if err != nil {
		return err
	}
	switch *level {
	case report.LevelAuto, report.LevelOff, report.LevelNotice, report.LevelWarning, report.LevelError:
	default:
		return fmt.Errorf("invalid --annotation-level %q (want auto, off, notice, warning or error)", *level)
	}

	in := stdin
	if *logPath != "" && *logPath != "-" {
		f, err := os.Open(*logPath)
		if err != nil {
			return fmt.Errorf("open log: %w", err)
		}
		defer f.Close() //nolint:errcheck // read-only file
		in = f
	}
	// Buffer once here so both the raw and aggregated paths read in large
	// chunks regardless of whether the source is a file or a pipe.
	br := bufio.NewReader(in)

	opts := report.Options{Top: *top, AnnotationLevel: *level}
	out := bufio.NewWriter(stdout)

	if *raw {
		rr, err := report.RawRendererFor(resolved, out, opts)
		if err != nil {
			return err
		}
		if _, _, err := report.ScanLog(br, rr.WriteEvent); err != nil {
			return err
		}
		if err := rr.Close(); err != nil {
			return err
		}
		return out.Flush()
	}

	c := report.NewCollector()
	logMode, malformed, err := report.ScanLog(br, c.Add)
	if err != nil {
		return err
	}
	if *mode != "" {
		logMode = *mode
	}
	c.SetMode(logMode)
	c.SetMalformed(malformed)
	summary := c.Summary()

	// csv has no in-band way to note a truncated table (unlike text/markdown/
	// json, which each carry their own "N more omitted" marker), so warn on
	// stderr here for every format rather than let a --top cap look like full
	// coverage.
	if *top > 0 && len(summary.Destinations) > *top {
		slog.Warn("destinations truncated by --top", "shown", *top, "total", len(summary.Destinations))
	}
	if malformed > 0 {
		slog.Warn("skipped unparsable log lines", "count", malformed)
	}

	r, err := report.RendererFor(resolved, opts)
	if err != nil {
		return err
	}
	if err := r.Render(out, summary); err != nil {
		return err
	}
	return out.Flush()
}
