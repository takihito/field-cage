package report

import (
	"fmt"
	"io"
	"strings"
)

// Output formats accepted by RendererFor. FormatAuto picks markdown on a
// GitHub Actions runner and text elsewhere.
const (
	FormatAuto        = "auto"
	FormatText        = "text"
	FormatJSON        = "json"
	FormatCSV         = "csv"
	FormatMarkdown    = "markdown"
	FormatAnnotations = "annotations"
)

// FormatNames lists the accepted formats for help output and error messages.
var FormatNames = []string{FormatAuto, FormatText, FormatJSON, FormatCSV, FormatMarkdown, FormatAnnotations}

// Annotation levels for the annotations renderer. LevelAuto derives the level
// from the mode: block-mode denials are warnings, audit-mode ones are notices,
// because audit mode never actually blocked the traffic.
const (
	LevelAuto    = "auto"
	LevelOff     = "off"
	LevelNotice  = "notice"
	LevelWarning = "warning"
	LevelError   = "error"
)

// Options controls renderer behaviour.
type Options struct {
	// Top caps the rows per table; 0 means unlimited. Omitted rows are
	// reported rather than silently dropped.
	Top int
	// AnnotationLevel is one of the Level* constants; "" means LevelAuto.
	AnnotationLevel string
}

// Renderer writes an aggregated report.
type Renderer interface {
	Render(w io.Writer, s *Summary) error
}

// RawRenderer writes one row per event without aggregating, for callers that
// want to post-process the log elsewhere. Close must be called to flush.
type RawRenderer interface {
	WriteEvent(ev Event) error
	Close() error
}

// ResolveFormat expands FormatAuto and validates the format name. getenv is
// injected so the auto-detection is testable; pass os.Getenv in production.
func ResolveFormat(format string, getenv func(string) string) (string, error) {
	if format == "" || format == FormatAuto {
		if getenv != nil && getenv("GITHUB_ACTIONS") == "true" {
			return FormatMarkdown, nil
		}
		return FormatText, nil
	}
	switch format {
	case FormatText, FormatJSON, FormatCSV, FormatMarkdown, FormatAnnotations:
		return format, nil
	}
	return "", fmt.Errorf("unknown format %q (want one of: %s)", format, strings.Join(FormatNames, ", "))
}

// RendererFor returns the aggregated renderer for an already-resolved format.
func RendererFor(format string, opts Options) (Renderer, error) {
	switch format {
	case FormatText:
		return textRenderer{opts}, nil
	case FormatJSON:
		return jsonRenderer{opts}, nil
	case FormatCSV:
		return csvRenderer{opts}, nil
	case FormatMarkdown:
		return markdownRenderer{opts}, nil
	case FormatAnnotations:
		return annotationsRenderer{opts}, nil
	}
	return nil, fmt.Errorf("unknown format %q (want one of: %s)", format, strings.Join(FormatNames, ", "))
}

// RawRendererFor returns the per-event renderer for an already-resolved
// format. Only text, json (as JSON Lines) and csv support raw output;
// markdown and annotations are summary presentations by nature.
func RawRendererFor(format string, w io.Writer, opts Options) (RawRenderer, error) {
	switch format {
	case FormatText:
		return newRawText(w), nil
	case FormatJSON:
		return newRawJSON(w), nil
	case FormatCSV:
		return newRawCSV(w), nil
	case FormatMarkdown, FormatAnnotations:
		return nil, fmt.Errorf("--raw is not supported with format %q (use text, json or csv)", format)
	}
	return nil, fmt.Errorf("unknown format %q (want one of: %s)", format, strings.Join(FormatNames, ", "))
}

// resolveLevel maps LevelAuto to a concrete annotation level based on the mode.
func resolveLevel(level, mode string) string {
	if level == "" {
		level = LevelAuto
	}
	if level != LevelAuto {
		return level
	}
	if strings.HasPrefix(mode, "block") {
		return LevelWarning
	}
	return LevelNotice
}

// modeLabel renders the mode for display, naming the unknown case explicitly
// rather than printing an empty field.
func modeLabel(mode string) string {
	if mode == "" {
		return "unknown"
	}
	return mode
}

// markdownEscape neutralises the Markdown and HTML metacharacters in a
// log-derived value. Domain names come from observed DNS responses and process
// names from the kernel comm field, so an attacker who can influence either
// could otherwise inject markup — or extra table cells — into the job summary.
// Control characters were already removed at parse time (see sanitize).
func markdownEscape(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		switch r {
		case '\\', '|', '`', '<', '>', '&', '*', '_', '[', ']', '#', '~':
			b.WriteByte('\\')
		}
		b.WriteRune(r)
	}
	return b.String()
}

// annotationMessage escapes a value used as a workflow-command message, and
// annotationProperty a value used as a command property (title=...). Both
// prevent a log-derived value from being read as a new workflow command.
// See https://docs.github.com/actions/reference/workflow-commands-for-github-actions
func annotationMessage(s string) string {
	s = strings.ReplaceAll(s, "%", "%25")
	s = strings.ReplaceAll(s, "\r", "%0D")
	s = strings.ReplaceAll(s, "\n", "%0A")
	return s
}

func annotationProperty(s string) string {
	s = annotationMessage(s)
	s = strings.ReplaceAll(s, ":", "%3A")
	s = strings.ReplaceAll(s, ",", "%2C")
	return s
}

// limit returns the rows to show and how many were omitted, honouring
// Options.Top.
func limitRows(rows []DestStat, top int) (shown []DestStat, omitted int) {
	if top <= 0 || len(rows) <= top {
		return rows, 0
	}
	return rows[:top], len(rows) - top
}

// processList renders the process column, marking names dropped by the
// per-destination cap so the reader knows the list is partial.
func processList(d DestStat) string {
	s := strings.Join(d.Processes, ",")
	if d.MoreProcesses > 0 {
		if s != "" {
			s += ","
		}
		s += fmt.Sprintf("+%d more", d.MoreProcesses)
	}
	if s == "" {
		return "-"
	}
	return s
}
