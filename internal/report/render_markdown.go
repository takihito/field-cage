package report

import (
	"fmt"
	"io"
	"strings"
)

// markdownRenderer writes the GitHub Actions job summary. Every log-derived
// value goes through markdownEscape so a hostile domain or process name cannot
// inject markup or extra table cells.
type markdownRenderer struct{ opts Options }

func (r markdownRenderer) Render(w io.Writer, s *Summary) error {
	b := &strings.Builder{}
	fmt.Fprintf(b, "## \U0001F331 field-cage report \U0001F340\n\n")
	fmt.Fprintf(b, "%s **mode:** `%s` &middot; \U0001F4CA **events:** %d",
		modeEmoji(s.Mode), markdownEscape(modeLabel(s.Mode)), s.Total)
	if s.Malformed > 0 {
		fmt.Fprintf(b, " &middot; ⚠️ **unparsable log lines:** %d", s.Malformed)
	}
	fmt.Fprintf(b, "\n\n")

	if s.Total == 0 {
		fmt.Fprintf(b, "✅ No connection events were captured.\n")
		_, err := io.WriteString(w, b.String())
		return err
	}

	denied, allowed, skipped := s.Denied(), s.Allowed(), s.Skipped()
	fmt.Fprintf(b, "✅ **%d** allowed &nbsp;&middot;&nbsp; \U0001F6AB **%d** denied &nbsp;&middot;&nbsp; ⏭️ **%d** skipped\n\n",
		s.AllowedEvents(), s.DeniedEvents(), s.SkippedEvents())

	b.WriteString("| verdict | count |\n| --- | --: |\n")
	for _, vc := range s.VerdictCounts() {
		fmt.Fprintf(b, "| %s `%s` | %d |\n", verdictEmoji(vc.Verdict), markdownEscape(string(vc.Verdict)), vc.Count)
	}
	b.WriteString("\n")

	if len(denied) > 0 {
		fmt.Fprintf(b, "### \U0001F6AB Denied destinations (%d)\n\n", len(denied))
		r.writeTable(b, denied)
	}
	r.writeDetails(b, fmt.Sprintf("✅ Allowed destinations (%d)", len(allowed)), allowed)
	r.writeDetails(b, fmt.Sprintf("⏭️ Skipped: DNS, loopback, and the agent's own traffic (%d)", len(skipped)), skipped)

	if len(s.SuggestedAllowlist) > 0 {
		b.WriteString("<details>\n<summary>\U0001F4CB Suggested allowlist (review before use)</summary>\n\n")
		b.WriteString("```yaml\nallowlist:\n")
		for _, d := range s.SuggestedAllowlist {
			// Single-quote each entry so a destination containing YAML
			// metacharacters cannot alter the structure of a policy file
			// pasted from here; a literal quote is doubled per the YAML spec.
			fmt.Fprintf(b, "  - '%s'\n", strings.ReplaceAll(d, "'", "''"))
		}
		b.WriteString("```\n\n</details>\n")
	}

	_, err := io.WriteString(w, b.String())
	return err
}

// modeEmoji picks a glyph reflecting the enforcement mode, so the reader can
// tell block from audit at a glance without reading the label.
func modeEmoji(mode string) string {
	if strings.HasPrefix(mode, "block") {
		return "\U0001F512" // lock: block mode enforces the allowlist
	}
	return "\U0001F50D" // magnifying glass: audit mode only observes
}

// verdictEmoji picks a glyph per verdict family so the tally table is
// scannable without reading every label.
func verdictEmoji(v Verdict) string {
	switch {
	case v.IsDeny():
		return "\U0001F6AB"
	case v.IsAllow():
		return "✅"
	case v.IsSkip():
		return "⏭️"
	default:
		return "❓"
	}
}

func (r markdownRenderer) writeDetails(b *strings.Builder, summary string, rows []DestStat) {
	if len(rows) == 0 {
		return
	}
	fmt.Fprintf(b, "<details>\n<summary>%s</summary>\n\n", markdownEscape(summary))
	r.writeTable(b, rows)
	b.WriteString("</details>\n\n")
}

func (r markdownRenderer) writeTable(b *strings.Builder, rows []DestStat) {
	shown, omitted := limitRows(rows, r.opts.Top)
	b.WriteString("| destination | ip | port | count | processes |\n| --- | --- | --: | --: | --- |\n")
	for _, d := range shown {
		ip := d.IP
		if ip == d.Destination() {
			ip = "&mdash;" // no domain resolved: the destination column is the IP
		} else {
			ip = "`" + markdownEscape(ip) + "`"
		}
		fmt.Fprintf(b, "| `%s` | %s | %d | %d | `%s` |\n",
			markdownEscape(d.Destination()), ip, d.Port, d.Count, markdownEscape(processList(d)))
	}
	if omitted > 0 {
		fmt.Fprintf(b, "\n_%d more destinations omitted (raise `--top`)._\n", omitted)
	}
	b.WriteString("\n")
}
