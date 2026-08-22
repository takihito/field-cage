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
	fmt.Fprintf(b, "## field-cage report\n\n")
	fmt.Fprintf(b, "**mode:** `%s` &middot; **events:** %d", markdownEscape(modeLabel(s.Mode)), s.Total)
	if s.Malformed > 0 {
		fmt.Fprintf(b, " &middot; **unparsable log lines:** %d", s.Malformed)
	}
	fmt.Fprintf(b, "\n\n")

	if s.Total == 0 {
		fmt.Fprintf(b, "No connection events were captured.\n")
		_, err := io.WriteString(w, b.String())
		return err
	}

	b.WriteString("| verdict | count |\n| --- | --: |\n")
	for _, vc := range s.VerdictCounts() {
		fmt.Fprintf(b, "| `%s` | %d |\n", markdownEscape(string(vc.Verdict)), vc.Count)
	}
	b.WriteString("\n")

	if denied := s.Denied(); len(denied) > 0 {
		fmt.Fprintf(b, "### Denied destinations (%d)\n\n", len(denied))
		r.writeTable(b, denied)
	}
	r.writeDetails(b, fmt.Sprintf("Allowed destinations (%d)", len(s.Allowed())), s.Allowed())
	r.writeDetails(b, fmt.Sprintf("Skipped: DNS, loopback, and the agent's own traffic (%d)", len(s.Skipped())), s.Skipped())

	if len(s.SuggestedAllowlist) > 0 {
		b.WriteString("<details>\n<summary>Suggested allowlist (review before use)</summary>\n\n")
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
