package report

import (
	"fmt"
	"io"
	"strings"
	"text/tabwriter"
)

// textRenderer writes the human-readable aggregated report used on a terminal.
type textRenderer struct{ opts Options }

func (r textRenderer) Render(w io.Writer, s *Summary) error {
	if _, err := fmt.Fprintf(w, "field-cage report  mode=%s  events=%d", modeLabel(s.Mode), s.Total); err != nil {
		return err
	}
	if s.Malformed > 0 {
		if _, err := fmt.Fprintf(w, "  malformed-lines=%d", s.Malformed); err != nil {
			return err
		}
	}
	if _, err := fmt.Fprintln(w); err != nil {
		return err
	}
	if s.Total == 0 {
		_, err := fmt.Fprintln(w, "\nno connection events captured")
		return err
	}

	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "\nVERDICT\tCOUNT")
	for _, vc := range s.VerdictCounts() {
		fmt.Fprintf(tw, "%s\t%d\n", vc.Verdict, vc.Count)
	}
	if err := tw.Flush(); err != nil {
		return err
	}

	rows, omitted := limitRows(s.Destinations, r.opts.Top)
	tw = tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "\nCOUNT\tVERDICT\tDESTINATION\tIP\tPORT\tPROCESSES")
	for _, d := range rows {
		ip := d.IP
		if ip == d.Destination() {
			ip = "-" // no domain resolved: the destination column already shows the IP
		}
		fmt.Fprintf(tw, "%d\t%s\t%s\t%s\t%d\t%s\n",
			d.Count, d.Verdict, d.Destination(), ip, d.Port, processList(d))
	}
	if err := tw.Flush(); err != nil {
		return err
	}
	if omitted > 0 {
		if _, err := fmt.Fprintf(w, "... %d more destinations omitted (raise --top)\n", omitted); err != nil {
			return err
		}
	}

	if len(s.SuggestedAllowlist) > 0 {
		if _, err := fmt.Fprintln(w, "\nSUGGESTED ALLOWLIST (review before use)"); err != nil {
			return err
		}
		for _, d := range s.SuggestedAllowlist {
			if _, err := fmt.Fprintf(w, "  %s\n", d); err != nil {
				return err
			}
		}
	}
	return nil
}

// rawText writes one line per event, keeping the columns aligned.
type rawText struct {
	tw *tabwriter.Writer
}

func newRawText(w io.Writer) *rawText {
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, strings.Join([]string{"VERDICT", "PID", "TGID", "COMM", "DESTINATION", "IP", "PORT"}, "\t"))
	return &rawText{tw: tw}
}

func (r *rawText) WriteEvent(ev Event) error {
	_, err := fmt.Fprintf(r.tw, "%s\t%d\t%d\t%s\t%s\t%s\t%d\n",
		ev.Verdict, ev.PID, ev.TGID, ev.Comm, ev.Destination(), ev.IPString(), ev.Port)
	return err
}

func (r *rawText) Close() error { return r.tw.Flush() }
