package report

import (
	"encoding/csv"
	"io"
	"strconv"
	"strings"
)

// CSV header rows. These are part of the tool's public output contract:
// downstream spreadsheets and importers depend on the column order, so treat a
// change as breaking and note it in the release notes.
var (
	csvHeader    = []string{"verdict", "destination", "domain", "ip", "port", "count", "processes"}
	csvRawHeader = []string{"verdict", "pid", "tgid", "comm", "destination", "domain", "ip", "port"}
)

// csvRenderer writes one row per aggregated destination. Quoting is left to
// encoding/csv, which escapes separators and quotes in log-derived values.
type csvRenderer struct{ opts Options }

func (r csvRenderer) Render(w io.Writer, s *Summary) error {
	cw := csv.NewWriter(w)
	if err := cw.Write(csvHeader); err != nil {
		return err
	}
	rows, _ := limitRows(s.Destinations, r.opts.Top)
	for _, d := range rows {
		procs := strings.Join(d.Processes, ";")
		if d.MoreProcesses > 0 {
			if procs != "" {
				procs += ";"
			}
			procs += "+" + strconv.Itoa(d.MoreProcesses) + " more"
		}
		row := []string{
			string(d.Verdict),
			csvFormulaGuard(d.Destination()),
			csvFormulaGuard(d.Domain),
			d.IP,
			strconv.FormatUint(uint64(d.Port), 10),
			strconv.Itoa(d.Count),
			csvFormulaGuard(procs),
		}
		if err := cw.Write(row); err != nil {
			return err
		}
	}
	cw.Flush()
	return cw.Error()
}

// csvFormulaGuard prefixes a cell with "'" when it starts with a character
// that a spreadsheet application (Excel, Google Sheets, LibreOffice) would
// interpret as the start of a formula. encoding/csv only escapes CSV syntax
// (separators and quotes), not this; domain names and process names come
// from observed network traffic and are therefore attacker-influenced,
// letting a crafted destination execute a formula when a reviewer opens the
// exported CSV. See OWASP "CSV Injection".
func csvFormulaGuard(s string) string {
	if s == "" {
		return s
	}
	switch s[0] {
	case '=', '+', '-', '@', '\t', '\r':
		return "'" + s
	}
	return s
}

// rawCSV writes one row per event.
type rawCSV struct {
	cw     *csv.Writer
	header bool
}

func newRawCSV(w io.Writer) *rawCSV { return &rawCSV{cw: csv.NewWriter(w)} }

func (r *rawCSV) WriteEvent(ev Event) error {
	if !r.header {
		if err := r.cw.Write(csvRawHeader); err != nil {
			return err
		}
		r.header = true
	}
	return r.cw.Write([]string{
		string(ev.Verdict),
		strconv.FormatUint(uint64(ev.PID), 10),
		strconv.FormatUint(uint64(ev.TGID), 10),
		csvFormulaGuard(ev.Comm),
		csvFormulaGuard(ev.Destination()),
		csvFormulaGuard(ev.Domain),
		ev.IPString(),
		strconv.FormatUint(uint64(ev.Port), 10),
	})
}

func (r *rawCSV) Close() error {
	if !r.header {
		if err := r.cw.Write(csvRawHeader); err != nil {
			return err
		}
		r.header = true
	}
	r.cw.Flush()
	return r.cw.Error()
}
