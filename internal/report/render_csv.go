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
			d.Destination(),
			d.Domain,
			d.IP,
			strconv.FormatUint(uint64(d.Port), 10),
			strconv.Itoa(d.Count),
			procs,
		}
		if err := cw.Write(row); err != nil {
			return err
		}
	}
	cw.Flush()
	return cw.Error()
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
		ev.Comm,
		ev.Destination(),
		ev.Domain,
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
