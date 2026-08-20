package report

import (
	"encoding/json"
	"io"
)

// jsonSchemaVersion identifies the JSON report layout. It is part of the
// tool's public output contract: bump it only for a breaking change, and note
// the change in the release notes.
const jsonSchemaVersion = 1

type jsonReport struct {
	SchemaVersion  int            `json:"schema_version"`
	Mode           string         `json:"mode"`
	TotalEvents    int            `json:"total_events"`
	MalformedLines int            `json:"malformed_lines"`
	ByVerdict      map[string]int `json:"by_verdict"`
	Destinations   []jsonDest     `json:"destinations"`
	// OmittedDestinations counts rows dropped by the --top cap, so a capped
	// report is never mistaken for full coverage.
	OmittedDestinations int      `json:"omitted_destinations"`
	SuggestedAllowlist  []string `json:"suggested_allowlist"`
}

type jsonDest struct {
	Verdict       string   `json:"verdict"`
	Destination   string   `json:"destination"`
	Domain        string   `json:"domain"`
	IP            string   `json:"ip"`
	Port          uint16   `json:"port"`
	Count         int      `json:"count"`
	Processes     []string `json:"processes"`
	MoreProcesses int      `json:"more_processes"`
}

type jsonEvent struct {
	Verdict     string `json:"verdict"`
	PID         uint32 `json:"pid"`
	TGID        uint32 `json:"tgid"`
	Comm        string `json:"comm"`
	Destination string `json:"destination"`
	Domain      string `json:"domain"`
	IP          string `json:"ip"`
	Port        uint16 `json:"port"`
}

// jsonRenderer writes the aggregated report as a single JSON object.
type jsonRenderer struct{ opts Options }

func (r jsonRenderer) Render(w io.Writer, s *Summary) error {
	rows, omitted := limitRows(s.Destinations, r.opts.Top)
	out := jsonReport{
		SchemaVersion:      jsonSchemaVersion,
		Mode:               s.Mode,
		TotalEvents:        s.Total,
		MalformedLines:     s.Malformed,
		ByVerdict:          make(map[string]int, len(s.ByVerdict)),
		Destinations:       make([]jsonDest, 0, len(rows)),
		SuggestedAllowlist: s.SuggestedAllowlist,
	}
	if out.SuggestedAllowlist == nil {
		out.SuggestedAllowlist = []string{}
	}
	for v, c := range s.ByVerdict {
		out.ByVerdict[string(v)] = c
	}
	for _, d := range rows {
		procs := d.Processes
		if procs == nil {
			procs = []string{}
		}
		out.Destinations = append(out.Destinations, jsonDest{
			Verdict:       string(d.Verdict),
			Destination:   d.Destination(),
			Domain:        d.Domain,
			IP:            d.IP,
			Port:          d.Port,
			Count:         d.Count,
			Processes:     procs,
			MoreProcesses: d.MoreProcesses,
		})
	}
	out.OmittedDestinations = omitted
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(out)
}

// rawJSON writes one JSON object per line (JSON Lines), the conventional
// streaming format for logs.
type rawJSON struct{ enc *json.Encoder }

func newRawJSON(w io.Writer) *rawJSON { return &rawJSON{enc: json.NewEncoder(w)} }

func (r *rawJSON) WriteEvent(ev Event) error {
	return r.enc.Encode(jsonEvent{
		Verdict:     string(ev.Verdict),
		PID:         ev.PID,
		TGID:        ev.TGID,
		Comm:        ev.Comm,
		Destination: ev.Destination(),
		Domain:      ev.Domain,
		IP:          ev.IPString(),
		Port:        ev.Port,
	})
}

func (r *rawJSON) Close() error { return nil }
