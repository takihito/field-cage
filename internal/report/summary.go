package report

import "sort"

// maxProcessesPerDest bounds the process names retained per destination so a
// long-running job that touches one destination from thousands of short-lived
// processes cannot grow the aggregate without limit.
const maxProcessesPerDest = 10

// DestStat aggregates the events that share a verdict and a destination.
type DestStat struct {
	Verdict   Verdict
	Domain    string // empty when no DNS resolution was observed
	IP        string
	Port      uint16
	Count     int
	Processes []string // sorted, capped at maxProcessesPerDest
	// MoreProcesses is the number of distinct process names dropped by that cap.
	MoreProcesses int
}

// Destination returns the domain when one was resolved, otherwise the IP.
func (d DestStat) Destination() string {
	if d.Domain != "" {
		return d.Domain
	}
	return d.IP
}

// Summary is the aggregated view of one agent log, and the single input every
// renderer consumes.
type Summary struct {
	// Mode is the effective enforcement mode as reported by the agent
	// ("audit", "block", "audit (no policy)"), or "" when the log did not
	// contain the startup diagnostic.
	Mode string
	// Total is the number of connection events parsed.
	Total int
	// Malformed is the number of verdict lines that could not be parsed.
	Malformed int
	// ByVerdict counts events per verdict.
	ByVerdict map[Verdict]int
	// Destinations is ordered denied first, then allowed, then skipped; within
	// each group by descending count and then by name, so the output is stable
	// across runs.
	Destinations []DestStat
	// SuggestedAllowlist lists every non-skipped destination (domain when
	// known, otherwise IP) as allowlist candidates. It is a starting point for
	// a policy file and needs review: denied destinations are included by
	// design, since the point of the report is to show what the job touched.
	SuggestedAllowlist []string
}

// Denied returns the denied destinations, keeping Destinations' order.
func (s *Summary) Denied() []DestStat { return s.filter(Verdict.IsDeny) }

// Allowed returns the allowed destinations, keeping Destinations' order.
func (s *Summary) Allowed() []DestStat { return s.filter(Verdict.IsAllow) }

// Skipped returns the destinations exempt from enforcement, keeping
// Destinations' order.
func (s *Summary) Skipped() []DestStat { return s.filter(Verdict.IsSkip) }

func (s *Summary) filter(pred func(Verdict) bool) []DestStat {
	var out []DestStat
	for _, d := range s.Destinations {
		if pred(d.Verdict) {
			out = append(out, d)
		}
	}
	return out
}

// DeniedEvents returns the number of denied connection events (not
// destinations); AllowedEvents does the same for allowed events.
func (s *Summary) DeniedEvents() int  { return s.countEvents(Verdict.IsDeny) }
func (s *Summary) AllowedEvents() int { return s.countEvents(Verdict.IsAllow) }

func (s *Summary) countEvents(pred func(Verdict) bool) int {
	n := 0
	for v, c := range s.ByVerdict {
		if pred(v) {
			n += c
		}
	}
	return n
}

// VerdictCounts returns the per-verdict counts in a stable presentation order:
// the known verdicts first, then any unknown ones alphabetically. A future
// agent version may emit a verdict this build does not know about, so unknown
// values are reported rather than dropped.
func (s *Summary) VerdictCounts() []VerdictCount {
	known := []Verdict{VerdictAllow, VerdictDenyPolicy, VerdictDenyNoDomain, VerdictSkipDNS, VerdictSkipLoopback}
	seen := make(map[Verdict]bool, len(known))
	out := make([]VerdictCount, 0, len(s.ByVerdict))
	for _, v := range known {
		seen[v] = true
		if c, ok := s.ByVerdict[v]; ok {
			out = append(out, VerdictCount{v, c})
		}
	}
	var rest []VerdictCount
	for v, c := range s.ByVerdict {
		if !seen[v] {
			rest = append(rest, VerdictCount{v, c})
		}
	}
	sort.Slice(rest, func(i, j int) bool { return rest[i].Verdict < rest[j].Verdict })
	return append(out, rest...)
}

// VerdictCount is one row of the verdict tally.
type VerdictCount struct {
	Verdict Verdict
	Count   int
}

// Collector aggregates events into a Summary. It accumulates per destination
// rather than retaining every event, so memory stays bounded by the number of
// distinct destinations regardless of how long the job ran.
type Collector struct {
	mode      string
	total     int
	malformed int
	byVerdict map[Verdict]int
	dests     map[destKey]*destAgg
}

type destKey struct {
	verdict Verdict
	domain  string
	ip      string
	port    uint16
}

type destAgg struct {
	count     int
	procs     []string
	procSeen  map[string]struct{}
	procsMore int
}

// NewCollector returns an empty Collector.
func NewCollector() *Collector {
	return &Collector{
		byVerdict: make(map[Verdict]int),
		dests:     make(map[destKey]*destAgg),
	}
}

// Add records one event. The error return is always nil; it exists so that
// Collector.Add can be passed directly to ScanLog.
func (c *Collector) Add(ev Event) error {
	c.total++
	c.byVerdict[ev.Verdict]++
	k := destKey{verdict: ev.Verdict, domain: ev.Domain, ip: ev.IPString(), port: ev.Port}
	agg, ok := c.dests[k]
	if !ok {
		agg = &destAgg{procSeen: make(map[string]struct{})}
		c.dests[k] = agg
	}
	agg.count++
	if ev.Comm != "" {
		if _, dup := agg.procSeen[ev.Comm]; !dup {
			// Mark seen regardless of whether the cap was reached: procsMore
			// counts *distinct* dropped names, so a name already counted as
			// overflow must not be recounted on its later occurrences.
			agg.procSeen[ev.Comm] = struct{}{}
			if len(agg.procs) < maxProcessesPerDest {
				agg.procs = append(agg.procs, ev.Comm)
			} else {
				agg.procsMore++
			}
		}
	}
	return nil
}

// SetMode records the effective mode, and SetMalformed the number of verdict
// lines that could not be parsed. Both come from ScanLog.
func (c *Collector) SetMode(mode string) { c.mode = mode }
func (c *Collector) SetMalformed(n int)  { c.malformed = n }

// Summary renders the accumulated state. It may be called more than once.
func (c *Collector) Summary() *Summary {
	s := &Summary{
		Mode:      c.mode,
		Total:     c.total,
		Malformed: c.malformed,
		ByVerdict: make(map[Verdict]int, len(c.byVerdict)),
	}
	for v, n := range c.byVerdict {
		s.ByVerdict[v] = n
	}

	s.Destinations = make([]DestStat, 0, len(c.dests))
	suggested := make(map[string]struct{})
	for k, agg := range c.dests {
		procs := append([]string(nil), agg.procs...)
		sort.Strings(procs)
		s.Destinations = append(s.Destinations, DestStat{
			Verdict:       k.verdict,
			Domain:        k.domain,
			IP:            k.ip,
			Port:          k.port,
			Count:         agg.count,
			Processes:     procs,
			MoreProcesses: agg.procsMore,
		})
		if !k.verdict.IsSkip() {
			dst := k.domain
			if dst == "" {
				dst = k.ip
			}
			if dst != "" {
				suggested[dst] = struct{}{}
			}
		}
	}
	sort.Slice(s.Destinations, func(i, j int) bool {
		a, b := s.Destinations[i], s.Destinations[j]
		if ra, rb := severity(a.Verdict), severity(b.Verdict); ra != rb {
			return ra < rb
		}
		if a.Count != b.Count {
			return a.Count > b.Count
		}
		if da, db := a.Destination(), b.Destination(); da != db {
			return da < db
		}
		if a.Port != b.Port {
			return a.Port < b.Port
		}
		return a.Verdict < b.Verdict
	})

	s.SuggestedAllowlist = make([]string, 0, len(suggested))
	for d := range suggested {
		s.SuggestedAllowlist = append(s.SuggestedAllowlist, d)
	}
	sort.Strings(s.SuggestedAllowlist)
	return s
}

// severity ranks verdicts for presentation: denials first, since they are what
// the reader needs to act on.
func severity(v Verdict) int {
	switch {
	case v.IsDeny():
		return 0
	case v.IsAllow():
		return 1
	case v.IsSkip():
		return 2
	default:
		return 3
	}
}
