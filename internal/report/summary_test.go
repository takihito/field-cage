package report

import (
	"fmt"
	"net"
	"testing"
)

// TestCollectorProcessOverflowCountsDistinctNamesOnce pins a fix: once a
// destination has accumulated maxProcessesPerDest distinct process names, a
// later event from an already-overflowed process must not increment
// MoreProcesses again — MoreProcesses counts distinct dropped names, not
// events.
func TestCollectorProcessOverflowCountsDistinctNamesOnce(t *testing.T) {
	c := NewCollector()
	dst := net.ParseIP("203.0.113.9")

	for i := 0; i < maxProcessesPerDest; i++ {
		if err := c.Add(Event{Verdict: VerdictAllow, Comm: fmt.Sprintf("proc-%d", i), IP: dst, Port: 443}); err != nil {
			t.Fatal(err)
		}
	}
	// The 11th distinct process overflows the cap; repeat it several times.
	for i := 0; i < 5; i++ {
		if err := c.Add(Event{Verdict: VerdictAllow, Comm: "overflow-proc", IP: dst, Port: 443}); err != nil {
			t.Fatal(err)
		}
	}

	dests := c.Summary().Destinations
	if len(dests) != 1 {
		t.Fatalf("got %d destinations, want 1", len(dests))
	}
	if got := dests[0].MoreProcesses; got != 1 {
		t.Errorf("MoreProcesses = %d, want 1 (one distinct process was dropped, seen 5 times)", got)
	}
	if got := dests[0].Count; got != maxProcessesPerDest+5 {
		t.Errorf("Count = %d, want %d", got, maxProcessesPerDest+5)
	}
}

// TestSummaryDestinationOrderIsDeterministic pins a fix: when several
// destinations tie on every other sort key (domain, port, count, verdict —
// e.g. several resolved addresses of one domain, each seen once), the order
// must not depend on Go's randomized map iteration order. IP breaks the tie.
func TestSummaryDestinationOrderIsDeterministic(t *testing.T) {
	c := NewCollector()
	ips := []string{
		"104.16.0.34", "104.16.9.34", "104.16.1.34",
		"2606:4700::6810:422", "2606:4700::6810:22",
	}
	for _, ip := range ips {
		if err := c.Add(Event{Verdict: VerdictSkipSelf, Comm: "field-cage_linu", Domain: "registry.npmjs.org", IP: net.ParseIP(ip), Port: 53}); err != nil {
			t.Fatal(err)
		}
	}

	for i := 0; i < 20; i++ {
		dests := c.Summary().Destinations
		if len(dests) != len(ips) {
			t.Fatalf("run %d: got %d destinations, want %d", i, len(dests), len(ips))
		}
		for j := 1; j < len(dests); j++ {
			if dests[j-1].IP >= dests[j].IP {
				t.Fatalf("run %d: destinations not sorted by IP as a tiebreak: %q then %q", i, dests[j-1].IP, dests[j].IP)
			}
		}
	}
}
