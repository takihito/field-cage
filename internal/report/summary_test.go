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
