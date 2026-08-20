package report

import (
	"net"
	"strings"
	"testing"
)

// TestParseLineRoundTrip pins the parser to Line.String(): the agent's stdout
// format is a public contract (CI smoke tests grep it) and the report
// subcommand parses it back, so a change to either side must fail here.
func TestParseLineRoundTrip(t *testing.T) {
	cases := []struct {
		name string
		ev   Event
	}{
		{"domain and IPv4", Event{VerdictAllow, 1234, 1234, "curl", "github.com", net.ParseIP("140.82.113.4"), 443}},
		{"no domain", Event{VerdictDenyNoDomain, 7, 7, "python3", "", net.ParseIP("198.51.100.9"), 8443}},
		{"bare IPv6", Event{VerdictAllow, 9, 9, "node", "", net.ParseIP("2606:4700::6810:23"), 443}},
		{"IPv6 with domain", Event{VerdictAllow, 9, 9, "node", "example.com", net.ParseIP("2001:db8::1"), 443}},
		// comm is a 16-byte kernel field holding an arbitrary string, so it may
		// contain spaces and even look like another field marker.
		{"comm with space", Event{VerdictSkipDNS, 1, 1, "my proc", "", net.ParseIP("10.0.0.2"), 53}},
		{"comm looks like dst field", Event{VerdictAllow, 1, 1, "a dst=9.9.9.9:1", "example.com", net.ParseIP("1.1.1.1"), 443}},
		{"comm at max length", Event{VerdictAllow, 1, 1, "0123456789abcde", "example.com", net.ParseIP("1.1.1.1"), 443}},
		{"max pid", Event{VerdictAllow, 4294967295, 4294967295, "x", "", net.ParseIP("1.1.1.1"), 65535}},
		{"port 0", Event{VerdictAllow, 1, 1, "x", "", net.ParseIP("1.1.1.1"), 0}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rendered := Line{
				Verdict: tc.ev.Verdict, PID: tc.ev.PID, TGID: tc.ev.TGID, Comm: tc.ev.Comm,
				Dst: Dst(tc.ev.Domain, tc.ev.IP), DPort: tc.ev.Port,
			}.String()
			got, err := ParseLine(rendered)
			if err != nil {
				t.Fatalf("ParseLine(%q) failed: %v", rendered, err)
			}
			if got.Verdict != tc.ev.Verdict || got.PID != tc.ev.PID || got.TGID != tc.ev.TGID ||
				got.Comm != tc.ev.Comm || got.Domain != tc.ev.Domain || got.Port != tc.ev.Port ||
				!got.IP.Equal(tc.ev.IP) {
				t.Errorf("round trip mismatch\n line: %q\n got:  %+v\n want: %+v", rendered, got, tc.ev)
			}
		})
	}
}

func TestParseLineErrors(t *testing.T) {
	cases := []struct{ name, line string }{
		{"empty", ""},
		{"slog diagnostic", `time=2026-08-20T12:00:00Z level=INFO msg="watching outbound connections"`},
		{"missing dst", "verdict=ALLOW pid=1 tgid=1 comm=curl"},
		{"missing pid", "verdict=ALLOW tgid=1 comm=curl dst=1.2.3.4:443"},
		{"missing tgid", "verdict=ALLOW pid=1 comm=curl dst=1.2.3.4:443"},
		{"missing comm", "verdict=ALLOW pid=1 tgid=1 dst=1.2.3.4:443"},
		{"non numeric pid", "verdict=ALLOW pid=x tgid=1 comm=curl dst=1.2.3.4:443"},
		{"non numeric tgid", "verdict=ALLOW pid=1 tgid=x comm=curl dst=1.2.3.4:443"},
		{"pid overflows uint32", "verdict=ALLOW pid=4294967296 tgid=1 comm=curl dst=1.2.3.4:443"},
		{"port overflows uint16", "verdict=ALLOW pid=1 tgid=1 comm=curl dst=1.2.3.4:65536"},
		{"no port", "verdict=ALLOW pid=1 tgid=1 comm=curl dst=1.2.3.4"},
		{"invalid IP", "verdict=ALLOW pid=1 tgid=1 comm=curl dst=not-an-ip:443"},
		{"empty verdict", "verdict= pid=1 tgid=1 comm=curl dst=1.2.3.4:443"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if ev, err := ParseLine(tc.line); err == nil {
				t.Errorf("ParseLine(%q) = %+v, want error", tc.line, ev)
			}
		})
	}
}

// TestParseLineSanitizes checks that control characters in attacker-influenced
// fields are neutralised at parse time, which is what lets the renderers reason
// only about their own metacharacters.
func TestParseLineSanitizes(t *testing.T) {
	line := "verdict=ALLOW pid=1 tgid=1 comm=ev\til dst=ba\x07d.example (1.2.3.4):443"
	ev, err := ParseLine(line)
	if err != nil {
		t.Fatalf("ParseLine: %v", err)
	}
	if strings.ContainsAny(ev.Comm, "\t\n\r\x07") || strings.ContainsAny(ev.Domain, "\t\n\r\x07") {
		t.Errorf("control characters survived: comm=%q domain=%q", ev.Comm, ev.Domain)
	}
	if want := "ev?il"; ev.Comm != want {
		t.Errorf("comm = %q, want %q", ev.Comm, want)
	}
	if want := "ba?d.example"; ev.Domain != want {
		t.Errorf("domain = %q, want %q", ev.Domain, want)
	}
}

func TestParseLineTruncatesOverlongValues(t *testing.T) {
	longDomain := strings.Repeat("a", maxDomainLen+50)
	longComm := strings.Repeat("b", maxCommLen+50)
	ev, err := ParseLine("verdict=ALLOW pid=1 tgid=1 comm=" + longComm + " dst=" + longDomain + " (1.2.3.4):443")
	if err != nil {
		t.Fatalf("ParseLine: %v", err)
	}
	if len(ev.Domain) != maxDomainLen {
		t.Errorf("domain length = %d, want %d", len(ev.Domain), maxDomainLen)
	}
	if len(ev.Comm) != maxCommLen {
		t.Errorf("comm length = %d, want %d", len(ev.Comm), maxCommLen)
	}
}

func TestScanLog(t *testing.T) {
	log := strings.Join([]string{
		`time=2026-08-20T12:00:00Z level=INFO msg="watching outbound connections (Ctrl+C to stop)" version=v0.1.0 mode="audit (no policy)"`,
		`time=2026-08-20T12:00:00Z level=INFO msg="watching outbound connections (Ctrl+C to stop)" version=v0.1.0 mode=block`,
		"verdict=ALLOW pid=1 tgid=1 comm=curl dst=github.com (1.1.1.1):443",
		"verdict=ALLOW pid=nope tgid=1 comm=curl dst=1.1.1.1:443",
		`time=2026-08-20T12:00:01Z level=WARN msg="close error"`,
		"verdict=DENY(no-domain) pid=2 tgid=2 comm=sh dst=203.0.113.1:443",
	}, "\n")

	var got []Event
	mode, malformed, err := ScanLog(strings.NewReader(log), func(ev Event) error {
		got = append(got, ev)
		return nil
	})
	if err != nil {
		t.Fatalf("ScanLog: %v", err)
	}
	// The first startup diagnostic wins: a restarted agent must not silently
	// relabel the whole report.
	if want := "audit (no policy)"; mode != want {
		t.Errorf("mode = %q, want %q", mode, want)
	}
	if malformed != 1 {
		t.Errorf("malformed = %d, want 1", malformed)
	}
	if len(got) != 2 {
		t.Fatalf("events = %d, want 2", len(got))
	}
	if got[0].Domain != "github.com" || got[1].Verdict != VerdictDenyNoDomain {
		t.Errorf("unexpected events: %+v", got)
	}
}

func TestScanLogNoModeLine(t *testing.T) {
	mode, malformed, err := ScanLog(strings.NewReader("verdict=ALLOW pid=1 tgid=1 comm=curl dst=1.1.1.1:443\n"), nil)
	if err != nil {
		t.Fatalf("ScanLog: %v", err)
	}
	if mode != "" || malformed != 0 {
		t.Errorf("mode = %q, malformed = %d; want \"\", 0", mode, malformed)
	}
}
