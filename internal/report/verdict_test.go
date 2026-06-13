package report

import (
	"net"
	"testing"
)

// allowFunc adapts a function to the Allower interface for tests.
type allowFunc func(domain string, ip net.IP) bool

func (f allowFunc) Allow(domain string, ip net.IP) bool { return f(domain, ip) }

var (
	allowAll  = allowFunc(func(string, net.IP) bool { return true })
	denyAll   = allowFunc(func(string, net.IP) bool { return false })
	publicIP  = net.IPv4(93, 184, 216, 34)
	dnsServer = net.IPv4(8, 8, 8, 8)
)

func TestVerdictFor(t *testing.T) {
	cases := []struct {
		name   string
		dport  uint16
		daddr  net.IP
		domain string
		allow  Allower
		want   Verdict
	}{
		// DNS port takes precedence over everything else, including a
		// deny-all policy and loopback destinations.
		{"dns port 53", 53, dnsServer, "", denyAll, VerdictSkipDNS},
		{"dns on loopback (stub resolver)", 53, net.IPv4(127, 0, 0, 53), "", denyAll, VerdictSkipDNS},

		// Loopback boundary values: 127.0.0.0/8 is loopback, neighbours are not.
		{"loopback low", 443, net.IPv4(127, 0, 0, 1), "", denyAll, VerdictSkipLoopback},
		{"loopback high", 443, net.IPv4(127, 255, 255, 255), "", denyAll, VerdictSkipLoopback},
		{"below loopback range", 443, net.IPv4(126, 255, 255, 255), "", allowAll, VerdictAllow},
		{"above loopback range", 443, net.IPv4(128, 0, 0, 1), "", allowAll, VerdictAllow},

		// No policy loaded: everything is allowed.
		{"nil allower", 443, publicIP, "", nil, VerdictAllow},
		{"nil allower with domain", 443, publicIP, "example.com", nil, VerdictAllow},

		// Policy decisions and the DENY reason split on domain presence.
		{"policy allows", 443, publicIP, "example.com", allowAll, VerdictAllow},
		{"policy denies, domain known", 443, publicIP, "evil.example", denyAll, VerdictDenyPolicy},
		{"policy denies, no domain", 443, publicIP, "", denyAll, VerdictDenyNoDomain},

		// Non-53 UDP/TCP ports near the DNS port are not skipped.
		{"port 52", 52, publicIP, "", denyAll, VerdictDenyNoDomain},
		{"port 54", 54, publicIP, "", denyAll, VerdictDenyNoDomain},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := VerdictFor(tc.dport, tc.daddr, tc.domain, tc.allow)
			if got != tc.want {
				t.Errorf("VerdictFor(%d, %s, %q) = %q, want %q",
					tc.dport, tc.daddr, tc.domain, got, tc.want)
			}
		})
	}
}

func TestDst(t *testing.T) {
	if got, want := Dst("example.com", publicIP), "example.com (93.184.216.34)"; got != want {
		t.Errorf("Dst with domain = %q, want %q", got, want)
	}
	if got, want := Dst("", publicIP), "93.184.216.34"; got != want {
		t.Errorf("Dst without domain = %q, want %q", got, want)
	}
}

// TestLineString pins the exact output format; the log line is parsed by
// users and by the planned allowlist-suggestion tooling, so any change here
// is a breaking change.
func TestLineString(t *testing.T) {
	cases := []struct {
		name string
		line Line
		want string
	}{
		{
			"allow with domain",
			Line{Verdict: VerdictAllow, PID: 1234, TGID: 1234, Comm: "curl",
				Dst: "api.github.com (140.82.121.4)", DPort: 443, ConnectMs: 23},
			"verdict=ALLOW                pid=1234   tgid=1234   comm=curl             dst=api.github.com (140.82.121.4):443 connect_ms=23",
		},
		{
			"deny without domain",
			Line{Verdict: VerdictDenyNoDomain, PID: 7, TGID: 7, Comm: "wget",
				Dst: "93.184.216.34", DPort: 80, ConnectMs: 0},
			"verdict=DENY(no-domain)      pid=7      tgid=7      comm=wget             dst=93.184.216.34:80 connect_ms=0",
		},
		{
			"skip dns",
			Line{Verdict: VerdictSkipDNS, PID: 99, TGID: 99, Comm: "systemd-resolve",
				Dst: "127.0.0.53", DPort: 53, ConnectMs: 0},
			"verdict=SKIP(dns)            pid=99     tgid=99     comm=systemd-resolve  dst=127.0.0.53:53 connect_ms=0",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.line.String(); got != tc.want {
				t.Errorf("Line.String() =\n  %q\nwant\n  %q", got, tc.want)
			}
		})
	}
}
