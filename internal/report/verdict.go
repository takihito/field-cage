// Package report computes the policy verdict for captured connection events
// and formats the per-connection log lines emitted by the agent. It has no
// build-tag or eBPF dependency so it can be unit-tested on any platform.
package report

import (
	"fmt"
	"net"
)

// Verdict labels the policy decision for a captured connection event.
// The verdict is observational: in block mode the kernel enforces the
// allowlist directly via the cgroup/connect4 program, and this label
// reflects the policy decision for the captured event.
type Verdict string

const (
	// VerdictAllow marks a connection permitted by the policy (or any
	// connection when no policy is loaded).
	VerdictAllow Verdict = "ALLOW"
	// VerdictSkipDNS marks DNS traffic (port 53), which is excluded from
	// enforcement at the eBPF level so name resolution keeps working.
	VerdictSkipDNS Verdict = "SKIP(dns)"
	// VerdictSkipLoopback marks loopback traffic (127.0.0.0/8), which is
	// excluded from enforcement at the eBPF level.
	VerdictSkipLoopback Verdict = "SKIP(loopback)"
	// VerdictDenyNoDomain marks a denied connection whose destination IP has
	// no resolved domain in the DNS cache.
	VerdictDenyNoDomain Verdict = "DENY(no-domain)"
	// VerdictDenyPolicy marks a denied connection whose resolved domain is
	// not on the allowlist.
	VerdictDenyPolicy Verdict = "DENY(not-in-policy)"
)

// Allower reports whether a domain/IP pair is permitted by the policy.
// *policy.Engine satisfies this interface. A nil Allower means no policy is
// loaded and every connection is allowed.
type Allower interface {
	Allow(domain string, ip net.IP) bool
}

// VerdictFor computes the verdict for a captured connection.
//
// DNS (port 53) and loopback destinations are excluded from enforcement at
// the eBPF level and are labelled SKIP rather than DENY to avoid misleading
// the user into thinking the connection was blocked. domain may be empty if
// DNS resolution has not been observed for the destination IP.
func VerdictFor(dport uint16, daddr net.IP, domain string, allow Allower) Verdict {
	switch {
	case dport == 53:
		return VerdictSkipDNS
	case daddr.IsLoopback():
		return VerdictSkipLoopback
	case allow != nil && !allow.Allow(domain, daddr):
		if domain == "" {
			return VerdictDenyNoDomain
		}
		return VerdictDenyPolicy
	default:
		return VerdictAllow
	}
}

// Dst formats the destination column of a log line: "domain (ip)" when the
// domain is known, otherwise just the IP.
func Dst(domain string, daddr net.IP) string {
	if domain != "" {
		return fmt.Sprintf("%s (%s)", domain, daddr)
	}
	return daddr.String()
}

// Line holds the fields of one per-connection log line.
type Line struct {
	Verdict   Verdict
	PID       uint32
	TGID      uint32
	Comm      string
	Dst       string // pre-formatted destination, see Dst
	DPort     uint16
	ConnectMs uint32
}

// String renders the log line (without a trailing newline) in the agent's
// stable output format:
//
//	verdict=<V> pid=<P> tgid=<T> comm=<C> dst=<domain> (<ip>):<port> connect_ms=<ms>
func (l Line) String() string {
	return fmt.Sprintf("verdict=%-20s pid=%-6d tgid=%-6d comm=%-16s dst=%s:%d connect_ms=%d",
		l.Verdict, l.PID, l.TGID, l.Comm, l.Dst, l.DPort, l.ConnectMs)
}
