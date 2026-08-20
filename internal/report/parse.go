package report

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"unicode"
)

// Field markers of the agent's stable stdout format (see Line.String).
// Parsing locates values by these markers rather than by splitting on
// whitespace: the kernel comm field is an arbitrary 16-byte string and may
// itself contain spaces.
const (
	prefixVerdict = "verdict="
	fieldPID      = " pid="
	fieldTGID     = " tgid="
	fieldComm     = " comm="
	fieldDst      = " dst="
)

// Length caps for log-derived values: 253 is the maximum length of a DNS name,
// 16 is the size of the kernel comm field.
const (
	maxDomainLen = 253
	maxCommLen   = 16
	maxModeLen   = 64
)

// scanBufferMax bounds a single log line so a corrupted or hostile log cannot
// make the scanner allocate without limit.
const scanBufferMax = 1 << 20

// Event is one parsed per-connection log line. It is the inverse of Line:
// Line renders the agent's stdout format, Event recovers its fields for
// aggregation and reporting.
//
// Domain and Comm are sanitised at parse time (see sanitize): they originate
// from DNS responses and the kernel comm field and are therefore
// attacker-influenced. Removing control characters here is a precondition for
// the format-specific escaping the renderers apply.
type Event struct {
	Verdict Verdict
	PID     uint32
	TGID    uint32
	Comm    string
	Domain  string // empty when no DNS resolution was observed
	IP      net.IP
	Port    uint16
}

// Destination returns the domain when one was resolved, otherwise the IP.
func (e Event) Destination() string {
	if e.Domain != "" {
		return e.Domain
	}
	return e.IPString()
}

// IPString renders the destination IP, or "" when it is unset.
func (e Event) IPString() string {
	if e.IP == nil {
		return ""
	}
	return e.IP.String()
}

// ParseLine parses one agent verdict line back into an Event. Lines that are
// not verdict lines (the agent's slog diagnostics share the log file when
// stderr is redirected into it) return an error and are skipped by ScanLog.
func ParseLine(line string) (Event, error) {
	s := strings.TrimRight(line, "\r\n")
	if !strings.HasPrefix(s, prefixVerdict) {
		return Event{}, fmt.Errorf("not a verdict line")
	}
	// dst is the final field, so LastIndex is used: a crafted comm containing
	// " dst=" must not truncate the line early.
	dstAt := strings.LastIndex(s, fieldDst)
	if dstAt < 0 {
		return Event{}, fmt.Errorf("missing dst field")
	}
	head, dst := s[:dstAt], s[dstAt+len(fieldDst):]

	verdict, rest, err := cutField(head, prefixVerdict, fieldPID)
	if err != nil {
		return Event{}, err
	}
	pidStr, rest, err := cutField(rest, fieldPID, fieldTGID)
	if err != nil {
		return Event{}, err
	}
	tgidStr, rest, err := cutField(rest, fieldTGID, fieldComm)
	if err != nil {
		return Event{}, err
	}
	if !strings.HasPrefix(rest, fieldComm) {
		return Event{}, fmt.Errorf("missing comm field")
	}
	comm := strings.TrimSpace(rest[len(fieldComm):])

	pid, err := strconv.ParseUint(pidStr, 10, 32)
	if err != nil {
		return Event{}, fmt.Errorf("invalid pid %q: %w", pidStr, err)
	}
	tgid, err := strconv.ParseUint(tgidStr, 10, 32)
	if err != nil {
		return Event{}, fmt.Errorf("invalid tgid %q: %w", tgidStr, err)
	}
	domain, ip, port, err := parseDst(dst)
	if err != nil {
		return Event{}, err
	}
	if verdict == "" {
		return Event{}, fmt.Errorf("empty verdict")
	}

	return Event{
		Verdict: Verdict(sanitize(verdict, maxDomainLen)),
		PID:     uint32(pid),
		TGID:    uint32(tgid),
		Comm:    sanitize(comm, maxCommLen),
		Domain:  sanitize(domain, maxDomainLen),
		IP:      ip,
		Port:    port,
	}, nil
}

// cutField extracts the value introduced by key and stops at the next field
// marker, returning the remainder starting at that marker.
func cutField(s, key, next string) (value, remainder string, err error) {
	if !strings.HasPrefix(s, key) {
		return "", "", fmt.Errorf("missing %s field", strings.TrimSpace(strings.TrimSuffix(key, "=")))
	}
	s = s[len(key):]
	i := strings.Index(s, next)
	if i < 0 {
		return "", "", fmt.Errorf("missing %s field", strings.TrimSpace(strings.TrimSuffix(next, "=")))
	}
	return strings.TrimSpace(s[:i]), s[i:], nil
}

// parseDst parses the destination column, which Dst renders either as
// "domain (ip):port" or as "ip:port". The port is always the trailing
// component, so splitting at the last colon also resolves the bare IPv6 form
// ("2001:db8::1:443") unambiguously.
func parseDst(s string) (domain string, ip net.IP, port uint16, err error) {
	s = strings.TrimSpace(s)
	colon := strings.LastIndex(s, ":")
	if colon < 0 {
		return "", nil, 0, fmt.Errorf("dst %q: missing port", s)
	}
	p, err := strconv.ParseUint(s[colon+1:], 10, 16)
	if err != nil {
		return "", nil, 0, fmt.Errorf("dst %q: invalid port: %w", s, err)
	}
	addr := s[:colon]
	if strings.HasSuffix(addr, ")") {
		if open := strings.LastIndex(addr, " ("); open >= 0 {
			domain = addr[:open]
			addr = addr[open+len(" (") : len(addr)-1]
		}
	}
	if ip = net.ParseIP(addr); ip == nil {
		return "", nil, 0, fmt.Errorf("dst %q: invalid IP %q", s, addr)
	}
	return domain, ip, uint16(p), nil
}

// modeLineMarker identifies the agent's startup diagnostic, which carries the
// effective mode. The agent writes it to stderr; the action redirects stderr
// into the same log file, so the report can recover the mode from there.
const modeLineMarker = `msg="watching outbound connections`

// parseModeLine extracts the mode from the agent's startup diagnostic, e.g.
// `... msg="watching outbound connections (Ctrl+C to stop)" version=v0.1.0 mode="audit (no policy)"`.
func parseModeLine(line string) (string, bool) {
	if !strings.Contains(line, modeLineMarker) {
		return "", false
	}
	const key = " mode="
	i := strings.Index(line, key)
	if i < 0 {
		return "", false
	}
	v := line[i+len(key):]
	if strings.HasPrefix(v, `"`) {
		v = v[1:]
		if j := strings.Index(v, `"`); j >= 0 {
			v = v[:j]
		}
	} else if j := strings.IndexByte(v, ' '); j >= 0 {
		v = v[:j]
	}
	v = sanitize(strings.TrimSpace(v), maxModeLen)
	return v, v != ""
}

// ScanLog reads an agent log and passes every verdict line to fn. Non-verdict
// lines are ignored except for the startup diagnostic, from which the mode is
// recovered. Verdict lines that fail to parse are counted as malformed rather
// than aborting the scan, so a single corrupted line cannot hide the rest of
// the report.
func ScanLog(r io.Reader, fn func(Event) error) (mode string, malformed int, err error) {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), scanBufferMax)
	for sc.Scan() {
		line := sc.Text()
		if strings.HasPrefix(line, prefixVerdict) {
			ev, perr := ParseLine(line)
			if perr != nil {
				malformed++
				continue
			}
			if fn != nil {
				if ferr := fn(ev); ferr != nil {
					return mode, malformed, ferr
				}
			}
			continue
		}
		if m, ok := parseModeLine(line); ok && mode == "" {
			mode = m
		}
	}
	if serr := sc.Err(); serr != nil {
		return mode, malformed, fmt.Errorf("read log: %w", serr)
	}
	return mode, malformed, nil
}

// sanitize replaces non-printable runes (including invalid UTF-8) with '?' and
// truncates the value to max runes. Values are replaced rather than dropped so
// that tampering stays visible instead of silently collapsing, e.g., a domain
// containing a newline into one plausible-looking name.
func sanitize(s string, max int) string {
	var b strings.Builder
	n := 0
	for _, r := range s {
		if n >= max {
			break
		}
		if r == '�' || !unicode.IsPrint(r) {
			b.WriteByte('?')
		} else {
			b.WriteRune(r)
		}
		n++
	}
	return b.String()
}
