package ebpf

import (
	"encoding/binary"
	"net"
	"os"
	"strings"

	"golang.org/x/net/dns/dnsmessage"
)

// htons converts a uint16 from host byte order to network byte order.
func htons(v uint16) uint16 {
	var b [2]byte
	binary.BigEndian.PutUint16(b[:], v)
	return binary.NativeEndian.Uint16(b[:])
}

// systemdUpstreamResolvConf is the resolv.conf maintained by systemd-resolved
// listing the real upstream nameservers. When /etc/resolv.conf points at the
// local stub (127.0.0.53), the stub's own outbound DNS goes to these servers.
const systemdUpstreamResolvConf = "/run/systemd/resolve/resolv.conf"

// SystemResolvers returns the nameserver IPs the host is configured to use,
// for both port-53 enforcement and DNS-response source validation. It parses
// /etc/resolv.conf; when that yields only loopback stub entries (e.g.
// systemd-resolved's 127.0.0.53), the stub's upstream servers from
// /run/systemd/resolve/resolv.conf are included as well — under root-cgroup
// enforcement the stub daemon's own outbound queries are subject to the same
// port-53 restriction, so its upstreams must be permitted or resolution
// through the stub would fail. The returned error reports an unreadable
// /etc/resolv.conf; the upstream file is optional and read best-effort.
func SystemResolvers() ([]net.IP, error) {
	etc, err := os.ReadFile("/etc/resolv.conf")
	if err != nil {
		return nil, err
	}
	run, _ := os.ReadFile(systemdUpstreamResolvConf) // absent on non-systemd hosts
	return resolversFrom(etc, run), nil
}

// resolversFrom merges nameserver entries from /etc/resolv.conf contents and,
// when the former contains only loopback entries (or none), from the
// systemd-resolved upstream resolv.conf contents. Duplicates are removed.
func resolversFrom(etc, run []byte) []net.IP {
	ips := parseResolvConf(etc)
	onlyLoopback := true
	for _, ip := range ips {
		if !ip.IsLoopback() {
			onlyLoopback = false
			break
		}
	}
	if onlyLoopback {
		ips = append(ips, parseResolvConf(run)...)
	}
	seen := make(map[string]struct{}, len(ips))
	out := ips[:0]
	for _, ip := range ips {
		if _, dup := seen[ip.String()]; dup {
			continue
		}
		seen[ip.String()] = struct{}{}
		out = append(out, ip)
	}
	return out
}

// parseResolvConf extracts the nameserver IP addresses (IPv4 and IPv6) from
// resolv.conf-format contents.
func parseResolvConf(data []byte) []net.IP {
	var ips []net.IP
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 || fields[0] != "nameserver" {
			continue
		}
		host := strings.TrimSuffix(strings.TrimPrefix(fields[1], "["), "]")
		// Strip an IPv6 zone suffix (e.g. "fe80::1%eth0"): net.ParseIP rejects
		// it, and the zone is carried in sin6_scope_id rather than the address,
		// so the plain address is what enforcement and source matching need.
		if i := strings.IndexByte(host, '%'); i >= 0 {
			host = host[:i]
		}
		if ip := net.ParseIP(host); ip != nil {
			ips = append(ips, ip)
		}
	}
	return ips
}

// isTrustedSourceIP reports whether a DNS response from the given source IP may
// be trusted to extend the allowlist. Loopback is always trusted (stub
// resolvers such as systemd-resolved answer from 127.0.0.0/8); otherwise the
// source must be one of the configured nameservers. Binding source port 53 or
// spoofing a source IP both require elevated capabilities, so this confines
// allowlist extension to legitimate resolver traffic in the common case.
func isTrustedSourceIP(ip net.IP, trusted map[string]struct{}) bool {
	if ip == nil {
		return false
	}
	if ip.IsLoopback() {
		return true
	}
	ip4 := ip.To4()
	if ip4 == nil {
		return false
	}
	_, ok := trusted[ip4.String()]
	return ok
}

// parseDNSResponse parses a raw DNS response and returns the queried domain
// name and the list of IP addresses from A and AAAA records in the answer
// section. Returns empty values if the message is not a valid DNS response or
// carries no question to attribute the answers to.
//
// Parsing is delegated to golang.org/x/net/dns/dnsmessage — the same wire
// parser the standard library's net package uses internally — rather than a
// hand-rolled one, because this input arrives on the wire and may be attacker
// controlled (a forged response with a spoofed source port 53). The library
// handles name compression, bounds checking, and malformed input robustly.
func parseDNSResponse(data []byte) (domain string, ips []net.IP) {
	var p dnsmessage.Parser
	hdr, err := p.Start(data)
	if err != nil {
		return "", nil
	}
	if !hdr.Response {
		return "", nil // a query, not a response
	}

	// Extract the queried name from the first question, then skip the rest so
	// the parser advances to the answer section. Without a question there is no
	// domain to attribute the answers to; the caller drops empty-domain results.
	q, err := p.Question()
	if err != nil {
		return "", nil
	}
	// Name.String() renders as a fully qualified name with a trailing dot
	// (e.g. "example.com."); strip it to match the cache/policy key format.
	domain = strings.TrimSuffix(q.Name.String(), ".")
	if err := p.SkipAllQuestions(); err != nil {
		return "", nil // malformed question section: not a valid response
	}

	for {
		h, err := p.AnswerHeader()
		if err != nil {
			break // ErrSectionDone or malformed: stop collecting
		}
		switch {
		case h.Type == dnsmessage.TypeA && h.Length == net.IPv4len:
			r, err := p.AResource()
			if err != nil {
				return domain, ips
			}
			ip := make(net.IP, net.IPv4len)
			copy(ip, r.A[:])
			ips = append(ips, ip)
		case h.Type == dnsmessage.TypeAAAA && h.Length == net.IPv6len:
			r, err := p.AAAAResource()
			if err != nil {
				return domain, ips
			}
			ip := make(net.IP, net.IPv6len)
			copy(ip, r.AAAA[:])
			ips = append(ips, ip)
		default:
			// Also covers A/AAAA records with an RDLENGTH that doesn't match the
			// fixed record size: AResource/AAAAResource read a fixed number of
			// bytes regardless of the declared length, so skip rather than risk
			// misreading adjacent record bytes as an address.
			if err := p.SkipAnswer(); err != nil {
				return domain, ips
			}
		}
	}

	return domain, ips
}
