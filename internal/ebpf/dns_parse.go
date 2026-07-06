package ebpf

import (
	"encoding/binary"
	"net"
	"os"
	"strings"
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
// section. Returns empty values if the message is not a valid DNS response.
func parseDNSResponse(data []byte) (domain string, ips []net.IP) {
	if len(data) < 12 {
		return "", nil
	}

	// Flags: bit 15 = QR (1 = response), bits 14-11 = opcode (0 = QUERY)
	flags := binary.BigEndian.Uint16(data[2:4])
	if flags&0x8000 == 0 {
		return "", nil // not a response
	}

	qdcount := int(binary.BigEndian.Uint16(data[4:6]))
	ancount := int(binary.BigEndian.Uint16(data[6:8]))

	offset := 12

	// Parse question section to extract the queried domain name.
	for i := 0; i < qdcount; i++ {
		name, n, ok := readDNSName(data, offset)
		if !ok {
			return "", nil
		}
		if i == 0 {
			domain = name
		}
		offset = n + 4 // skip QTYPE (2 bytes) + QCLASS (2 bytes)
	}

	// Parse answer section and collect A and AAAA records.
	for i := 0; i < ancount; i++ {
		_, n, ok := readDNSName(data, offset)
		if !ok {
			break
		}
		offset = n
		if offset+10 > len(data) {
			break
		}
		rtype := binary.BigEndian.Uint16(data[offset : offset+2])
		rdlen := int(binary.BigEndian.Uint16(data[offset+8 : offset+10]))
		offset += 10
		if offset+rdlen > len(data) {
			break
		}
		switch {
		case rtype == 1 && rdlen == 4: // A record
			ip := make(net.IP, 4)
			copy(ip, data[offset:offset+4])
			ips = append(ips, ip)
		case rtype == 28 && rdlen == 16: // AAAA record
			ip := make(net.IP, 16)
			copy(ip, data[offset:offset+16])
			ips = append(ips, ip)
		}
		offset += rdlen
	}

	return domain, ips
}

// readDNSName reads a DNS name (with compression pointer support) starting at
// offset. Returns the name, the offset after the name in the original message,
// and whether parsing succeeded.
func readDNSName(data []byte, offset int) (string, int, bool) {
	var labels []string
	finalOffset := -1
	visited := 0 // guard against pointer loops

	for {
		if offset >= len(data) || visited > 128 {
			return "", 0, false
		}
		visited++

		length := int(data[offset])
		if length == 0 {
			offset++
			break
		}

		if length&0xC0 == 0xC0 { // compression pointer
			if offset+1 >= len(data) {
				return "", 0, false
			}
			if finalOffset == -1 {
				finalOffset = offset + 2
			}
			ptr := int(binary.BigEndian.Uint16(data[offset:offset+2]) & 0x3FFF)
			offset = ptr
			continue
		}

		offset++
		if offset+length > len(data) {
			return "", 0, false
		}
		labels = append(labels, string(data[offset:offset+length]))
		offset += length
	}

	if finalOffset != -1 {
		offset = finalOffset
	}
	return strings.Join(labels, "."), offset, true
}
