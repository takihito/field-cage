//go:build linux

package ebpf

import (
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"strings"
	"sync"
	"syscall"

	"github.com/cilium/ebpf/ringbuf"
	"golang.org/x/sys/unix"
)

// DNSCache maps IPv4 addresses to the domain name resolved to that address.
// It is safe for concurrent use.
type DNSCache struct {
	mu      sync.RWMutex
	entries map[string]string // net.IP.String() → domain
}

func newDNSCache() *DNSCache {
	return &DNSCache{entries: make(map[string]string)}
}

// Lookup returns the domain name for the given IP, or an empty string.
func (c *DNSCache) Lookup(ip net.IP) string {
	c.mu.RLock()
	v := c.entries[ip.String()]
	c.mu.RUnlock()
	return v
}

func (c *DNSCache) set(ip net.IP, domain string) {
	c.mu.Lock()
	c.entries[ip.String()] = domain
	c.mu.Unlock()
}

// dnsWatcher attaches an eBPF socket_filter to a raw AF_PACKET socket,
// reads DNS response payloads from the ring buffer, and populates a DNSCache.
// In block mode, isAllowed and allow are set so that A records resolved for
// allowlisted domains are proactively added to the enforcement allowlist;
// both are nil in audit mode. trustedResolvers holds the nameserver IPs that
// responses must originate from before they are trusted for allowlisting
// (loopback is always trusted); it is only consulted when allow is non-nil.
type dnsWatcher struct {
	objs             DnsObjects
	fd               int
	reader           *ringbuf.Reader
	cache            *DNSCache
	isAllowed        func(domain string) bool
	allow            func(ip net.IP) error
	trustedResolvers map[string]struct{}
}

func newDNSWatcher(cache *DNSCache, isAllowed func(string) bool, allow func(net.IP) error) (*dnsWatcher, error) {
	var objs DnsObjects
	if err := LoadDnsObjects(&objs, nil); err != nil {
		return nil, fmt.Errorf("load DNS eBPF objects: %w", err)
	}

	// AF_PACKET raw socket — requires CAP_NET_RAW.
	// Protocol ETH_P_IP (0x0800) must be in network byte order.
	proto := int(htons(syscall.ETH_P_IP))
	fd, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW, proto)
	if err != nil {
		objs.Close()
		return nil, fmt.Errorf("create raw socket: %w", err)
	}

	if err := syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, unix.SO_ATTACH_BPF, objs.CaptureDns.FD()); err != nil {
		syscall.Close(fd) //nolint:errcheck
		objs.Close()
		return nil, fmt.Errorf("attach DNS socket filter: %w", err)
	}

	reader, err := ringbuf.NewReader(objs.DnsEvents)
	if err != nil {
		syscall.Close(fd) //nolint:errcheck
		objs.Close()
		return nil, fmt.Errorf("open DNS ringbuf reader: %w", err)
	}

	w := &dnsWatcher{objs: objs, fd: fd, reader: reader, cache: cache, isAllowed: isAllowed, allow: allow}

	// Block mode only: determine which resolver source IPs are trusted for
	// allowlisting. Responses from any other source (e.g. forged packets with a
	// spoofed source port 53) are still cached for logging but never extend the
	// kernel allowlist.
	if allow != nil {
		data, err := os.ReadFile("/etc/resolv.conf")
		if err != nil {
			log.Printf("field-cage: read /etc/resolv.conf failed; live DNS allowlisting limited to loopback responses: %v", err)
		}
		w.trustedResolvers = parseResolvConf(data)
	}

	go w.run()
	return w, nil
}

func (w *dnsWatcher) run() {
	for {
		record, err := w.reader.Read()
		if err != nil {
			return
		}
		// Wire layout (see struct dns_event in bpf/dns.c):
		//   [0:4]  len (native endian)   [4:8]  source IPv4 (network order)
		//   [8:8+len] DNS payload
		if len(record.RawSample) < 8 {
			continue
		}
		length := binary.NativeEndian.Uint32(record.RawSample[:4])
		if length == 0 || int(length) > len(record.RawSample)-8 {
			continue
		}
		srcIP := make(net.IP, 4)
		copy(srcIP, record.RawSample[4:8])
		payload := record.RawSample[8 : 8+length]
		domain, ips := parseDNSResponse(payload)
		if domain == "" {
			continue
		}
		// Only extend the kernel allowlist from responses that (a) resolve an
		// allowlisted domain and (b) originate from a trusted resolver. This
		// prevents a forged DNS response (spoofed source port 53) from poisoning
		// the allowlist and bypassing default-deny enforcement.
		allowDomain := w.allow != nil && w.isAllowed != nil &&
			w.isAllowed(domain) && isTrustedSourceIP(srcIP, w.trustedResolvers)
		for _, ip := range ips {
			w.cache.set(ip, domain)
			// In block mode, proactively permit IPs for allowlisted domains so the
			// application's subsequent connection is not denied. The DNS response
			// is observed on the wire before the application connects, so this
			// usually wins the race; if not, the first connection fails closed and
			// the application's retry succeeds once the map is updated.
			if allowDomain {
				if err := w.allow(ip); err != nil {
					log.Printf("field-cage: allow resolved IP %s for %s: %v", ip, domain, err)
				}
			}
		}
	}
}

func (w *dnsWatcher) Close() error {
	var errs []error
	if err := w.reader.Close(); err != nil {
		errs = append(errs, fmt.Errorf("dns reader: %w", err))
	}
	if err := syscall.Close(w.fd); err != nil {
		errs = append(errs, fmt.Errorf("dns socket: %w", err))
	}
	w.objs.Close()
	return errors.Join(errs...)
}

// htons converts a uint16 from host byte order to network byte order.
func htons(v uint16) uint16 {
	var b [2]byte
	binary.BigEndian.PutUint16(b[:], v)
	return binary.NativeEndian.Uint16(b[:])
}

// parseResolvConf extracts the IPv4 nameserver addresses from /etc/resolv.conf
// contents. These are the resolver source IPs trusted for live allowlisting.
func parseResolvConf(data []byte) map[string]struct{} {
	set := make(map[string]struct{})
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 || fields[0] != "nameserver" {
			continue
		}
		if ip := net.ParseIP(fields[1]); ip != nil {
			if ip4 := ip.To4(); ip4 != nil {
				set[ip4.String()] = struct{}{}
			}
		}
	}
	return set
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
// name and the list of IPv4 addresses from A records in the answer section.
// Returns empty values if the message is not a valid DNS response.
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

	// Parse answer section and collect A records.
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
		if rtype == 1 && rdlen == 4 { // A record
			ip := make(net.IP, 4)
			copy(ip, data[offset:offset+4])
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
