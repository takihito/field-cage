//go:build linux

package ebpf

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
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
type dnsWatcher struct {
	objs   DnsObjects
	fd     int
	reader *ringbuf.Reader
	cache  *DNSCache
}

func newDNSWatcher(cache *DNSCache) (*dnsWatcher, error) {
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

	w := &dnsWatcher{objs: objs, fd: fd, reader: reader, cache: cache}
	go w.run()
	return w, nil
}

func (w *dnsWatcher) run() {
	for {
		record, err := w.reader.Read()
		if err != nil {
			return
		}
		if len(record.RawSample) < 4 {
			continue
		}
		length := binary.NativeEndian.Uint32(record.RawSample[:4])
		if length == 0 || int(length) > len(record.RawSample)-4 {
			continue
		}
		payload := record.RawSample[4 : 4+length]
		domain, ips := parseDNSResponse(payload)
		if domain == "" {
			continue
		}
		for _, ip := range ips {
			w.cache.set(ip, domain)
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
