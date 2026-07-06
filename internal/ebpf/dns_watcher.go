//go:build linux

package ebpf

import (
	"encoding/binary"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"syscall"

	"github.com/cilium/ebpf/ringbuf"
	"golang.org/x/sys/unix"
)

// dnsWatcher attaches an eBPF socket_filter to a raw AF_PACKET socket,
// reads DNS response payloads from the ring buffer, and populates a DNSCache.
// In block mode, isAllowed and allow are set so that A/AAAA records resolved
// for allowlisted domains are proactively added to the enforcement allowlist;
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
		resolvers, err := SystemResolvers()
		if err != nil {
			slog.Warn("discover DNS resolvers failed; live DNS allowlisting limited to loopback responses", "error", err)
		}
		w.trustedResolvers = make(map[string]struct{})
		for _, ip := range resolvers {
			// Includes the upstreams behind a systemd-resolved stub: their
			// responses to the stub are what actually appears on the wire, so
			// trusting them is what lets live allowlisting work on stub hosts.
			// IPv6 entries never match today (monitoring observes IPv4 transport
			// only) but are harmless and keep this set in sync with enforcement.
			w.trustedResolvers[ip.String()] = struct{}{}
		}
	}

	go w.run()
	return w, nil
}

func (w *dnsWatcher) run() {
	for {
		record, err := w.reader.Read()
		if err != nil {
			// ringbuf.ErrClosed means Close() was called — a normal shutdown.
			// Anything else silently stopping this loop would freeze the DNS
			// cache and, in block mode, halt live allowlisting: rotating IPs of
			// allowlisted domains would start being denied with no visible
			// cause. Make that failure loud.
			if !errors.Is(err, ringbuf.ErrClosed) {
				slog.Error("DNS watcher stopped unexpectedly; IP-to-domain mapping and live DNS allowlisting halted", "error", err)
			}
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
					slog.Warn("allow resolved IP failed", "ip", ip.String(), "domain", domain, "error", err)
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
