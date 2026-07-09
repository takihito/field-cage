//go:build linux

package ebpf

import (
	"errors"
	"fmt"
	"log/slog"
	"net"

	ciliumebpf "github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

// Watcher attaches to the sys_enter_connect and sys_exit_connect tracepoints
// and streams Events. It also runs a DNS cache that annotates events with
// resolved domain names. When blockObjs is non-nil, AllowIP populates the
// allowlist enforced by the cgroup/connect4 program (default-deny).
type Watcher struct {
	objs        ConnectObjects
	tp          link.Link // sys_enter_connect
	tpExit      link.Link // sys_exit_connect
	reader      *ringbuf.Reader
	dnsCache    *DNSCache
	dnsWatcher  *dnsWatcher
	blockObjs   *BlockObjects
	cgroupLink  link.Link // cgroup/connect4
	cgroupLink6 link.Link // cgroup/connect6

	// malformed counts ring buffer records dropped by Read because they failed
	// to parse. Only touched from Read, which is called from a single
	// goroutine, so no synchronization is needed.
	malformed uint64
}

// NewWatcher loads the eBPF program and attaches it to the tracepoint.
// The caller must call Close when done.
func NewWatcher() (*Watcher, error) {
	return newWatcher("", nil, nil)
}

// NewBlockWatcher is like NewWatcher but also loads the cgroup/connect4 and
// cgroup/connect6 enforcement programs, which deny every outbound connection
// by default (allowlist model). Use AllowIP to seed the permitted-IP set;
// observed DNS responses for domains accepted by isAllowedDomain are added
// automatically.
// cgroupPath is the path to a writable cgroup v2 directory
// (e.g. "/sys/fs/cgroup"). isAllowedDomain reports whether a resolved domain is
// on the allowlist; it may be nil, in which case only seeded IPs are permitted.
// resolvers are the system nameservers (from SystemResolvers), discovered once
// by the caller and shared across port-53 seeding and DNS-response source
// validation; it may be nil, in which case only loopback DNS is trusted.
func NewBlockWatcher(cgroupPath string, isAllowedDomain func(string) bool, resolvers []net.IP) (*Watcher, error) {
	return newWatcher(cgroupPath, isAllowedDomain, resolvers)
}

func newWatcher(cgroupPath string, isAllowedDomain func(string) bool, resolvers []net.IP) (w *Watcher, err error) {
	withBlock := cgroupPath != ""

	// Cleanup stack: every successfully acquired resource pushes its release
	// function; on any subsequent error the deferred unwind closes them in
	// reverse order. This makes it impossible to leak an earlier resource by
	// forgetting it on a later error path (which has bitten us before — the
	// sys_exit_connect tracepoint was once leaked exactly this way).
	var cleanups []func()
	defer func() {
		if err != nil {
			for i := len(cleanups) - 1; i >= 0; i-- {
				cleanups[i]()
			}
		}
	}()

	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, fmt.Errorf("remove memlock rlimit: %w", err)
	}

	var objs ConnectObjects
	if err := LoadConnectObjects(&objs, nil); err != nil {
		return nil, fmt.Errorf("load eBPF objects: %w", err)
	}
	cleanups = append(cleanups, func() { objs.Close() })

	tp, err := link.Tracepoint("syscalls", "sys_enter_connect", objs.TraceConnectEnter, nil)
	if err != nil {
		return nil, fmt.Errorf("attach tracepoint syscalls/sys_enter_connect: %w", err)
	}
	cleanups = append(cleanups, func() { tp.Close() }) //nolint:errcheck

	tpExit, err := link.Tracepoint("syscalls", "sys_exit_connect", objs.TraceConnectExit, nil)
	if err != nil {
		return nil, fmt.Errorf("attach tracepoint syscalls/sys_exit_connect: %w", err)
	}
	cleanups = append(cleanups, func() { tpExit.Close() }) //nolint:errcheck

	reader, err := ringbuf.NewReader(objs.Events)
	if err != nil {
		return nil, fmt.Errorf("open ringbuf reader: %w", err)
	}
	cleanups = append(cleanups, func() { reader.Close() }) //nolint:errcheck

	cache := newDNSCache()
	w = &Watcher{objs: objs, tp: tp, tpExit: tpExit, reader: reader, dnsCache: cache}

	// Attach the enforcement program before starting the DNS watcher so that
	// AllowIP can populate the allowlist as soon as DNS responses arrive.
	if withBlock {
		if err := w.attachBlock(cgroupPath); err != nil {
			return nil, fmt.Errorf("attach block program: %w", err)
		}
		cleanups = append(cleanups, func() {
			w.cgroupLink6.Close() //nolint:errcheck
			w.cgroupLink.Close()  //nolint:errcheck
			w.blockObjs.Close()
		})
		// Seed trusted resolver IPs so DNS (port 53) is permitted to them under
		// default-deny. Loopback resolvers are already covered by the loopback
		// rule; if no resolvers are found only loopback DNS works (fail-closed).
		w.seedResolvers(resolvers)
	}

	// In block mode, observed DNS responses for allowlisted domains are added to
	// the enforcement map proactively (before the application connects).
	var onAllowedIP func(net.IP) error
	if withBlock {
		onAllowedIP = w.AllowIP
	}
	dw, err := newDNSWatcher(cache, isAllowedDomain, onAllowedIP, resolvers)
	if err != nil {
		if withBlock {
			// In block mode the allowlist is keyed on domain names resolved from
			// DNS responses. Without DNS capture only the IPs seeded at startup
			// could ever be permitted, so any domain whose address rotates (CDNs,
			// round-robin) would be denied. Fail loudly rather than silently
			// mis-enforcing policy.
			return nil, fmt.Errorf(
				"DNS capture is required in block mode but could not start: %w\n"+
					"  Possible causes:\n"+
					"    - missing CAP_NET_RAW capability (run with sudo or grant the capability)\n"+
					"    - AF_PACKET socket creation denied by seccomp/AppArmor\n"+
					"  Without DNS capture only IPs seeded at startup would be permitted and\n"+
					"  domains whose addresses rotate would be denied.", err)
		}
		// In audit mode DNS capture is best-effort: connections are still logged
		// with their IP addresses and the agent continues running.
		slog.Warn("DNS capture unavailable; connections will show IPs only (audit mode)", "error", err)
		dw = nil
	}
	w.dnsWatcher = dw
	return w, nil
}

// attachBlock loads the cgroup/connect4 and cgroup/connect6 eBPF programs and
// attaches them to the given cgroup path so they can block unauthorized
// connections system-wide for both address families.
func (w *Watcher) attachBlock(cgroupPath string) error {
	var blockObjs BlockObjects
	if err := LoadBlockObjects(&blockObjs, nil); err != nil {
		return fmt.Errorf("load block eBPF objects: %w", err)
	}

	cg, err := link.AttachCgroup(link.CgroupOptions{
		Path:    cgroupPath,
		Attach:  ciliumebpf.AttachCGroupInet4Connect,
		Program: blockObjs.BlockConnect,
	})
	if err != nil {
		blockObjs.Close()
		return fmt.Errorf("attach cgroup/connect4: %w", err)
	}

	cg6, err := link.AttachCgroup(link.CgroupOptions{
		Path:    cgroupPath,
		Attach:  ciliumebpf.AttachCGroupInet6Connect,
		Program: blockObjs.BlockConnect6,
	})
	if err != nil {
		cg.Close() //nolint:errcheck
		blockObjs.Close()
		return fmt.Errorf("attach cgroup/connect6: %w", err)
	}

	w.blockObjs = &blockObjs
	w.cgroupLink = cg
	w.cgroupLink6 = cg6
	return nil
}

// lpmKey is the key for the IPv4 allowed_ips LPM trie.
// Layout must match the C struct lpm_key in bpf/block.c:
//
//	{ __u32 prefixlen; __u8 addr[4]; }
type lpmKey struct {
	Prefixlen uint32
	Addr      [4]byte
}

// lpmKey6 is the key for the IPv6 allowed_ips6 LPM trie.
// Layout must match the C struct lpm_key6 in bpf/block.c:
//
//	{ __u32 prefixlen; __u8 addr[16]; }
type lpmKey6 struct {
	Prefixlen uint32
	Addr      [16]byte
}

// AllowIP adds a single IP address (/32 or /128) to the enforcement LPM trie
// for its address family, permitting outbound connections to it under the
// default-deny enforcement program. IPv4 addresses (including IPv4-mapped
// IPv6) go to the IPv4 trie — the connect6 program consults it for
// IPv4-mapped destinations, so one entry covers both socket families. It is a
// no-op for nil/invalid addresses or if the watcher was not created with
// NewBlockWatcher.
func (w *Watcher) AllowIP(ip net.IP) error {
	if w.blockObjs == nil || ip == nil {
		return nil
	}
	if ip4 := ip.To4(); ip4 != nil {
		key := lpmKey{Prefixlen: 32, Addr: [4]byte{ip4[0], ip4[1], ip4[2], ip4[3]}}
		var val uint8 = 1
		if err := w.blockObjs.AllowedIps.Put(key, val); err != nil {
			return fmt.Errorf("add allowed IP %s: %w", ip, err)
		}
		return nil
	}
	ip16 := ip.To16()
	if ip16 == nil {
		return nil
	}
	key := lpmKey6{Prefixlen: 128}
	copy(key.Addr[:], ip16)
	var val uint8 = 1
	if err := w.blockObjs.AllowedIps6.Put(key, val); err != nil {
		return fmt.Errorf("add allowed IPv6 %s: %w", ip, err)
	}
	return nil
}

// AllowCIDR adds a CIDR range to the enforcement LPM trie for its address
// family, permitting all addresses within the subnet. It is a no-op for nil
// networks or if the watcher was not created with NewBlockWatcher.
func (w *Watcher) AllowCIDR(cidr *net.IPNet) error {
	if cidr == nil || w.blockObjs == nil {
		return nil
	}
	ones, _ := cidr.Mask.Size()
	if ip4 := cidr.IP.To4(); ip4 != nil {
		key := lpmKey{Prefixlen: uint32(ones), Addr: [4]byte{ip4[0], ip4[1], ip4[2], ip4[3]}}
		var val uint8 = 1
		if err := w.blockObjs.AllowedIps.Put(key, val); err != nil {
			return fmt.Errorf("add allowed CIDR %s: %w", cidr, err)
		}
		return nil
	}
	ip16 := cidr.IP.To16()
	if ip16 == nil {
		return nil
	}
	key := lpmKey6{Prefixlen: uint32(ones)}
	copy(key.Addr[:], ip16)
	var val uint8 = 1
	if err := w.blockObjs.AllowedIps6.Put(key, val); err != nil {
		return fmt.Errorf("add allowed IPv6 CIDR %s: %w", cidr, err)
	}
	return nil
}

// AllowResolver permits port-53 (DNS) connections to the given resolver IP
// under default-deny enforcement. IPv4 (and IPv4-mapped IPv6) addresses go to
// the dns_resolvers set; IPv6 to dns_resolvers6. It is a no-op for nil
// addresses or if the watcher was not created with NewBlockWatcher. Loopback
// resolvers need not be seeded — the program always permits loopback.
func (w *Watcher) AllowResolver(ip net.IP) error {
	if w.blockObjs == nil || ip == nil {
		return nil
	}
	var val uint8 = 1
	if ip4 := ip.To4(); ip4 != nil {
		var key [4]byte
		copy(key[:], ip4)
		if err := w.blockObjs.DnsResolvers.Put(key, val); err != nil {
			return fmt.Errorf("add DNS resolver %s: %w", ip, err)
		}
		return nil
	}
	ip16 := ip.To16()
	if ip16 == nil {
		return nil
	}
	var key [16]byte
	copy(key[:], ip16)
	if err := w.blockObjs.DnsResolvers6.Put(key, val); err != nil {
		return fmt.Errorf("add DNS resolver (v6) %s: %w", ip, err)
	}
	return nil
}

// SetAllowAllDNS toggles the allow_all_dns opt-in in the enforcement config
// map. When enabled, any port-53 destination is permitted (legacy behavior);
// when disabled (the default), only trusted resolvers and loopback are
// permitted on port 53. No-op if not created with NewBlockWatcher.
func (w *Watcher) SetAllowAllDNS(enabled bool) error {
	if w.blockObjs == nil {
		return nil
	}
	var idx uint32
	var val uint8
	if enabled {
		val = 1
	}
	if err := w.blockObjs.Config.Put(idx, val); err != nil {
		return fmt.Errorf("set allow_all_dns=%v: %w", enabled, err)
	}
	return nil
}

// seedResolvers permits DNS (port 53) to each configured non-loopback
// nameserver, including the upstream servers behind a systemd-resolved
// loopback stub (see SystemResolvers) — the stub daemon's own outbound
// queries fall under root-cgroup enforcement, so its upstreams must be
// permitted or resolution through the stub would fail. The nameserver set is
// discovered once by the caller and passed in. When it contains no non-loopback
// nameserver (the set is empty, or holds only loopback stub entries), nothing
// is seeded and only loopback DNS is permitted (fail-closed); this is logged so
// a broken name-resolution setup can be diagnosed.
func (w *Watcher) seedResolvers(resolvers []net.IP) {
	seeded := 0
	for _, ip := range resolvers {
		if ip.IsLoopback() {
			continue // loopback is always permitted by the program
		}
		if err := w.AllowResolver(ip); err != nil {
			slog.Warn("seed DNS resolver failed", "resolver", ip.String(), "error", err)
			continue
		}
		seeded++
	}
	if seeded == 0 {
		slog.Warn("no non-loopback nameservers discovered; " +
			"only loopback DNS is permitted under block mode (set allow_all_dns: true to relax)")
	}
}

// Read blocks until a connection event is available and returns it.
// Returns an error when the watcher is closed.
//
// A malformed record is logged and skipped rather than returned as an error:
// callers treat a Read error as fatal and tear down the watcher, which in
// block mode detaches the cgroup enforcement programs — a single bad
// monitoring event must not turn enforcement off (fail-open).
func (w *Watcher) Read() (*Event, error) {
	for {
		record, err := w.reader.Read()
		if err != nil {
			return nil, err
		}
		ev, err := parseEvent(record.RawSample)
		if err != nil {
			// Rate-limit the warning: a struct-layout mismatch would make every
			// event malformed, and an unthrottled warn per record floods the log.
			// The first occurrence logs immediately so a mismatch is noticed;
			// after that every 1000th keeps the ongoing failure visible.
			w.malformed++
			if w.malformed == 1 || w.malformed%1000 == 0 {
				slog.Warn("skipping malformed connection event", "error", err, "total_skipped", w.malformed)
			}
			continue
		}
		ev.Domain = w.dnsCache.Lookup(ev.DAddr)
		return ev, nil
	}
}

// Close releases all eBPF resources and returns the first error encountered.
func (w *Watcher) Close() error {
	var errs []error
	if w.dnsWatcher != nil {
		if err := w.dnsWatcher.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	if w.cgroupLink6 != nil {
		if err := w.cgroupLink6.Close(); err != nil {
			errs = append(errs, fmt.Errorf("cgroup link (connect6): %w", err))
		}
	}
	if w.cgroupLink != nil {
		if err := w.cgroupLink.Close(); err != nil {
			errs = append(errs, fmt.Errorf("cgroup link: %w", err))
		}
	}
	if w.blockObjs != nil {
		w.blockObjs.Close()
	}
	if err := w.reader.Close(); err != nil {
		errs = append(errs, fmt.Errorf("reader: %w", err))
	}
	if w.tpExit != nil {
		if err := w.tpExit.Close(); err != nil {
			errs = append(errs, fmt.Errorf("tracepoint sys_exit_connect: %w", err))
		}
	}
	if err := w.tp.Close(); err != nil {
		errs = append(errs, fmt.Errorf("tracepoint sys_enter_connect: %w", err))
	}
	w.objs.Close()
	return errors.Join(errs...)
}
