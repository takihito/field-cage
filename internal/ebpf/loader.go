//go:build linux

package ebpf

import (
	"errors"
	"fmt"
	"log"
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
}

// NewWatcher loads the eBPF program and attaches it to the tracepoint.
// The caller must call Close when done.
func NewWatcher() (*Watcher, error) {
	return newWatcher("", nil)
}

// NewBlockWatcher is like NewWatcher but also loads the cgroup/connect4 and
// cgroup/connect6 enforcement programs, which deny every outbound connection
// by default (allowlist model). Use AllowIP to seed the permitted-IP set;
// observed DNS responses for domains accepted by isAllowedDomain are added
// automatically.
// cgroupPath is the path to a writable cgroup v2 directory
// (e.g. "/sys/fs/cgroup"). isAllowedDomain reports whether a resolved domain is
// on the allowlist; it may be nil, in which case only seeded IPs are permitted.
func NewBlockWatcher(cgroupPath string, isAllowedDomain func(string) bool) (*Watcher, error) {
	return newWatcher(cgroupPath, isAllowedDomain)
}

func newWatcher(cgroupPath string, isAllowedDomain func(string) bool) (w *Watcher, err error) {
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
	}

	// In block mode, observed DNS responses for allowlisted domains are added to
	// the enforcement map proactively (before the application connects).
	var onAllowedIP func(net.IP) error
	if withBlock {
		onAllowedIP = w.AllowIP
	}
	dw, err := newDNSWatcher(cache, isAllowedDomain, onAllowedIP)
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
		log.Printf("field-cage: DNS capture unavailable (audit mode, connections will show IPs only): %v", err)
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

// Read blocks until a connection event is available and returns it.
// Returns an error when the watcher is closed.
func (w *Watcher) Read() (*Event, error) {
	record, err := w.reader.Read()
	if err != nil {
		return nil, err
	}
	ev, err := parseEvent(record.RawSample)
	if err != nil {
		return nil, err
	}
	ev.Domain = w.dnsCache.Lookup(ev.DAddr)
	return ev, nil
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
