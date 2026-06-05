//go:build linux

package ebpf

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"net"
	ciliumebpf "github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

// Event represents a captured outbound IPv4 connection attempt.
type Event struct {
	PID    uint32
	TGID   uint32
	DPort  uint16
	DAddr  net.IP
	Comm   string
	Domain string // resolved domain name, empty if not yet in DNS cache
}

// connectEvent mirrors the C struct event layout for binary deserialization.
type connectEvent struct {
	Pid    uint32
	Tgid   uint32
	Dport  uint16
	Family uint16
	Daddr  [4]byte
	Comm   [16]byte
}

// Watcher attaches to the sys_enter_connect tracepoint and streams Events.
// It also runs a DNS cache that annotates events with resolved domain names.
// When blockObjs is non-nil, UpdateBlockList can be used to enforce policy.
type Watcher struct {
	objs       ConnectObjects
	tp         link.Link
	reader     *ringbuf.Reader
	dnsCache   *DNSCache
	dnsWatcher *dnsWatcher
	blockObjs  *BlockObjects
	cgroupLink link.Link
}

// NewWatcher loads the eBPF program and attaches it to the tracepoint.
// The caller must call Close when done.
func NewWatcher() (*Watcher, error) {
	return newWatcher("")
}

// NewBlockWatcher is like NewWatcher but also loads the cgroup/connect4
// enforcement program. Use UpdateBlockList to populate the blocked-IP set.
// cgroupPath is the path to a writable cgroup v2 directory
// (e.g. "/sys/fs/cgroup").
func NewBlockWatcher(cgroupPath string) (*Watcher, error) {
	return newWatcher(cgroupPath)
}

func newWatcher(cgroupPath string) (*Watcher, error) {
	withBlock := cgroupPath != ""
	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, fmt.Errorf("remove memlock rlimit: %w", err)
	}

	var objs ConnectObjects
	if err := LoadConnectObjects(&objs, nil); err != nil {
		return nil, fmt.Errorf("load eBPF objects: %w", err)
	}

	tp, err := link.Tracepoint("syscalls", "sys_enter_connect", objs.TraceConnect, nil)
	if err != nil {
		objs.Close()
		return nil, fmt.Errorf("attach tracepoint syscalls/sys_enter_connect: %w", err)
	}

	reader, err := ringbuf.NewReader(objs.Events)
	if err != nil {
		tp.Close()
		objs.Close()
		return nil, fmt.Errorf("open ringbuf reader: %w", err)
	}

	cache := newDNSCache()
	dw, err := newDNSWatcher(cache)
	if err != nil {
		if withBlock {
			// In block mode the policy engine relies on domain names resolved from
			// DNS responses. Without DNS capture every connection has an empty
			// domain and only explicitly listed IPs can be matched, so all
			// domain-based allowlist entries become ineffective and virtually all
			// outbound traffic would be denied. Fail loudly rather than silently
			// mis-enforcing policy.
			reader.Close()  //nolint:errcheck
			tp.Close()      //nolint:errcheck
			objs.Close()
			return nil, fmt.Errorf(
				"DNS capture is required in block mode but could not start: %w\n"+
					"  Possible causes:\n"+
					"    - missing CAP_NET_RAW capability (run with sudo or grant the capability)\n"+
					"    - AF_PACKET socket creation denied by seccomp/AppArmor\n"+
					"  Without DNS capture every connection would show an empty domain and\n"+
					"  domain-based allowlist entries would never match, blocking all traffic.", err)
		}
		// In audit mode DNS capture is best-effort: connections are still logged
		// with their IP addresses and the agent continues running.
		log.Printf("field-cage: DNS capture unavailable (audit mode, connections will show IPs only): %v", err)
		dw = nil
	}

	w := &Watcher{objs: objs, tp: tp, reader: reader, dnsCache: cache, dnsWatcher: dw}

	if withBlock {
		if err := w.attachBlock(cgroupPath); err != nil {
			w.Close() //nolint:errcheck
			return nil, fmt.Errorf("attach block program: %w", err)
		}
	}
	return w, nil
}

// attachBlock loads the cgroup/connect4 eBPF program and attaches it to the
// given cgroup path so it can block unauthorized connections system-wide.
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

	w.blockObjs = &blockObjs
	w.cgroupLink = cg
	return nil
}

// AddBlockedIP adds a single IPv4 address to the blocked_ips eBPF map.
// This is an O(1) incremental operation; use it instead of UpdateBlockList
// when only one new IP needs to be blocked to avoid O(n) map iteration.
// No-op for non-IPv4 addresses or if not in block mode.
func (w *Watcher) AddBlockedIP(ip net.IP) error {
	if w.blockObjs == nil {
		return nil
	}
	ip4 := ip.To4()
	if ip4 == nil {
		return nil
	}
	var key [4]byte
	copy(key[:], ip4)
	var val uint8 = 1
	if err := w.blockObjs.BlockedIps.Put(key, val); err != nil {
		return fmt.Errorf("add blocked IP %s: %w", ip, err)
	}
	return nil
}

// UpdateBlockList replaces the set of blocked IPv4 addresses in the eBPF map.
// ips is the full set of IPs that should be blocked; any previously blocked
// IPs not in the new list are removed. Prefer AddBlockedIP for incremental
// updates to avoid O(n) map iteration on every new denial.
// No-op if the watcher was not created with NewBlockWatcher.
func (w *Watcher) UpdateBlockList(ips []net.IP) error {
	if w.blockObjs == nil {
		return nil
	}

	m := w.blockObjs.BlockedIps
	var blocked uint8 = 1

	// Add all IPs in the new list.
	newSet := make(map[[4]byte]struct{}, len(ips))
	for _, ip := range ips {
		ip4 := ip.To4()
		if ip4 == nil {
			continue
		}
		var key [4]byte
		copy(key[:], ip4)
		newSet[key] = struct{}{}
		if err := m.Put(key, blocked); err != nil {
			return fmt.Errorf("update blocked_ips map: %w", err)
		}
	}

	// Remove stale entries.
	var key [4]byte
	iter := m.Iterate()
	var val uint8
	var toDelete [][4]byte
	for iter.Next(&key, &val) {
		if _, ok := newSet[key]; !ok {
			toDelete = append(toDelete, key)
		}
	}
	if err := iter.Err(); err != nil {
		return fmt.Errorf("iterate blocked_ips map: %w", err)
	}
	for _, k := range toDelete {
		if err := m.Delete(k); err != nil {
			return fmt.Errorf("delete blocked_ips entry: %w", err)
		}
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

func parseEvent(data []byte) (*Event, error) {
	var raw connectEvent
	if err := binary.Read(bytes.NewReader(data), binary.NativeEndian, &raw); err != nil {
		return nil, fmt.Errorf("parse event: %w", err)
	}
	return &Event{
		PID:   raw.Pid,
		TGID:  raw.Tgid,
		DPort: raw.Dport,
		DAddr: net.IP(raw.Daddr[:]),
		Comm:  nullTerminatedString(raw.Comm[:]),
	}, nil
}

// Close releases all eBPF resources and returns the first error encountered.
func (w *Watcher) Close() error {
	var errs []error
	if w.dnsWatcher != nil {
		if err := w.dnsWatcher.Close(); err != nil {
			errs = append(errs, err)
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
	if err := w.tp.Close(); err != nil {
		errs = append(errs, fmt.Errorf("tracepoint: %w", err))
	}
	w.objs.Close()
	return errors.Join(errs...)
}

func nullTerminatedString(b []byte) string {
	if i := bytes.IndexByte(b, 0); i >= 0 {
		return string(b[:i])
	}
	return string(b)
}
