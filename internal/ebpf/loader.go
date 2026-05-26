//go:build linux

package ebpf

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"net"

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
type Watcher struct {
	objs       ConnectObjects
	tp         link.Link
	reader     *ringbuf.Reader
	dnsCache   *DNSCache
	dnsWatcher *dnsWatcher
}

// NewWatcher loads the eBPF program and attaches it to the tracepoint.
// The caller must call Close when done.
func NewWatcher() (*Watcher, error) {
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
		// DNS capture is best-effort; connections are still logged without domain names.
		log.Printf("field-cage: DNS capture unavailable (connections will show IPs only): %v", err)
		dw = nil
	}

	return &Watcher{objs: objs, tp: tp, reader: reader, dnsCache: cache, dnsWatcher: dw}, nil
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
