package ebpf

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

// Event represents a captured outbound IPv4 connection attempt.
type Event struct {
	PID   uint32
	TGID  uint32
	DPort uint16
	DAddr net.IP
	Comm  string
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
type Watcher struct {
	objs   ConnectObjects
	tp     link.Link
	reader *ringbuf.Reader
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

	return &Watcher{objs: objs, tp: tp, reader: reader}, nil
}

// Read blocks until a connection event is available and returns it.
// Returns an error when the watcher is closed.
func (w *Watcher) Read() (*Event, error) {
	record, err := w.reader.Read()
	if err != nil {
		return nil, err
	}
	return parseEvent(record.RawSample)
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

// Close releases all eBPF resources.
func (w *Watcher) Close() {
	w.reader.Close()
	w.tp.Close()
	w.objs.Close()
}

func nullTerminatedString(b []byte) string {
	if i := bytes.IndexByte(b, 0); i >= 0 {
		return string(b[:i])
	}
	return string(b)
}
