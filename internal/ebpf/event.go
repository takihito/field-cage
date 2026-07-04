package ebpf

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
)

// Address families (Linux UAPI). Mirrored here so this file stays
// platform-independent and unit-testable on any OS.
const (
	afInet  = 2  // AF_INET
	afInet6 = 10 // AF_INET6
)

// Event represents a captured outbound IPv4/IPv6 connection attempt.
type Event struct {
	PID    uint32
	TGID   uint32
	DPort  uint16
	DAddr  net.IP
	Comm   string
	Domain string // resolved domain name, empty if not yet in DNS cache
}

// connectEvent mirrors the C struct event layout for binary deserialization.
// binary.Read uses a packed layout, so the C struct carries an explicit _pad
// field before the 8-byte-aligned connect_ns; the blank field below mirrors
// it. Keep in sync with struct event in bpf/connect.c.
type connectEvent struct {
	Pid       uint32
	Tgid      uint32
	Dport     uint16
	Family    uint16
	Daddr     [16]byte
	Comm      [16]byte
	_         [4]byte // mirrors the C struct's explicit _pad
	ConnectNs uint64
}

func parseEvent(data []byte) (*Event, error) {
	var raw connectEvent
	if err := binary.Read(bytes.NewReader(data), binary.NativeEndian, &raw); err != nil {
		return nil, fmt.Errorf("parse event: %w", err)
	}
	var daddr net.IP
	switch raw.Family {
	case afInet6:
		// 16-byte net.IP; IPv4-mapped addresses (::ffff:a.b.c.d) render and
		// compare as IPv4 automatically.
		daddr = append(net.IP(nil), raw.Daddr[:]...)
	default:
		daddr = append(net.IP(nil), raw.Daddr[:4]...)
	}
	return &Event{
		PID:   raw.Pid,
		TGID:  raw.Tgid,
		DPort: raw.Dport,
		DAddr: daddr,
		Comm:  nullTerminatedString(raw.Comm[:]),
	}, nil
}

func nullTerminatedString(b []byte) string {
	if i := bytes.IndexByte(b, 0); i >= 0 {
		return string(b[:i])
	}
	return string(b)
}
