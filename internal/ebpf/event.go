package ebpf

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
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
	Pid       uint32
	Tgid      uint32
	Dport     uint16
	Family    uint16
	Daddr     [4]byte
	Comm      [16]byte
	ConnectNs uint64
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

func nullTerminatedString(b []byte) string {
	if i := bytes.IndexByte(b, 0); i >= 0 {
		return string(b[:i])
	}
	return string(b)
}
