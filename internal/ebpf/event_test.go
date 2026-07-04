package ebpf

import (
	"bytes"
	"encoding/binary"
	"net"
	"testing"
)

func TestNullTerminatedString(t *testing.T) {
	cases := []struct {
		input []byte
		want  string
	}{
		{[]byte{'c', 'u', 'r', 'l', 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, "curl"},
		{[]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, ""},
		{[]byte{'a', 'b', 'c', 0}, "abc"},
		{[]byte{'a', 'b', 'c'}, "abc"}, // no null terminator
	}
	for _, tc := range cases {
		got := nullTerminatedString(tc.input)
		if got != tc.want {
			t.Errorf("nullTerminatedString(%v) = %q, want %q", tc.input, got, tc.want)
		}
	}
}

func TestParseEvent(t *testing.T) {
	raw := connectEvent{
		Pid:       1234,
		Tgid:      1234,
		Dport:     443,
		Family:    afInet,
		Daddr:     [16]byte{93, 184, 216, 34}, // IPv4: first 4 bytes significant
		Comm:      [16]byte{'c', 'u', 'r', 'l'},
		ConnectNs: 23_500_000, // 23.5 ms → 23 ms after truncation
	}

	buf := new(bytes.Buffer)
	if err := binary.Write(buf, binary.NativeEndian, raw); err != nil {
		t.Fatal(err)
	}

	ev, err := parseEvent(buf.Bytes())
	if err != nil {
		t.Fatalf("parseEvent: %v", err)
	}

	if ev.PID != 1234 {
		t.Errorf("PID = %d, want 1234", ev.PID)
	}
	if ev.DPort != 443 {
		t.Errorf("DPort = %d, want 443", ev.DPort)
	}
	want := net.IP{93, 184, 216, 34}
	if !ev.DAddr.Equal(want) {
		t.Errorf("DAddr = %v, want %v", ev.DAddr, want)
	}
	if len(ev.DAddr) != 4 {
		t.Errorf("DAddr length = %d, want 4 for AF_INET", len(ev.DAddr))
	}
	if ev.Comm != "curl" {
		t.Errorf("Comm = %q, want %q", ev.Comm, "curl")
	}
}

func TestParseEventIPv6(t *testing.T) {
	// 2001:db8::1 in wire order.
	addr := [16]byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}
	raw := connectEvent{
		Pid:    5678,
		Tgid:   5678,
		Dport:  443,
		Family: afInet6,
		Daddr:  addr,
		Comm:   [16]byte{'w', 'g', 'e', 't'},
	}

	buf := new(bytes.Buffer)
	if err := binary.Write(buf, binary.NativeEndian, raw); err != nil {
		t.Fatal(err)
	}

	ev, err := parseEvent(buf.Bytes())
	if err != nil {
		t.Fatalf("parseEvent: %v", err)
	}

	want := net.ParseIP("2001:db8::1")
	if !ev.DAddr.Equal(want) {
		t.Errorf("DAddr = %v, want %v", ev.DAddr, want)
	}
	if ev.Comm != "wget" {
		t.Errorf("Comm = %q, want %q", ev.Comm, "wget")
	}
}

func TestParseEventIPv4Mapped(t *testing.T) {
	// ::ffff:192.0.2.5 — dual-stack socket connecting to an IPv4 destination.
	// net.IP renders and compares IPv4-mapped addresses as IPv4.
	addr := [16]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 192, 0, 2, 5}
	raw := connectEvent{
		Pid:    99,
		Tgid:   99,
		Dport:  80,
		Family: afInet6,
		Daddr:  addr,
		Comm:   [16]byte{'n', 'o', 'd', 'e'},
	}

	buf := new(bytes.Buffer)
	if err := binary.Write(buf, binary.NativeEndian, raw); err != nil {
		t.Fatal(err)
	}

	ev, err := parseEvent(buf.Bytes())
	if err != nil {
		t.Fatalf("parseEvent: %v", err)
	}

	if !ev.DAddr.Equal(net.ParseIP("192.0.2.5")) {
		t.Errorf("DAddr = %v, want 192.0.2.5 (IPv4-mapped)", ev.DAddr)
	}
	if got := ev.DAddr.String(); got != "192.0.2.5" {
		t.Errorf("DAddr.String() = %q, want %q", got, "192.0.2.5")
	}
}

func TestParseEvent_TruncatedData(t *testing.T) {
	_, err := parseEvent([]byte{0x01, 0x02}) // too short
	if err == nil {
		t.Error("expected error for truncated data, got nil")
	}
}
