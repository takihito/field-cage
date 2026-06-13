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
		Family:    2, // AF_INET
		Daddr:     [4]byte{93, 184, 216, 34},
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
	if ev.Comm != "curl" {
		t.Errorf("Comm = %q, want %q", ev.Comm, "curl")
	}
	if ev.ConnectMs != 23 {
		t.Errorf("ConnectMs = %d, want 23", ev.ConnectMs)
	}
}

func TestParseEvent_TruncatedData(t *testing.T) {
	_, err := parseEvent([]byte{0x01, 0x02}) // too short
	if err == nil {
		t.Error("expected error for truncated data, got nil")
	}
}
