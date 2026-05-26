//go:build integration

package ebpf_test

import (
	"context"
	"errors"
	"net"
	"os"
	"testing"
	"time"

	"github.com/takihito/field-cage/internal/ebpf"
)

// TestWatcherCapturesIPv4Connect verifies that the eBPF tracepoint captures
// an outbound IPv4 TCP connection made by the test process itself.
// Requires CAP_BPF (run with sudo or as root).
func TestWatcherCapturesIPv4Connect(t *testing.T) {
	watcher, err := ebpf.NewWatcher()
	if err != nil {
		// Skip only for known permission/unsupported errors so that CI fails
		// loudly if the loader or attach path breaks for any other reason.
		if errors.Is(err, os.ErrPermission) {
			t.Skipf("skipping: insufficient privileges (needs CAP_BPF/root): %v", err)
		}
		t.Fatalf("NewWatcher: %v", err)
	}
	defer watcher.Close()

	// Start a local TCP listener so the test is self-contained and not
	// dependent on external network reachability.
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	targetAddr := ln.Addr().(*net.TCPAddr)

	// Collect events in the background until the test ends.
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	events := make(chan *ebpf.Event, 128)
	go func() {
		for {
			ev, err := watcher.Read()
			if err != nil {
				return
			}
			select {
			case events <- ev:
			default:
			}
		}
	}()

	// Trigger an outbound connect from this process to the local listener.
	conn, err := net.DialTimeout("tcp4", targetAddr.String(), 3*time.Second)
	if err != nil {
		t.Fatalf("dial %s: %v", targetAddr, err)
	}
	conn.Close()

	// Wait for the eBPF event that matches our connect.
	for {
		select {
		case ev := <-events:
			if ev.DAddr.Equal(targetAddr.IP) && ev.DPort == uint16(targetAddr.Port) {
				t.Logf("captured: pid=%d comm=%s dst=%s:%d", ev.PID, ev.Comm, ev.DAddr, ev.DPort)
				return
			}
		case <-ctx.Done():
			t.Errorf("timeout: connect to %s was not captured by eBPF", targetAddr)
			return
		}
	}
}
