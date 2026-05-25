//go:build integration

package ebpf_test

import (
	"context"
	"net"
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
		t.Skipf("cannot attach eBPF tracepoint (needs CAP_BPF/root): %v", err)
	}
	defer watcher.Close()

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

	// Trigger an outbound TCP connect from this process.
	// 1.1.1.1:443 is Cloudflare DNS-over-HTTPS — reachable on GitHub Actions runners.
	const targetAddr = "1.1.1.1:443"
	conn, err := net.DialTimeout("tcp", targetAddr, 3*time.Second)
	if err != nil {
		t.Logf("dial %s failed (connection may be filtered): %v", targetAddr, err)
	}
	if conn != nil {
		conn.Close()
	}

	targetIP := net.ParseIP("1.1.1.1").To4()

	for {
		select {
		case ev := <-events:
			if ev.DAddr.Equal(targetIP) && ev.DPort == 443 {
				t.Logf("captured: pid=%d comm=%s dst=%s:%d", ev.PID, ev.Comm, ev.DAddr, ev.DPort)
				return
			}
		case <-ctx.Done():
			t.Errorf("timeout: connect to %s was not captured by eBPF", targetAddr)
			return
		}
	}
}
