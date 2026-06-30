//go:build linux && integration

package ebpf_test

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"syscall"
	"testing"
	"time"

	"github.com/takihito/field-cage/internal/ebpf"
)

// setupTestCgroup creates a dedicated child cgroup, moves the current process
// into it, and returns its path. This confines default-deny enforcement to the
// test process so the integration test does not disrupt unrelated processes or
// networking in a shared CI/container environment. The process is moved back to
// the root cgroup and the child removed on cleanup. The test is skipped if a
// writable cgroup v2 hierarchy is unavailable (e.g. insufficient privileges).
func setupTestCgroup(t *testing.T) string {
	t.Helper()
	const root = "/sys/fs/cgroup"
	dir := filepath.Join(root, "field-cage-test")
	if err := os.Mkdir(dir, 0o755); err != nil && !errors.Is(err, os.ErrExist) {
		t.Skipf("skipping: cannot create test cgroup (needs cgroup v2 + privileges): %v", err)
	}
	pid := strconv.Itoa(os.Getpid())
	if err := os.WriteFile(filepath.Join(dir, "cgroup.procs"), []byte(pid), 0); err != nil {
		os.Remove(dir) //nolint:errcheck
		t.Skipf("skipping: cannot move process into test cgroup: %v", err)
	}
	t.Cleanup(func() {
		// Move the process back to the root cgroup so the child can be removed.
		if err := os.WriteFile(filepath.Join(root, "cgroup.procs"), []byte(pid), 0); err != nil {
			t.Logf("warning: failed to move process back to root cgroup: %v", err)
		}
		if err := os.Remove(dir); err != nil {
			t.Logf("warning: failed to remove test cgroup %s: %v", dir, err)
		}
	})
	return dir
}

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

// TestBlockWatcherDefaultDeny verifies the cgroup/connect4 enforcement program:
// a non-loopback, non-allowlisted destination is rejected with EPERM, loopback
// is always permitted, and AllowIP lifts the denial for a specific IP.
// Requires CAP_BPF + CAP_NET_RAW and a writable cgroup v2 (run with sudo/root,
// e.g. a privileged container). Enforcement is confined to a dedicated child
// cgroup holding only the test process, so it does not disrupt other processes.
func TestBlockWatcherDefaultDeny(t *testing.T) {
	cgroupPath := setupTestCgroup(t)
	denyAll := func(string) bool { return false }
	w, err := ebpf.NewBlockWatcher(cgroupPath, denyAll)
	if err != nil {
		if errors.Is(err, os.ErrPermission) {
			t.Skipf("skipping: insufficient privileges (needs CAP_BPF/CAP_NET_RAW/root): %v", err)
		}
		t.Fatalf("NewBlockWatcher: %v", err)
	}
	defer w.Close()

	// Loopback is always allowed: a connection to a local listener must succeed.
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	conn, err := net.DialTimeout("tcp4", ln.Addr().String(), 3*time.Second)
	if err != nil {
		t.Fatalf("loopback connect should be allowed under block mode, got: %v", err)
	}
	conn.Close()

	// TEST-NET-1 (RFC 5737): guaranteed non-routable and non-loopback.
	const target = "192.0.2.1:80"

	// Default-deny: the connect is rejected by the program and fails with EPERM
	// immediately, rather than attempting the network and timing out.
	_, err = net.DialTimeout("tcp4", target, 2*time.Second)
	if err == nil {
		t.Fatalf("expected connect to %s to be denied, but it succeeded", target)
	}
	if !errors.Is(err, syscall.EPERM) {
		t.Fatalf("expected EPERM for denied connect to %s, got: %v", target, err)
	}

	// After allowing the IP, the connect is no longer rejected by policy; it
	// proceeds to the network and fails with something other than EPERM (the
	// address is unroutable, so a timeout is expected).
	if err := w.AllowIP(net.ParseIP("192.0.2.1")); err != nil {
		t.Fatalf("AllowIP: %v", err)
	}
	_, err = net.DialTimeout("tcp4", target, 2*time.Second)
	if errors.Is(err, syscall.EPERM) {
		t.Fatalf("after AllowIP, connect to %s should not be EPERM, got: %v", target, err)
	}
}

// TestBlockWatcherAllowCIDR verifies that AllowCIDR seeds the LPM trie with a
// subnet prefix: a host address inside the CIDR must no longer be denied by
// default-deny after the CIDR is seeded.
// Requires the same privileges as TestBlockWatcherDefaultDeny.
func TestBlockWatcherAllowCIDR(t *testing.T) {
	cgroupPath := setupTestCgroup(t)
	denyAll := func(string) bool { return false }
	w, err := ebpf.NewBlockWatcher(cgroupPath, denyAll)
	if err != nil {
		if errors.Is(err, os.ErrPermission) {
			t.Skipf("skipping: insufficient privileges (needs CAP_BPF/CAP_NET_RAW/root): %v", err)
		}
		t.Fatalf("NewBlockWatcher: %v", err)
	}
	defer w.Close()

	// TEST-NET-1 host inside 192.0.2.0/24 — non-routable, so any non-EPERM
	// error after AllowCIDR indicates the CIDR seeding worked.
	const target = "192.0.2.2:80"

	// Default-deny: the connection must fail with EPERM before seeding.
	_, err = net.DialTimeout("tcp4", target, 2*time.Second)
	if err == nil {
		t.Fatalf("expected connect to %s to be denied, but it succeeded", target)
	}
	if !errors.Is(err, syscall.EPERM) {
		t.Fatalf("expected EPERM for denied connect to %s, got: %v", target, err)
	}

	// Seed the containing /24 subnet into the LPM trie.
	_, cidr, _ := net.ParseCIDR("192.0.2.0/24")
	if err := w.AllowCIDR(cidr); err != nil {
		t.Fatalf("AllowCIDR: %v", err)
	}

	// After seeding the subnet, the host must no longer be EPERM.
	_, err = net.DialTimeout("tcp4", target, 2*time.Second)
	if errors.Is(err, syscall.EPERM) {
		t.Fatalf("after AllowCIDR(192.0.2.0/24), connect to %s must not be EPERM, got: %v", target, err)
	}
}
