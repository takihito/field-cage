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

	"golang.org/x/sys/unix"

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

// TestBlockWatcherDefaultDenyIPv6 verifies the cgroup/connect6 enforcement
// program: ::1 loopback is always permitted, a non-allowlisted IPv6
// destination is rejected with EPERM, and AllowIP / AllowCIDR lift the denial.
// Skipped when the environment has no IPv6 support.
func TestBlockWatcherDefaultDenyIPv6(t *testing.T) {
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

	// ::1 loopback is always allowed: a connection to a local listener must
	// succeed. If IPv6 is unavailable in this environment, skip.
	ln, err := net.Listen("tcp6", "[::1]:0")
	if err != nil {
		t.Skipf("skipping: IPv6 unavailable: %v", err)
	}
	defer ln.Close()
	conn, err := net.DialTimeout("tcp6", ln.Addr().String(), 3*time.Second)
	if err != nil {
		t.Fatalf("IPv6 loopback connect should be allowed under block mode, got: %v", err)
	}
	conn.Close()

	// 2001:db8::/32 (RFC 3849 documentation range): guaranteed non-routable.
	const target = "[2001:db8::1]:80"

	// Default-deny: rejected by the connect6 program with EPERM.
	_, err = net.DialTimeout("tcp6", target, 2*time.Second)
	if err == nil {
		t.Fatalf("expected connect to %s to be denied, but it succeeded", target)
	}
	if !errors.Is(err, syscall.EPERM) {
		t.Fatalf("expected EPERM for denied connect to %s, got: %v", target, err)
	}

	// AllowIP (/128) lifts the denial; the connect then proceeds to the network
	// and fails with something other than EPERM (unroutable destination).
	if err := w.AllowIP(net.ParseIP("2001:db8::1")); err != nil {
		t.Fatalf("AllowIP: %v", err)
	}
	_, err = net.DialTimeout("tcp6", target, 2*time.Second)
	if errors.Is(err, syscall.EPERM) {
		t.Fatalf("after AllowIP, connect to %s should not be EPERM, got: %v", target, err)
	}

	// AllowCIDR: a different host inside a /64 seeded as a subnet.
	const target2 = "[2001:db8:0:1::7]:80"
	_, err = net.DialTimeout("tcp6", target2, 2*time.Second)
	if !errors.Is(err, syscall.EPERM) {
		t.Fatalf("expected EPERM for %s before AllowCIDR, got: %v", target2, err)
	}
	_, cidr, _ := net.ParseCIDR("2001:db8:0:1::/64")
	if err := w.AllowCIDR(cidr); err != nil {
		t.Fatalf("AllowCIDR: %v", err)
	}
	_, err = net.DialTimeout("tcp6", target2, 2*time.Second)
	if errors.Is(err, syscall.EPERM) {
		t.Fatalf("after AllowCIDR(2001:db8:0:1::/64), connect to %s should not be EPERM, got: %v", target2, err)
	}
}

// TestBlockWatcherIPv4MappedConnect6 verifies that a dual-stack AF_INET6
// socket connecting to an IPv4-mapped destination (::ffff:a.b.c.d) — the path
// taken by Node.js and Java runtimes for IPv4 destinations — is enforced
// against the IPv4 allowlist by the connect6 program. Go's net package
// normalizes IPv4-mapped addresses to AF_INET sockets, so this test uses raw
// syscalls to force the AF_INET6 path.
func TestBlockWatcherIPv4MappedConnect6(t *testing.T) {
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

	// TEST-NET-2 (RFC 5737) in its IPv4-mapped form.
	mapped := net.ParseIP("::ffff:198.51.100.7").To16()

	// Non-blocking so an allowed connect returns EINPROGRESS immediately
	// instead of hanging on the unroutable destination.
	dial := func() error {
		fd, err := unix.Socket(unix.AF_INET6, unix.SOCK_STREAM|unix.SOCK_NONBLOCK|unix.SOCK_CLOEXEC, 0)
		if err != nil {
			t.Skipf("skipping: cannot create AF_INET6 socket (IPv6 unavailable?): %v", err)
		}
		defer unix.Close(fd) //nolint:errcheck
		sa := &unix.SockaddrInet6{Port: 80}
		copy(sa.Addr[:], mapped)
		return unix.Connect(fd, sa)
	}

	// Default-deny: the IPv4-mapped destination is not allowlisted → EPERM.
	if err := dial(); !errors.Is(err, unix.EPERM) {
		t.Fatalf("expected EPERM for v4-mapped connect before AllowIP, got: %v", err)
	}

	// Allowing the plain IPv4 address must lift the denial for the v4-mapped
	// path too (the connect6 program consults the IPv4 trie).
	if err := w.AllowIP(net.ParseIP("198.51.100.7")); err != nil {
		t.Fatalf("AllowIP: %v", err)
	}
	if err := dial(); errors.Is(err, unix.EPERM) {
		t.Fatalf("after AllowIP(198.51.100.7), v4-mapped connect should not be EPERM, got: %v", err)
	}
}
