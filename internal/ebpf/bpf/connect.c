// eBPF C source for field-cage. Edit this file as needed.
// Build: bpf2go compiles it into Go bindings via `go generate ./internal/ebpf/...`
// Do NOT edit the generated connect_bpf*.go / connect_bpf*.o files — regenerate instead.

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

// Define UAPI types inline to avoid header-chain issues with -target bpf.
// These constants and struct layouts are stable in the Linux kernel UAPI.
#define AF_INET  2
#define AF_INET6 10

struct in_addr {
	__u32 s_addr;
};

struct sockaddr_in {
	__u16          sin_family;
	__u16          sin_port;
	struct in_addr sin_addr;
	__u8           sin_zero[8];
};

struct sockaddr_in6 {
	__u16 sin6_family;
	__u16 sin6_port;
	__u32 sin6_flowinfo;
	__u8  sin6_addr[16];
	__u32 sin6_scope_id;
};

#define TASK_COMM_LEN 16

// Event emitted to user-space via the ring buffer.
// daddr holds the destination address in network byte order: for AF_INET the
// first 4 bytes are significant, for AF_INET6 all 16 bytes are. family
// distinguishes the two. The explicit _pad field keeps the C layout identical
// to Go's packed binary.Read layout in internal/ebpf/event.go — keep both in
// sync when changing this struct.
struct event {
	__u32 pid;
	__u32 tgid;
	__u16 dport;       // host byte order
	__u16 family;      // AF_INET or AF_INET6
	__u8  daddr[16];   // network byte order; IPv4 uses first 4 bytes
	char  comm[TASK_COMM_LEN];
	__u32 _pad;        // explicit padding before the 8-byte-aligned field
	__u64 connect_ns;  // connect() duration: sys_exit_connect - sys_enter_connect
};

// Pending connect: stored at sys_enter_connect, consumed at sys_exit_connect.
// Key is pid_tgid so concurrent connects from the same process are distinguished.
struct pending_connect {
	__u64 start_ns;
	__u16 dport;
	__u16 family;
	__u8  daddr[16];
	char  comm[TASK_COMM_LEN];
	__u32 pid;
	__u32 tgid;
};

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 24); // 16 MB
} events SEC(".maps");

// LRU_HASH rather than HASH: an interrupted connect() (e.g. killed between
// enter and exit tracepoints) leaves its entry behind forever, and a plain
// HASH would eventually fill up and drop all new events. LRU auto-evicts the
// stale entries under pressure.
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 10240);
	__type(key,   __u64);
	__type(value, struct pending_connect);
} pending_connects SEC(".maps");

// Matches /sys/kernel/tracing/events/syscalls/sys_enter_connect/format
struct connect_enter_args {
	__u8  __common[8];   // common tracepoint header
	__s32 __syscall_nr;
	__u32 __pad;
	__u64 fd;
	void *uservaddr;     // user-space pointer to struct sockaddr
	__s32 addrlen;
};

// Matches /sys/kernel/tracing/events/syscalls/sys_exit_connect/format
struct connect_exit_args {
	__u8  __common[8];   // common tracepoint header
	__s32 __syscall_nr;
	__u32 __pad;
	long  ret;           // return value of connect()
};

SEC("tracepoint/syscalls/sys_enter_connect")
int trace_connect_enter(struct connect_enter_args *ctx)
{
	// Read the address family first: the sockaddr size differs per family, and
	// reading past the user buffer (e.g. sockaddr_in6 from an AF_INET connect)
	// could fault and drop the event.
	__u16 family = 0;
	if (bpf_probe_read_user(&family, sizeof(family), ctx->uservaddr) < 0)
		return 0;

	struct pending_connect pc = {};

	if (family == AF_INET) {
		struct sockaddr_in sa = {};
		if (bpf_probe_read_user(&sa, sizeof(sa), ctx->uservaddr) < 0)
			return 0;
		pc.dport = bpf_ntohs(sa.sin_port);
		__builtin_memcpy(pc.daddr, &sa.sin_addr.s_addr, 4);
	} else if (family == AF_INET6) {
		struct sockaddr_in6 sa6 = {};
		if (bpf_probe_read_user(&sa6, sizeof(sa6), ctx->uservaddr) < 0)
			return 0;
		pc.dport = bpf_ntohs(sa6.sin6_port);
		__builtin_memcpy(pc.daddr, sa6.sin6_addr, 16);
	} else {
		return 0;
	}

	__u64 pid_tgid = bpf_get_current_pid_tgid();

	pc.start_ns = bpf_ktime_get_ns();
	pc.pid      = (__u32)pid_tgid;
	pc.tgid     = (__u32)(pid_tgid >> 32);
	pc.family   = family;
	bpf_get_current_comm(pc.comm, sizeof(pc.comm));

	// LRU_HASH evicts the least-recently-used entry when full, so this update
	// only fails on transient conditions; return cleanly and lose the one event.
	if (bpf_map_update_elem(&pending_connects, &pid_tgid, &pc, BPF_ANY) < 0)
		return 0;
	return 0;
}

SEC("tracepoint/syscalls/sys_exit_connect")
int trace_connect_exit(struct connect_exit_args *ctx)
{
	__u64 pid_tgid = bpf_get_current_pid_tgid();

	struct pending_connect *pc = bpf_map_lookup_elem(&pending_connects, &pid_tgid);
	if (!pc)
		return 0;

	__u64 connect_ns = bpf_ktime_get_ns() - pc->start_ns;

	struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e) {
		bpf_map_delete_elem(&pending_connects, &pid_tgid);
		return 0;
	}

	e->pid        = pc->pid;
	e->tgid       = pc->tgid;
	e->family     = pc->family;
	e->dport      = pc->dport;
	__builtin_memcpy(e->daddr, pc->daddr, 16);
	__builtin_memcpy(e->comm,  pc->comm,  TASK_COMM_LEN);
	e->_pad       = 0;
	e->connect_ns = connect_ns;

	bpf_map_delete_elem(&pending_connects, &pid_tgid);
	bpf_ringbuf_submit(e, 0);
	return 0;
}

char LICENSE[] SEC("license") = "GPL";
