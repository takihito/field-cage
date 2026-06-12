// eBPF C source for field-cage. Edit this file as needed.
// Build: bpf2go compiles it into Go bindings via `go generate ./internal/ebpf/...`
// Do NOT edit the generated connect_bpf*.go / connect_bpf*.o files — regenerate instead.

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

// Define UAPI types inline to avoid header-chain issues with -target bpf.
// These constants and struct layouts are stable in the Linux kernel UAPI.
#define AF_INET 2

struct in_addr {
	__u32 s_addr;
};

struct sockaddr_in {
	__u16          sin_family;
	__u16          sin_port;
	struct in_addr sin_addr;
	__u8           sin_zero[8];
};

#define TASK_COMM_LEN 16

// Event emitted to user-space via the ring buffer.
// connect_ns holds the duration of the connect() syscall in nanoseconds;
// the Go agent converts this to milliseconds for logging.
struct event {
	__u32 pid;
	__u32 tgid;
	__u16 dport;       // host byte order
	__u16 family;
	__u8  daddr[4];    // network byte order (big-endian), IPv4 only
	char  comm[TASK_COMM_LEN];
	__u64 connect_ns;  // connect() duration: sys_exit_connect - sys_enter_connect
};

// Pending connect: stored at sys_enter_connect, consumed at sys_exit_connect.
// Key is pid_tgid so concurrent connects from the same process are distinguished.
struct pending_connect {
	__u64 start_ns;
	__u16 dport;
	__u16 family;
	__u8  daddr[4];
	char  comm[TASK_COMM_LEN];
	__u32 pid;
	__u32 tgid;
};

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 24); // 16 MB
} events SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
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
	struct sockaddr_in sa = {};

	if (bpf_probe_read_user(&sa, sizeof(sa), ctx->uservaddr) < 0)
		return 0;

	// IPv4 only for the prototype
	if (sa.sin_family != AF_INET)
		return 0;

	__u64 pid_tgid = bpf_get_current_pid_tgid();

	struct pending_connect pc = {};
	pc.start_ns = bpf_ktime_get_ns();
	pc.pid      = (__u32)pid_tgid;
	pc.tgid     = (__u32)(pid_tgid >> 32);
	pc.family   = sa.sin_family;
	pc.dport    = bpf_ntohs(sa.sin_port);
	__builtin_memcpy(pc.daddr, &sa.sin_addr.s_addr, 4);
	bpf_get_current_comm(pc.comm, sizeof(pc.comm));

	bpf_map_update_elem(&pending_connects, &pid_tgid, &pc, BPF_ANY);
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
	__builtin_memcpy(e->daddr, pc->daddr, 4);
	__builtin_memcpy(e->comm,  pc->comm,  TASK_COMM_LEN);
	e->connect_ns = connect_ns;

	bpf_map_delete_elem(&pending_connects, &pid_tgid);
	bpf_ringbuf_submit(e, 0);
	return 0;
}

char LICENSE[] SEC("license") = "GPL";
