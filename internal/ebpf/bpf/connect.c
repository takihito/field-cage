// Compiled by bpf2go; do not edit directly — use `go generate ./internal/ebpf/...`

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

struct event {
	__u32 pid;
	__u32 tgid;
	__u16 dport;   // host byte order
	__u16 family;
	__u8  daddr[4]; // network byte order (big-endian), IPv4 only
	char  comm[TASK_COMM_LEN];
};

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 24); // 16 MB
} events SEC(".maps");

// Matches /sys/kernel/tracing/events/syscalls/sys_enter_connect/format
struct connect_args {
	__u8  __common[8];   // common tracepoint header
	__s32 __syscall_nr;
	__u32 __pad;
	__u64 fd;
	void *uservaddr;     // user-space pointer to struct sockaddr
	__s32 addrlen;
};

SEC("tracepoint/syscalls/sys_enter_connect")
int trace_connect(struct connect_args *ctx)
{
	struct sockaddr_in sa = {};

	if (bpf_probe_read_user(&sa, sizeof(sa), ctx->uservaddr) < 0)
		return 0;

	// IPv4 only for the prototype
	if (sa.sin_family != AF_INET)
		return 0;

	struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e)
		return 0;

	__u64 pid_tgid = bpf_get_current_pid_tgid();
	e->pid   = (__u32)pid_tgid;
	e->tgid  = (__u32)(pid_tgid >> 32);
	e->family = sa.sin_family;
	e->dport  = bpf_ntohs(sa.sin_port);
	__builtin_memcpy(e->daddr, &sa.sin_addr.s_addr, 4);
	bpf_get_current_comm(e->comm, sizeof(e->comm));

	bpf_ringbuf_submit(e, 0);
	return 0;
}

char LICENSE[] SEC("license") = "GPL";
