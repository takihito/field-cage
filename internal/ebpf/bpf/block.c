// eBPF cgroup/connect4 program for field-cage enforcement mode.
// Checks the destination IPv4 address against a blocked_ips map and
// returns 0 (EPERM) to reject unauthorized connections.
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

// blocked_ips: IPv4 addresses (network byte order) that must be rejected.
// Populated from Go userspace based on the YAML policy allowlist.
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 4096);
	__type(key, __u32);
	__type(value, __u8);
} blocked_ips SEC(".maps");

SEC("cgroup/connect4")
int block_connect(struct bpf_sock_addr *ctx)
{
	__u32 daddr = ctx->user_ip4;
	__u8 *blocked = bpf_map_lookup_elem(&blocked_ips, &daddr);
	if (blocked)
		return 0; // block: kernel returns EPERM to the caller
	return 1;     // allow
}

char LICENSE[] SEC("license") = "GPL";
