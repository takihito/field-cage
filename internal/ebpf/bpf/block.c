// eBPF cgroup/connect4 program for field-cage enforcement mode.
// Default-deny allowlist model: a connection is rejected with EPERM unless its
// destination is explicitly permitted. DNS (port 53) and loopback are always
// allowed so that name resolution and local services keep working; every other
// destination must be present in the allowed_ips map.
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

// allowed_ips: IPv4 addresses (network byte order) that are permitted.
// Seeded from Go userspace at startup (resolved allowlist domains + explicit IP
// entries) and updated as DNS responses for allowlisted domains are observed.
// Keys are raw __u32 IPv4 addresses; value 1 means allowed.
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 4096);
	__type(key, __u32);
	__type(value, __u8);
} allowed_ips SEC(".maps");

SEC("cgroup/connect4")
int block_connect(struct bpf_sock_addr *ctx)
{
	// Always allow DNS (port 53) so name resolution works under default-deny.
	// user_port is in network byte order.
	if (ctx->user_port == bpf_htons(53))
		return 1; // allow

	__u32 daddr = ctx->user_ip4; // network byte order

	// Always allow loopback (127.0.0.0/8): the high-order octet is 127.
	if ((bpf_ntohl(daddr) >> 24) == 127)
		return 1; // allow

	__u8 *allowed = bpf_map_lookup_elem(&allowed_ips, &daddr);
	if (allowed)
		return 1; // allow: destination is on the allowlist

	// Default deny: cgroup/connect4 returning 0 causes the kernel to fail the
	// connect() syscall with EPERM.
	return 0;
}

char LICENSE[] SEC("license") = "GPL";
