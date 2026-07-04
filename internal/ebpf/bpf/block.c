// eBPF cgroup/connect4 program for field-cage enforcement mode.
// Default-deny allowlist model: a connection is rejected with EPERM unless its
// destination is explicitly permitted. DNS (port 53) and loopback are always
// allowed so that name resolution and local services keep working; every other
// destination must be present in the allowed_ips map.
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

// lpm_key is the key for the LPM trie. prefixlen is the number of significant
// bits (e.g. 32 for a single host, 24 for a /24 network). addr holds the IPv4
// address in the same byte order as ctx->user_ip4 (network byte order).
struct lpm_key {
	__u32 prefixlen;
	__u8  addr[4];
};

// allowed_ips: LPM trie of permitted IPv4 prefixes.
// Seeded from Go userspace at startup (resolved allowlist domains + explicit
// IP/CIDR entries) and updated as DNS responses for allowlisted domains are
// observed. A /32 entry permits a single host; shorter prefixes permit subnets.
// BPF_F_NO_PREALLOC is required for LPM_TRIE maps.
struct {
	__uint(type, BPF_MAP_TYPE_LPM_TRIE);
	__uint(max_entries, 4096);
	__type(key, struct lpm_key);
	__type(value, __u8);
	__uint(map_flags, BPF_F_NO_PREALLOC);
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

	// LPM trie lookup: prefixlen=32 matches the full address; the trie finds
	// the longest matching prefix (e.g. a /24 entry covers all /32 lookups
	// within that subnet).
	struct lpm_key key = {};
	key.prefixlen = 32;
	__builtin_memcpy(key.addr, &daddr, 4);

	__u8 *allowed = bpf_map_lookup_elem(&allowed_ips, &key);
	if (allowed)
		return 1; // allow: destination matches an allowlisted prefix

	// Default deny: cgroup/connect4 returning 0 causes the kernel to fail the
	// connect() syscall with EPERM.
	return 0;
}

char LICENSE[] SEC("license") = "GPL";
