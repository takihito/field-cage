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

// lpm_key6 is the IPv6 counterpart: prefixlen up to 128, addr holds the raw
// 16-byte IPv6 address in wire (network byte) order.
struct lpm_key6 {
	__u32 prefixlen;
	__u8  addr[16];
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

// allowed_ips6: LPM trie of permitted IPv6 prefixes (same model as
// allowed_ips). A /128 entry permits a single host.
struct {
	__uint(type, BPF_MAP_TYPE_LPM_TRIE);
	__uint(max_entries, 4096);
	__type(key, struct lpm_key6);
	__type(value, __u8);
	__uint(map_flags, BPF_F_NO_PREALLOC);
} allowed_ips6 SEC(".maps");

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

SEC("cgroup/connect6")
int block_connect6(struct bpf_sock_addr *ctx)
{
	// Always allow DNS (port 53) so name resolution works under default-deny.
	if (ctx->user_port == bpf_htons(53))
		return 1; // allow

	// user_ip6 holds the destination as four 32-bit words in network byte
	// order; copying them in sequence yields the 16 raw wire-order bytes.
	__u32 a0 = ctx->user_ip6[0];
	__u32 a1 = ctx->user_ip6[1];
	__u32 a2 = ctx->user_ip6[2];
	__u32 a3 = ctx->user_ip6[3];

	// Always allow the IPv6 loopback ::1 (counterpart of 127.0.0.0/8).
	if (a0 == 0 && a1 == 0 && a2 == 0 && a3 == bpf_htonl(1))
		return 1; // allow

	// IPv4-mapped IPv6 (::ffff:a.b.c.d): dual-stack sockets (common in Node.js
	// and Java) reach IPv4 destinations through connect6. Apply the same policy
	// as connect4 by consulting the IPv4 trie, so an IPv4 allowlist entry works
	// regardless of which socket family the application used.
	if (a0 == 0 && a1 == 0 && a2 == bpf_htonl(0x0000ffff)) {
		__u32 daddr4 = a3; // network byte order

		// Loopback 127.0.0.0/8 via its IPv4-mapped form.
		if ((bpf_ntohl(daddr4) >> 24) == 127)
			return 1; // allow

		struct lpm_key key4 = {};
		key4.prefixlen = 32;
		__builtin_memcpy(key4.addr, &daddr4, 4);
		if (bpf_map_lookup_elem(&allowed_ips, &key4))
			return 1; // allow
		return 0; // deny
	}

	struct lpm_key6 key = {};
	key.prefixlen = 128;
	__builtin_memcpy(key.addr,      &a0, 4);
	__builtin_memcpy(key.addr + 4,  &a1, 4);
	__builtin_memcpy(key.addr + 8,  &a2, 4);
	__builtin_memcpy(key.addr + 12, &a3, 4);
	if (bpf_map_lookup_elem(&allowed_ips6, &key))
		return 1; // allow: destination matches an allowlisted prefix

	// Default deny (EPERM), same as block_connect.
	return 0;
}

char LICENSE[] SEC("license") = "GPL";
