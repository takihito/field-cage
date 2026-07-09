// eBPF cgroup/connect4 + connect6 programs for field-cage enforcement mode.
// Default-deny allowlist model: a connection is rejected with EPERM unless its
// destination is explicitly permitted. Loopback is always allowed. DNS
// (port 53) is additionally permitted to trusted resolvers (seeded from
// /etc/resolv.conf) so that name resolution works without turning port 53
// into a general outbound tunnel to arbitrary hosts; this can be relaxed to
// "allow any port-53 destination" via the config map (opt-in, default off).
// Any destination in the allowed_ips / allowed_ips6 maps is reachable on any
// port, including 53; everything else is denied.
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

// in6_key is a fixed 16-byte IPv6 address used as an exact-match hash key.
struct in6_key {
	__u8 addr[16];
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

// dns_resolvers / dns_resolvers6: exact-match sets of trusted resolver IPs
// (from /etc/resolv.conf). A port-53 connection is permitted to these
// destinations. Loopback resolvers (e.g. systemd-resolved on 127.0.0.53) are
// already covered by the loopback rule and need not be listed here.
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 16);
	__type(key, __u32); // IPv4 address, network byte order
	__type(value, __u8);
} dns_resolvers SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 16);
	__type(key, struct in6_key);
	__type(value, __u8);
} dns_resolvers6 SEC(".maps");

// config: single-entry runtime configuration set from Go userspace.
//   index 0 = allow_all_dns: when non-zero, any port-53 destination is
//             permitted (legacy behavior). Default 0 (resolver-restricted).
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u8);
} config SEC(".maps");

// dns_allow_all reports whether the allow_all_dns opt-in is enabled.
static __always_inline int dns_allow_all(void)
{
	__u32 idx = 0;
	__u8 *v = bpf_map_lookup_elem(&config, &idx);
	return v && *v;
}

// check_ipv4 applies the IPv4 default-deny policy to a destination address
// (network byte order) and port (ctx->user_port, network byte order in its low
// 16 bits). Returns 1 to allow, 0 to deny. Shared by cgroup/connect4 and the
// IPv4-mapped IPv6 path in cgroup/connect6 so the two cannot drift: a change to
// the IPv4 policy (loopback, DNS resolver, or allowlist handling) is applied to
// both socket families at once.
static __always_inline int check_ipv4(__u32 daddr, __u32 dport)
{
	// Always allow loopback (127.0.0.0/8): the high-order octet is 127.
	// This also covers loopback DNS resolvers (e.g. systemd-resolved).
	if ((bpf_ntohl(daddr) >> 24) == 127)
		return 1; // allow

	// DNS (port 53): permit only to trusted resolvers unless allow_all_dns is
	// set. Any other port-53 destination still gets a chance below in case it
	// is an explicitly allowlisted IP; otherwise it is denied (fail-closed).
	if (dport == bpf_htons(53)) {
		if (dns_allow_all())
			return 1; // opt-in: allow any DNS destination
		if (bpf_map_lookup_elem(&dns_resolvers, &daddr))
			return 1; // allow: trusted resolver
	}

	// LPM trie lookup: prefixlen=32 matches the full address; the trie finds
	// the longest matching prefix (e.g. a /24 entry covers all /32 lookups
	// within that subnet).
	struct lpm_key key = {};
	key.prefixlen = 32;
	__builtin_memcpy(key.addr, &daddr, 4);

	if (bpf_map_lookup_elem(&allowed_ips, &key))
		return 1; // allow: destination matches an allowlisted prefix

	// Default deny: returning 0 causes the kernel to fail the connect() syscall
	// with EPERM.
	return 0;
}

SEC("cgroup/connect4")
int block_connect(struct bpf_sock_addr *ctx)
{
	return check_ipv4(ctx->user_ip4, ctx->user_port);
}

SEC("cgroup/connect6")
int block_connect6(struct bpf_sock_addr *ctx)
{
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
	// as connect4 by consulting the IPv4 maps (via check_ipv4), so an IPv4
	// allowlist / resolver entry works regardless of which socket family the
	// application used.
	if (a0 == 0 && a1 == 0 && a2 == bpf_htonl(0x0000ffff))
		return check_ipv4(a3, ctx->user_port);

	// Native IPv6 DNS (port 53): permit to trusted resolvers (or any
	// destination when allow_all_dns is set). A non-resolver port-53
	// destination is not rejected here — it falls through to the allowlist
	// lookup below like any other port, so an explicitly allowlisted IPv6
	// address is still reachable on port 53; otherwise default-deny applies.
	if (ctx->user_port == bpf_htons(53)) {
		if (dns_allow_all())
			return 1;
		struct in6_key rk = {};
		__builtin_memcpy(rk.addr,      &a0, 4);
		__builtin_memcpy(rk.addr + 4,  &a1, 4);
		__builtin_memcpy(rk.addr + 8,  &a2, 4);
		__builtin_memcpy(rk.addr + 12, &a3, 4);
		if (bpf_map_lookup_elem(&dns_resolvers6, &rk))
			return 1; // trusted resolver
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
