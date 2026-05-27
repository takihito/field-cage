// eBPF socket_filter: captures DNS response packets (UDP src port 53) and
// forwards raw DNS payload to userspace via ring buffer for parsing.
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define ETH_HLEN    14
#define IPPROTO_UDP 17
#define DNS_PORT    53
#define DNS_MAX_LEN 512

struct dns_event {
	__u32 len;
	__u8  payload[DNS_MAX_LEN];
};

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 22);
} dns_events SEC(".maps");

SEC("socket")
int capture_dns(struct __sk_buff *skb)
{
	/* Reject anything shorter than ETH + min IP header + UDP header */
	if (skb->len < ETH_HLEN + 20 + 8)
		return 0;

	/* IP protocol is at byte 9 of the IP header (ETH_HLEN + 9) */
	__u8 proto = 0;
	bpf_skb_load_bytes(skb, ETH_HLEN + 9, &proto, 1);
	if (proto != IPPROTO_UDP)
		return 0;

	/* IP IHL: lower nibble of first byte of IP header, in 4-byte units */
	__u8 ihl_byte = 0;
	bpf_skb_load_bytes(skb, ETH_HLEN, &ihl_byte, 1);
	__u32 ihl = (__u32)(ihl_byte & 0x0f) * 4;
	if (ihl < 20 || ihl > 60)
		return 0;

	/* UDP source port (first 2 bytes of UDP header) must be 53 */
	__u16 sport = 0;
	bpf_skb_load_bytes(skb, ETH_HLEN + ihl, &sport, 2);
	if (sport != bpf_htons(DNS_PORT))
		return 0;

	/* UDP length field (bytes 4-5) includes the 8-byte UDP header */
	__u16 udp_len_be = 0;
	bpf_skb_load_bytes(skb, ETH_HLEN + ihl + 4, &udp_len_be, 2);
	__u32 dns_len = (__u32)bpf_ntohs(udp_len_be);
	if (dns_len <= 8)
		return 0;
	dns_len -= 8;

	/* Mask to bound dns_len to 0..DNS_MAX_LEN-1. DNS_MAX_LEN is a power of two,
	 * so the mask gives the verifier an exact non-negative range for the
	 * bpf_skb_load_bytes length argument; a plain clamp leaves the signed
	 * minimum unproven and the verifier rejects the call. */
	dns_len &= DNS_MAX_LEN - 1;
	if (dns_len == 0)
		return 0;

	struct dns_event *ev = bpf_ringbuf_reserve(&dns_events, sizeof(*ev), 0);
	if (!ev)
		return 0;

	ev->len = dns_len;
	__u32 dns_offset = ETH_HLEN + ihl + 8;
	if (bpf_skb_load_bytes(skb, dns_offset, ev->payload, dns_len) != 0) {
		bpf_ringbuf_discard(ev, 0);
		return 0;
	}
	bpf_ringbuf_submit(ev, 0);

	/* Return 0: we collect data via ring buffer, not via the socket fd */
	return 0;
}

char LICENSE[] SEC("license") = "GPL";
