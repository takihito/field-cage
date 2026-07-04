package ebpf

import (
	"net"
	"testing"
)

// buildDNSResponse constructs a minimal DNS response with one A record.
// Format: header(12) + question + answer(A record).
func buildDNSResponse(domain string, ip net.IP) []byte {
	encodeName := func(name string) []byte {
		var b []byte
		parts := splitDomain(name)
		for _, p := range parts {
			b = append(b, byte(len(p)))
			b = append(b, []byte(p)...)
		}
		b = append(b, 0) // root label
		return b
	}

	qname := encodeName(domain)

	// Header: ID=1, QR=1(response), opcode=0, QDCOUNT=1, ANCOUNT=1
	header := []byte{
		0x00, 0x01, // ID
		0x81, 0x80, // flags: QR=1, OPCODE=0, AA=0, RD=1, RA=1
		0x00, 0x01, // QDCOUNT = 1
		0x00, 0x01, // ANCOUNT = 1
		0x00, 0x00, // NSCOUNT = 0
		0x00, 0x00, // ARCOUNT = 0
	}

	// Question: QNAME + QTYPE(A=1) + QCLASS(IN=1)
	question := append(qname, 0x00, 0x01, 0x00, 0x01)

	// Answer: NAME(ptr to offset 12) + TYPE(A) + CLASS(IN) + TTL + RDLENGTH + RDATA
	answer := []byte{
		0xc0, 0x0c, // pointer to offset 12 (start of question QNAME)
		0x00, 0x01, // TYPE = A
		0x00, 0x01, // CLASS = IN
		0x00, 0x00, 0x00, 0x3c, // TTL = 60
		0x00, 0x04, // RDLENGTH = 4
		ip[0], ip[1], ip[2], ip[3],
	}

	var msg []byte
	msg = append(msg, header...)
	msg = append(msg, question...)
	msg = append(msg, answer...)
	return msg
}

func splitDomain(domain string) []string {
	var parts []string
	start := 0
	for i, c := range domain {
		if c == '.' {
			if i > start {
				parts = append(parts, domain[start:i])
			}
			start = i + 1
		}
	}
	if start < len(domain) {
		parts = append(parts, domain[start:])
	}
	return parts
}

func TestParseDNSResponse_ARecord(t *testing.T) {
	ip := net.IP{93, 184, 216, 34}
	msg := buildDNSResponse("example.com", ip)

	domain, ips := parseDNSResponse(msg)
	if domain != "example.com" {
		t.Errorf("domain = %q, want %q", domain, "example.com")
	}
	if len(ips) != 1 {
		t.Fatalf("len(ips) = %d, want 1", len(ips))
	}
	if !ips[0].Equal(ip) {
		t.Errorf("ip = %v, want %v", ips[0], ip)
	}
}

// buildDNSResponseAAAA constructs a minimal DNS response with one AAAA record.
func buildDNSResponseAAAA(domain string, ip net.IP) []byte {
	msg := buildDNSResponse(domain, net.IP{0, 0, 0, 0})
	// Replace the A answer with an AAAA answer. The A answer is 16 bytes:
	// name ptr(2) + type(2) + class(2) + ttl(4) + rdlength(2) + rdata(4).
	msg = msg[:len(msg)-16]
	answer := []byte{
		0xc0, 0x0c, // pointer to offset 12 (start of question QNAME)
		0x00, 0x1c, // TYPE = AAAA (28)
		0x00, 0x01, // CLASS = IN
		0x00, 0x00, 0x00, 0x3c, // TTL = 60
		0x00, 0x10, // RDLENGTH = 16
	}
	answer = append(answer, ip.To16()...)
	return append(msg, answer...)
}

func TestParseDNSResponse_AAAARecord(t *testing.T) {
	ip := net.ParseIP("2001:db8::1")
	msg := buildDNSResponseAAAA("example.com", ip)

	domain, ips := parseDNSResponse(msg)
	if domain != "example.com" {
		t.Errorf("domain = %q, want %q", domain, "example.com")
	}
	if len(ips) != 1 {
		t.Fatalf("len(ips) = %d, want 1", len(ips))
	}
	if !ips[0].Equal(ip) {
		t.Errorf("ip = %v, want %v", ips[0], ip)
	}
}

func TestParseDNSResponse_NotResponse(t *testing.T) {
	// QR bit = 0 → query, not response
	msg := buildDNSResponse("example.com", net.IP{1, 2, 3, 4})
	msg[2] = 0x01 // clear QR bit
	domain, ips := parseDNSResponse(msg)
	if domain != "" || len(ips) != 0 {
		t.Errorf("expected empty result for query packet, got domain=%q ips=%v", domain, ips)
	}
}

func TestParseDNSResponse_TooShort(t *testing.T) {
	domain, ips := parseDNSResponse([]byte{0x01, 0x02})
	if domain != "" || len(ips) != 0 {
		t.Errorf("expected empty result for short data")
	}
}

func TestReadDNSName_WithPointer(t *testing.T) {
	// Build a message where the answer NAME uses a compression pointer.
	// Pointer 0xc00c points to offset 12 which holds "example.com".
	domain := "example.com"
	ip := net.IP{1, 2, 3, 4}
	msg := buildDNSResponse(domain, ip)

	// The answer NAME starts at offset 29:
	//   12 (header)
	// +  8 (0x07 "example")
	// +  4 (0x03 "com")
	// +  1 (0x00 root label)     = 13 bytes QNAME
	// +  2 (QTYPE) + 2 (QCLASS) =  4 bytes → question = 17 bytes
	// = 12 + 17 = 29
	// At offset 29 lies 0xc0 0x0c — the compression pointer — which must be
	// followed back to offset 12 to reconstruct "example.com".
	const answerNameOffset = 29
	got, _, ok := readDNSName(msg, answerNameOffset)
	if !ok {
		t.Fatal("readDNSName returned not ok")
	}
	if got != domain {
		t.Errorf("got %q, want %q", got, domain)
	}
}

func TestParseResolvConf(t *testing.T) {
	data := []byte(`# managed by something
; a comment
nameserver 127.0.0.53
nameserver 8.8.8.8
nameserver 2001:4860:4860::8888
options edns0
search example.com
nameserver
`)
	got := parseResolvConf(data)
	// Both IPv4 and IPv6 nameservers are returned (resolver enforcement and
	// live-allowlisting source validation both consume this list).
	want := []string{"127.0.0.53", "8.8.8.8", "2001:4860:4860::8888"}
	if len(got) != len(want) {
		t.Fatalf("parseResolvConf returned %d entries, want %d: %v", len(got), len(want), got)
	}
	gotSet := make(map[string]struct{}, len(got))
	for _, ip := range got {
		gotSet[ip.String()] = struct{}{}
	}
	for _, w := range want {
		if _, ok := gotSet[w]; !ok {
			t.Errorf("expected nameserver %s to be parsed, got %v", w, got)
		}
	}
}

func TestIsTrustedSourceIP(t *testing.T) {
	trusted := map[string]struct{}{"8.8.8.8": {}}
	cases := []struct {
		ip   string
		want bool
	}{
		{"8.8.8.8", true},    // configured nameserver
		{"127.0.0.53", true}, // loopback (stub resolver) always trusted
		{"127.0.0.1", true},  // loopback
		{"1.2.3.4", false},   // arbitrary / forged source
		{"9.9.9.9", false},   // not configured
	}
	for _, tc := range cases {
		got := isTrustedSourceIP(net.ParseIP(tc.ip), trusted)
		if got != tc.want {
			t.Errorf("isTrustedSourceIP(%s) = %v, want %v", tc.ip, got, tc.want)
		}
	}
	if isTrustedSourceIP(nil, trusted) {
		t.Error("nil IP should not be trusted")
	}
}
