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

func TestParseDNSResponse_CompressionPointer(t *testing.T) {
	// buildDNSResponse writes the answer NAME as the compression pointer
	// 0xc00c (back to the question name at offset 12). A successful parse of
	// the domain and A record therefore exercises name-compression handling.
	domain := "example.com"
	ip := net.IP{1, 2, 3, 4}
	msg := buildDNSResponse(domain, ip)

	gotDomain, ips := parseDNSResponse(msg)
	if gotDomain != domain {
		t.Errorf("domain = %q, want %q", gotDomain, domain)
	}
	if len(ips) != 1 || !ips[0].Equal(ip) {
		t.Errorf("ips = %v, want [%v]", ips, ip)
	}
}

func TestParseDNSResponse_MalformedRDLength(t *testing.T) {
	// A record with RDLENGTH = 0 instead of 4, followed by trailing bytes that
	// must not be misread as the IP (regression for a mismatched-length answer
	// being parsed as an address anyway).
	domain := "example.com"
	msg := buildDNSResponse(domain, net.IP{1, 2, 3, 4})
	rdlenOff := len(msg) - 6 // offset of the RDLENGTH field in the A answer
	msg[rdlenOff] = 0x00
	msg[rdlenOff+1] = 0x00 // RDLENGTH = 0
	// Leave the 4 trailing "RDATA" bytes in place; the parser must not read them.

	gotDomain, ips := parseDNSResponse(msg)
	if gotDomain != domain {
		t.Errorf("domain = %q, want %q", gotDomain, domain)
	}
	if len(ips) != 0 {
		t.Errorf("ips = %v, want none for a mismatched RDLENGTH", ips)
	}
}

func TestParseDNSResponse_MalformedQuestionSection(t *testing.T) {
	// QDCOUNT claims 2 questions but the message ends after the first, so
	// SkipAllQuestions fails after the domain was already extracted from the
	// first question. The answer section must be dropped too: otherwise its
	// bytes happen to parse as a valid second question.
	msg := buildDNSResponse("example.com", net.IP{1, 2, 3, 4})
	msg[5] = 0x02          // QDCOUNT = 2
	msg = msg[:len(msg)-16] // truncate the 16-byte answer record

	domain, ips := parseDNSResponse(msg)
	if domain != "" || ips != nil {
		t.Errorf("expected fully empty result for a malformed question section, got domain=%q ips=%v", domain, ips)
	}
}

func TestParseResolvConf(t *testing.T) {
	data := []byte(`# managed by something
; a comment
nameserver 127.0.0.53
nameserver 8.8.8.8
nameserver 2001:4860:4860::8888
nameserver fe80::1%eth0
nameserver [2001:db8::5]
options edns0
search example.com
nameserver
`)
	got := parseResolvConf(data)
	// Both IPv4 and IPv6 nameservers are returned (resolver enforcement and
	// live-allowlisting source validation both consume this list). A zone
	// suffix ("%eth0") and surrounding brackets are stripped before parsing —
	// the zone lives in sin6_scope_id, not the address, so the plain address
	// is what enforcement and source matching need.
	want := []string{"127.0.0.53", "8.8.8.8", "2001:4860:4860::8888", "fe80::1", "2001:db8::5"}
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

func TestResolversFrom(t *testing.T) {
	stubEtc := []byte("nameserver 127.0.0.53\noptions edns0 trust-ad\n")
	realEtc := []byte("nameserver 10.0.0.2\nnameserver 2001:4860:4860::8888\n")
	run := []byte("# managed by systemd-resolved\nnameserver 168.63.129.16\nnameserver 10.0.0.2\n")

	toStrings := func(ips []net.IP) []string {
		var out []string
		for _, ip := range ips {
			out = append(out, ip.String())
		}
		return out
	}

	cases := []struct {
		name string
		etc  []byte
		run  []byte
		want []string
	}{
		// Loopback-only stub (systemd-resolved): upstream servers are merged in
		// so the stub daemon's own outbound DNS is permitted under enforcement.
		{"stub merges upstream", stubEtc, run, []string{"127.0.0.53", "168.63.129.16", "10.0.0.2"}},
		// Real resolvers in /etc/resolv.conf: the upstream file is ignored.
		{"real etc ignores run", realEtc, run, []string{"10.0.0.2", "2001:4860:4860::8888"}},
		// No nameservers at all in /etc: fall back to the upstream file.
		{"empty etc uses run", []byte("search example.com\n"), run, []string{"168.63.129.16", "10.0.0.2"}},
		// Neither file yields anything.
		{"both empty", nil, nil, nil},
		// Duplicates across files are removed.
		{"dedupe", []byte("nameserver 127.0.0.53\nnameserver 127.0.0.53\n"), []byte("nameserver 8.8.8.8\nnameserver 8.8.8.8\n"), []string{"127.0.0.53", "8.8.8.8"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := toStrings(resolversFrom(tc.etc, tc.run))
			if len(got) != len(tc.want) {
				t.Fatalf("resolversFrom = %v, want %v", got, tc.want)
			}
			for i := range got {
				if got[i] != tc.want[i] {
					t.Errorf("resolversFrom[%d] = %s, want %s (full: %v)", i, got[i], tc.want[i], got)
				}
			}
		})
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
