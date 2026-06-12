package ebpf

import (
	"net"
	"testing"
)

func TestDNSCache_SetAndLookup(t *testing.T) {
	cache := newDNSCache()
	ip := net.IP{93, 184, 216, 34}
	cache.set(ip, "example.com")

	got := cache.Lookup(ip)
	if got != "example.com" {
		t.Errorf("Lookup = %q, want %q", got, "example.com")
	}
}

func TestDNSCache_LookupMiss(t *testing.T) {
	cache := newDNSCache()
	got := cache.Lookup(net.IP{1, 2, 3, 4})
	if got != "" {
		t.Errorf("Lookup for unknown IP = %q, want empty", got)
	}
}
