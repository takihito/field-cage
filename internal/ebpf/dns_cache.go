package ebpf

import (
	"net"
	"sync"
)

// DNSCache maps IPv4 addresses to the domain name resolved to that address.
// It is safe for concurrent use.
type DNSCache struct {
	mu      sync.RWMutex
	entries map[string]string // net.IP.String() → domain
}

func newDNSCache() *DNSCache {
	return &DNSCache{entries: make(map[string]string)}
}

// Lookup returns the domain name for the given IP, or an empty string.
func (c *DNSCache) Lookup(ip net.IP) string {
	c.mu.RLock()
	v := c.entries[ip.String()]
	c.mu.RUnlock()
	return v
}

func (c *DNSCache) set(ip net.IP, domain string) {
	c.mu.Lock()
	c.entries[ip.String()] = domain
	c.mu.Unlock()
}
