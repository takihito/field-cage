//go:build linux

package ebpf

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang Dns ./bpf/dns.c -- -O2 -Wall -Werror -target bpf
