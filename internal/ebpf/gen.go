//go:build linux

package ebpf

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang Connect ./bpf/connect.c -- -O2 -Wall -Werror -target bpf
