//go:build linux

package ebpf

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang Block ./bpf/block.c -- -O2 -Wall -Werror -target bpf
