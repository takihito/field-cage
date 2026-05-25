package ebpf

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang Connect connect.c -- -O2 -g -Wall -Werror -target bpf
