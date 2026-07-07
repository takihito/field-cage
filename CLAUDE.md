# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

@AGENTS.md

## Project Overview

**field-cage** is a lightweight network monitoring and restriction tool for GitHub Actions, designed to detect and prevent supply-chain attacks (unauthorized data exfiltration or external code fetching during builds). It uses eBPF at the Linux kernel level to monitor and control network syscalls.

Key goals:
- Zero dependency on Node.js / `node_modules`
- Single fully-static binary, works on any Linux runner without configuration
- Allowlist-based outbound traffic control with Audit (log-only) and Block (enforce) modes
- Automatic allowlist suggestion from post-run logs

## Tech Stack

| Layer | Technology |
|---|---|
| Agent | Go 1.21+ |
| eBPF programs | C, compiled via `bpf2go` |
| eBPF Go bindings | `cilium/ebpf` |
| DNS packet parsing | hand-written parser (`internal/ebpf/dns_parse.go`) |
| Config format | YAML |
| Distribution | GitHub Releases via GoReleaser, Composite Action (`action.yml`) |
| Build | `CGO_ENABLED=0` fully static binary |

## Architecture

### eBPF component (C)
- `tracepoint/syscalls/sys_enter_connect` — hooks outbound connection attempts (portable across kernel versions and architectures; prefer over `kprobe/sys_connect` which is symbol-name-dependent). Also stores `bpf_ktime_get_ns()` in a `pending_connects` hash map keyed by `pid_tgid` (`u64`: upper 32 bits = tgid, lower 32 bits = pid) for connect-time measurement.
- `tracepoint/syscalls/sys_exit_connect` — paired with `sys_enter_connect`; looks up the stored timestamp by `pid_tgid` and computes elapsed nanoseconds (`connect_ns`). This value is not currently logged because non-blocking sockets return EINPROGRESS in nanoseconds (rounds to 0ms).
- `socket_filter` on port 53 — sniffs DNS response packets (UDP src port 53 over IPv4 transport) to build the IP→domain mapping; in Block mode, responses originating from a trusted resolver (or loopback) also extend the enforcement allowlist
- `cgroup/connect4` + `cgroup/connect6` — in Block mode, enforce a default-deny allowlist: return `0` (which makes the kernel fail the `connect()` with `EPERM`) for any destination not in the `allowed_ips` / `allowed_ips6` LPM tries. Loopback is always permitted. DNS (port 53) is permitted only to trusted resolvers from `/etc/resolv.conf` (`dns_resolvers` / `dns_resolvers6` maps) unless `allow_all_dns: true` opts back into unconditional port-53 access. IPv4-mapped IPv6 destinations (`::ffff:a.b.c.d`) are checked against the IPv4 maps. (An earlier design considered `bpf_override_return` on the connect tracepoint; `cgroup/connect4` was chosen instead because it enforces synchronously before the connection is made, closing the first-connection gap.)

### Go agent
- **eBPF Loader** — loads compiled eBPF programs into the kernel using `cilium/ebpf`
- **DNS Cache** — in-memory map resolving IP addresses to domain names from eBPF events
- **Policy Engine** — matches live traffic against YAML allowlist (exact domain match only, case-insensitive)
- **Reporter** — writes per-connection verdict lines to stdout in a stable format: `verdict=<V> pid=<P> tgid=<T> comm=<C> dst=<domain> (<ip>):<port>`. Verdict values: `ALLOW`, `DENY(no-domain)`, `DENY(not-in-policy)`, `SKIP(dns)`, `SKIP(loopback)`. Diagnostics go to stderr via `log/slog`; keep the stdout format stable — CI smoke tests grep it.

### GitHub Action
- Implemented as a Composite Action (`action.yml`), no TypeScript
- Downloads binary from GitHub Releases via `curl` with a pinned version tag
- Verifies the binary with `sha256sum` against a published checksum file before execution
- Runs as `sudo ./agent --config policy.yml &` in the background

## Development Commands

All build and run steps happen inside Docker (eBPF requires Linux).

```sh
# First-time setup: generate go.sum
make tidy

# Build Docker image (runs bpf2go + go build internally)
make build

# Run the agent (requires privileged access for eBPF)
make run

# Run unit tests (builder image, no privileges needed)
make test

# Run a single test
docker run --rm field-cage:builder sh -c \
  "go generate ./internal/ebpf/... && go test ./internal/ebpf/... -run TestName"
```

### Code generation

The eBPF C source (`internal/ebpf/bpf/connect.c`) is compiled by `bpf2go` into Go bindings. This generates `connect_bpfel.go` (little-endian) and `connect_bpfeb.go` (big-endian), each embedding the compiled `.o` object. These files are generated artifacts — edit `bpf/connect.c` and re-run `go generate`, do not edit the generated files directly.

### Development Environment Requirements

eBPF development requires Linux. On macOS, the Docker build container provides the environment.

- Linux kernel 5.8+ in the Docker Desktop VM (for ring buffer support)
- `clang`, `llvm`, `libbpf-dev`, `linux-headers-$(uname -r)` — installed in the builder image
- `bpf2go` — installed in the builder image at the version pinned in `go.mod`

## Getting Started

Start by studying the `cilium/ebpf` [examples](https://github.com/cilium/ebpf/tree/master/examples) to understand the C↔Go data exchange via BPF Maps before writing new eBPF programs.

Development milestones
1. Prototype: log connection IPs to console via `kprobe` ✅
2. DNS resolution: map IPs to domain names from DNS sniffing ✅
3. Enforcement: block unauthorized IPs via `cgroup/connect4` ✅
4. GitHub Action: write `action.yml` and test in a real workflow ✅ (v0.0.2)
5. Log quality: `SKIP(dns)` / `SKIP(loopback)` verdicts ✅; TCP connection timing (connect_ns is captured but not logged; pending decision on display format)
6. IPv6 support: monitoring and block-mode enforcement (`cgroup/connect6`, `allowed_ips6`) ✅
7. DNS hardening: port 53 restricted to trusted resolvers (opt-out via `allow_all_dns`), DNS-response source validation for live allowlisting ✅
