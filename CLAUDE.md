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
| DNS packet parsing | `google/gopacket` (if needed) |
| Config format | YAML |
| Distribution | GitHub Releases via GoReleaser, Composite Action (`action.yml`) |
| Build | `CGO_ENABLED=0` fully static binary |

## Planned Architecture

### eBPF component (C)
- `tracepoint/syscalls/sys_enter_connect` — hooks outbound connection attempts (portable across kernel versions and architectures; prefer over `kprobe/sys_connect` which is symbol-name-dependent)
- `socket_filter` on port 53 — sniffs DNS packets to build IP→domain mapping
- `bpf_override_return` — in Block mode, returns an error to reject unauthorized connections

### Go agent
- **eBPF Loader** — loads compiled eBPF programs into the kernel using `cilium/ebpf`
- **DNS Cache** — in-memory map resolving IP addresses to domain names from eBPF events
- **Policy Engine** — matches live traffic against YAML allowlist (exact domain match only, case-insensitive)
- **Reporter** — writes structured logs to stdout (GitHub Actions format) or a file

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
1. Prototype: log connection IPs to console via `kprobe`
2. DNS resolution: map IPs to domain names from DNS sniffing
3. Enforcement: block unauthorized IPs via `bpf_override_return`
4. GitHub Action: write `action.yml` and test in a real workflow
