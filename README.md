# field-cage

A lightweight eBPF agent that monitors and restricts outbound network connections on GitHub Actions runners, designed to detect and prevent supply-chain attacks such as unauthorized data exfiltration or external code fetching during builds.

## Overview

field-cage hooks into the Linux kernel via eBPF to observe every outbound connection attempt in real time. It maps raw IP addresses to domain names through DNS sniffing, then evaluates each connection against a YAML allowlist.

- **Audit mode** — logs all connections without blocking. Safe to add to any existing workflow
- **Block mode** — denies connections not listed in the policy (`EPERM` returned to the process)

## Features

- Zero runtime dependencies. Single fully-static binary, no Node.js required
- Automatic IP-to-domain mapping via DNS packet sniffing
- YAML policy: exact domain and IP matching (case-insensitive)

## Log output

```
verdict=ALLOW                pid=1234   tgid=1234   comm=curl             dst=api.github.com (140.82.121.5):443
verdict=DENY(not-in-policy)  pid=1235   tgid=1235   comm=python3          dst=suspicious.example.com (93.184.216.34):443
verdict=DENY(no-domain)      pid=1236   tgid=1236   comm=curl             dst=93.184.216.34:80
```

| verdict | meaning |
|---------|---------|
| `ALLOW` | connection permitted by policy |
| `DENY(not-in-policy)` | domain resolved but not in the allowlist |
| `DENY(no-domain)` | IP-only connection; DNS not yet resolved |

## Policy file

```yaml
mode: block   # audit or block

allowlist:
  - github.com
  - api.github.com
  - codeload.github.com
  - objects.githubusercontent.com
  - 1.2.3.4        # raw IP addresses are supported
```

> **Note**: Wildcards (`*.github.com`) are not supported. List each subdomain explicitly.

## Usage

```sh
# Audit mode — log all connections, no policy file required
sudo ./field-cage

# Audit mode with a policy file
sudo ./field-cage --config policy.yml

# Block mode — deny connections not in the allowlist
sudo ./field-cage --config policy.yml --mode block
```

## Development

eBPF development requires Linux. On macOS, all build and test steps run inside Docker.

```sh
# First-time setup: generate go.sum
make tidy

# Build the Docker image (runs bpf2go + go build internally)
make build

# Run the agent with the privileges required for eBPF
make run

# Start a local verification container (curl/wget available for traffic generation)
make run-dev

# Stop the run-dev container
make stop-dev

# Run unit tests (no privileges needed)
make test

# Install git hooks (runs make test before every push)
make setup-hooks
```

## Limitations

- **Block mode first-connection slip-through**: enforcement is reactive. The first outbound connection to a newly-denied IP passes through before the BPF map is updated. A future milestone will flip to a default-deny allowlist model to close this gap.
- **IPv4 only**: IPv6 connections are not yet monitored or blocked.
- **DNS sniffing requires `CAP_NET_RAW`**: In block mode, failure to start the DNS watcher is fatal (fail-closed). In audit mode it is best-effort.

## Architecture

```
                     Linux kernel
┌─────────────────────────────────────────────┐
│  tracepoint/sys_enter_connect               │
│    → pushes connect events to ring buffer   │
│                                             │
│  socket_filter (port 53)                    │
│    → pushes DNS responses to ring buffer    │
│                                             │
│  cgroup/connect4  (block mode only)         │
│    → consults blocked_ips map; 0=deny/1=allow│
└─────────────────────────────────────────────┘
                     ↕ cilium/ebpf
┌─────────────────────────────────────────────┐
│  field-cage agent (Go)                      │
│    DNS Cache    : IP → domain name          │
│    Policy Engine: evaluates YAML allowlist  │
│    Reporter     : writes verdict to stdout  │
└─────────────────────────────────────────────┘
```

## Tech stack

| Layer | Technology |
|-------|-----------|
| Agent | Go 1.22 |
| eBPF programs | C, compiled via `bpf2go` |
| eBPF Go bindings | `cilium/ebpf v0.14.0` |
| Policy config | YAML (`gopkg.in/yaml.v3`) |
| Build | `CGO_ENABLED=0` fully-static binary |
