# field-cage

A lightweight eBPF agent that monitors and restricts outbound network connections on GitHub Actions runners, designed to detect and prevent supply-chain attacks such as unauthorized data exfiltration or external code fetching during builds.

## Overview

field-cage hooks into the Linux kernel via eBPF to observe every outbound connection attempt in real time. It maps raw IP addresses to domain names through DNS packet monitoring, then evaluates each connection against a YAML allowlist.

- **Audit mode** — logs all connections without blocking. Safe to add to any existing workflow
- **Block mode** — default-deny: every outbound connection whose destination is not on the allowlist is rejected (`EPERM` returned to the process). DNS (port 53) and loopback are always permitted

## Features

- Automatic IP-to-domain mapping via DNS packet monitoring
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
| `DENY(no-domain)` | domain unknown (IP direct, or DNS response not yet observed) |

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

# Block mode — default-deny; only allowlisted destinations are permitted.
# A policy file is required (block mode without one would deny all traffic).
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

## Block mode enforcement model

Block mode is **default-deny**: the `cgroup/connect4` program rejects every outbound IPv4 connection unless its destination IP is on the allowlist. The allowlist is built by:

1. **Startup seeding** — explicit IP entries are added directly, and each allowlisted domain is resolved (IPv4) and its addresses added.
2. **Live DNS observation** — when a DNS response for an allowlisted domain is seen on the wire, its A-record IPs are added to the allowlist before the application connects. Only responses originating from a configured resolver (the `nameserver` entries in `/etc/resolv.conf`) or from loopback are trusted for this; responses from any other source are cached for logging but never extend the kernel allowlist, so a forged response with a spoofed source port 53 cannot poison it.

DNS (destination port 53) and loopback (`127.0.0.0/8`) are always permitted so that name resolution and local services keep working. A policy file is required in block mode; without one the agent refuses to start rather than deny all traffic.

## Limitations

- **First-connection race (fail-closed)**: a connection to an allowlisted domain may be denied on the very first attempt if the application connects before the observed DNS response is applied to the map. This fails *closed* (the connection is denied, not leaked); the application's retry succeeds once the map is updated. Startup seeding avoids this for domains resolvable at launch.
- **IPv4 only**: IPv6 connections (`connect6`) are not yet hooked, so they are **not enforced** in block mode. IPv6 enforcement is planned.
- **DNS over port 53 is always allowed**: this is required for name resolution to function under default-deny. As a side effect, low-bandwidth exfiltration via DNS tunneling is not blocked (it is still visible in the DNS monitoring logs).
- **Live allowlisting trusts resolver-sourced responses**: only DNS responses from a configured resolver or loopback extend the allowlist. Forging a trusted response requires binding source port 53 (`CAP_NET_BIND_SERVICE`) or a raw socket (`CAP_NET_RAW`) — capabilities a normal build step does not hold; an attacker who already has them can subvert enforcement by other means.
- **Live allowlisting only observes plaintext IPv4 UDP DNS (port 53)**: DNS carried over IPv6 transport, TCP, or encrypted (DoH/DoT) is not observed, so it cannot extend the allowlist. Domains resolved that way are only covered by startup seeding; if their addresses rotate afterwards, block mode will deny the new IPs (fail-closed). Keep such domains pinned by IP in the policy, or ensure they resolve via plaintext IPv4 UDP.
- **DNS packet monitoring requires `CAP_NET_RAW`**: In block mode, failure to start DNS packet monitoring is fatal (fail-closed). In audit mode it is best-effort.

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
│    → default-deny; allows port 53, loopback,│
│      and IPs in the allowed_ips map (1=allow)│
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
