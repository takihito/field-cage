# field-cage

[![OpenSSF Scorecard](https://api.securityscorecards.dev/projects/github.com/takihito/field-cage/badge)](https://securityscorecards.dev/viewer/?uri=github.com/takihito/field-cage)

**[Documentation](https://takihito.github.io/field-cage/)** | [日本語ドキュメント](https://takihito.github.io/field-cage/ja/)

A lightweight eBPF agent that monitors and restricts outbound network connections on GitHub Actions runners, designed to detect and prevent supply-chain attacks such as unauthorized data exfiltration or external code fetching during builds.

## Overview

field-cage hooks into the Linux kernel via eBPF to observe every outbound connection attempt in real time. It maps raw IP addresses to domain names through DNS packet monitoring, then evaluates each connection against a YAML allowlist.

- **Audit mode** — logs all connections without blocking. Safe to add to any existing workflow
- **Block mode** — default-deny: every outbound IPv4/IPv6 connection whose destination is not on the allowlist is rejected (`EPERM` returned to the process). Loopback is always permitted; DNS (port 53) is permitted only to the system's configured resolvers (opt out with `allow_all_dns: true`)

## Features

- Automatic IP-to-domain mapping via DNS packet monitoring (A and AAAA records)
- YAML policy: exact domain and IP matching (case-insensitive), IPv4 and IPv6
- CIDR subnet matching (e.g. `10.0.0.0/8`, `203.0.113.0/24`, `2001:db8::/32`)
- Dual-stack aware: IPv4-mapped IPv6 connections (`::ffff:a.b.c.d`, used by Node.js/Java dual-stack sockets) are enforced against the IPv4 allowlist

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
| `SKIP(dns)` | DNS traffic exempt from policy evaluation (trusted resolver or loopback; any port-53 destination when `allow_all_dns` is set or no policy is loaded) |
| `SKIP(loopback)` | loopback destination (`127.0.0.0/8`, `::1`), excluded from enforcement |

## Policy file

```yaml
mode: block          # optional: audit or block; defaults to audit when omitted
                     # (the --mode flag overrides this in either case)
allow_all_dns: false # optional; see "DNS handling" below (default false)

allowlist:
  - github.com
  - api.github.com
  - codeload.github.com
  - objects.githubusercontent.com
  - 1.2.3.4             # single IPv4 address
  - 2001:db8::1         # single IPv6 address
  - 10.0.0.0/8          # IPv4 CIDR subnet (private range)
  - 203.0.113.0/24      # any /N prefix length is supported
  - 2001:db8::/32       # IPv6 CIDR subnet
```

> **Note**: Wildcards (`*.github.com`) are not supported — an entry containing `*` is rejected when the policy is loaded. List each subdomain explicitly.
>
> **Strict keys**: Unknown keys are rejected when the policy is loaded, so a misspelled key (e.g. `mdoe:`) fails fast instead of silently falling back to defaults.
>
> **CIDR**: A CIDR entry seeds the eBPF LPM trie directly, so all addresses in the subnet are permitted without per-IP DNS resolution.
>
> **DNS handling**: By default, port 53 is permitted only to the resolvers configured in `/etc/resolv.conf` plus loopback — this prevents a port-53 listener on an arbitrary host from being used as a general outbound tunnel. Set `allow_all_dns: true` to permit port 53 to any destination (the pre-0.x behavior). Even under the default, DNS *tunneling* through a legitimate resolver (data encoded in subdomains, resolved recursively) is not blocked; see Limitations.

## Usage

### Install

```sh
curl -fsSL https://takihito.github.io/field-cage/install.sh | sh
```

Installs to `~/.local/bin` by default (no `sudo` required for installation). To change the install directory:

```sh
curl -fsSL https://takihito.github.io/field-cage/install.sh | sudo FIELD_CAGE_INSTALL_DIR=/usr/local/bin sh
```

Requires Linux (`amd64` or `arm64`) — field-cage depends on eBPF and has no macOS or Windows build. For pre-built binaries or manual downloads, see the [Releases](https://github.com/takihito/field-cage/releases) page.

### Run

```sh
# Audit mode — log all connections, no policy file required
sudo field-cage

# Audit mode with a policy file
sudo field-cage --config policy.yml

# Block mode — default-deny; only allowlisted destinations are permitted.
# A policy file is required (block mode without one would deny all traffic).
sudo field-cage --config policy.yml --mode block

# Print version
field-cage --version
```

> `sudo` resets `PATH` on some systems, so if `sudo field-cage` reports "command not found", use the full path (e.g. `sudo ~/.local/bin/field-cage`) or run `sudo` with `-E`/`--preserve-env=PATH`.

## GitHub Actions

Use the composite action to run field-cage on a runner. It downloads the
pinned release binary, verifies its SHA-256 checksum, and starts the agent in
the background for the rest of the job.

**Inline allowlist** (no separate file needed):

```yaml
- uses: takihito/field-cage@v0.1.0
  with:
    version: v0.1.0
    mode: block
    allow: |
      github.com
      api.github.com
      objects.githubusercontent.com
      registry.npmjs.org
```

**External config file** (for complex or shared policies):

```yaml
- uses: takihito/field-cage@v0.1.0
  with:
    version: v0.1.0                          # must match the `uses:` ref
    config: .github/field-cage-policy.yml    # omit for audit mode with no policy
    mode: audit                              # audit (log-only) or block
```

`allow` and `config` are mutually exclusive — using both at the same time is an error.

- **Audit mode never blocks traffic** — it only logs outbound connections.
  This action requires a Linux runner (`ubuntu-*`, hosted or self-hosted)
  with passwordless `sudo` and eBPF support; on macOS/Windows runners,
  unsupported architectures, or restricted self-hosted Linux runners, the
  action fails to download or start the agent, which fails the job
  regardless of mode.
- The agent runs in the background; **view its log in a later step**, e.g.
  `cat /tmp/field-cage.log` (path configurable via the `log-file` input), or
  upload it as an artifact. Composite actions cannot run an automatic
  post-job step, so log collection and shutdown are left to the caller.
- See [`.github/field-cage-policy.example.yml`](.github/field-cage-policy.example.yml)
  for a sample policy.

### Releases

Binaries (`linux/amd64`, `linux/arm64`) and a `checksums.txt` are published to
GitHub Releases by [GoReleaser](https://goreleaser.com). Versioning is managed
by [tagpr](https://github.com/Songmu/tagpr): merging the auto-maintained
release PR pushes a `vX.Y.Z` tag, which triggers the release build.

Each release includes a [cosign](https://github.com/sigstore/cosign) keyless
signature bundle (`checksums.txt.bundle`) and a
[SLSA Level 3](https://slsa.dev/spec/v1.0/levels) provenance attestation
(`checksums.txt.intoto.jsonl`), both published as release assets.

**Verify the checksum signature:**

```sh
cosign verify-blob \
  --bundle checksums.txt.bundle \
  --certificate-identity "https://github.com/takihito/field-cage/.github/workflows/release.yml@refs/tags/vX.Y.Z" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
  checksums.txt
```

**Verify SLSA provenance:**

```sh
slsa-verifier verify-artifact \
  --provenance-path checksums.txt.intoto.jsonl \
  --source-uri github.com/takihito/field-cage \
  --source-tag vX.Y.Z \
  field-cage_linux_amd64   # or field-cage_linux_arm64
```

> Maintainer note: tagpr must push the tag with a PAT (repo scope) stored as the
> `TAGPR_TOKEN` secret — a tag pushed by the default `GITHUB_TOKEN` would not
> trigger the release workflow.

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

Block mode is **default-deny**: the `cgroup/connect4` and `cgroup/connect6` programs reject every outbound IPv4/IPv6 connection unless its destination IP is on the allowlist. IPv4-mapped IPv6 destinations (`::ffff:a.b.c.d`, the path dual-stack runtimes such as Node.js and Java take to IPv4 hosts) are checked against the IPv4 allowlist, so one IPv4 entry covers both socket families. The allowlist is built by:

1. **Startup seeding** — explicit IP and CIDR entries are added directly, and each allowlisted domain is resolved (A and AAAA) and its addresses added.
2. **Live DNS observation** — when a DNS response for an allowlisted domain is seen on the wire, its A/AAAA-record IPs are added to the allowlist before the application connects. Only responses originating from a configured resolver (the `nameserver` entries in `/etc/resolv.conf`) or from loopback are trusted for this; responses from any other source are cached for logging but never extend the kernel allowlist, so a forged response with a spoofed source port 53 cannot poison it.

Loopback (`127.0.0.0/8` and `::1`) is always permitted so that local services keep working. DNS (destination port 53) is permitted only to the system's resolvers (plus loopback) so that name resolution works without turning port 53 into a general outbound tunnel to arbitrary hosts; set `allow_all_dns: true` in the policy to restore unconditional port-53 access. Resolvers are discovered from `/etc/resolv.conf`; when it lists only a loopback stub (systemd-resolved's `127.0.0.53`), the stub's upstream servers from `/run/systemd/resolve/resolv.conf` are permitted as well — enforcement applies to the stub daemon's own outbound queries too, so its upstreams must be reachable. If no resolvers can be determined at startup, only loopback DNS is permitted (fail-closed). Denied port-53 connections are reported as `DENY`, not `SKIP(dns)`. A policy file is required in block mode; without one the agent refuses to start rather than deny all traffic.

## Limitations

- **First-connection race (fail-closed)**: a connection to an allowlisted domain may be denied on the very first attempt if the application connects before the observed DNS response is applied to the map. This fails *closed* (the connection is denied, not leaked); the application's retry succeeds once the map is updated. Startup seeding avoids this for domains resolvable at launch.
- **DNS tunneling through a legitimate resolver is not blocked**: port 53 to configured resolvers (and loopback) is permitted so name resolution works. An attacker can still encode data in subdomains and have a trusted resolver recursively resolve them, which no resolver-IP restriction can prevent. This is low-bandwidth and remains visible in the DNS monitoring logs. Note the default *does* block the coarser abuse of pointing port 53 at an arbitrary host as a direct tunnel — set `allow_all_dns: true` to disable that restriction.
- **Live allowlisting trusts resolver-sourced responses**: only DNS responses from a configured resolver or loopback extend the allowlist. Forging a trusted response requires binding source port 53 (`CAP_NET_BIND_SERVICE`) or a raw socket (`CAP_NET_RAW`) — capabilities a normal build step does not hold; an attacker who already has them can subvert enforcement by other means.
- **Live allowlisting only observes plaintext UDP DNS over IPv4 transport (port 53)**: DNS carried over IPv6 transport, TCP, or encrypted (DoH/DoT) is not observed, so it cannot extend the allowlist — this applies to both A and AAAA records (AAAA answers *are* observed when the query travels over IPv4 transport, the common case). Domains resolved via unobserved channels are only covered by startup seeding; if their addresses rotate afterwards, block mode will deny the new IPs (fail-closed). Keep such domains pinned by IP in the policy, or ensure they resolve via plaintext UDP over IPv4.
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
│  cgroup/connect4 + connect6 (block mode)    │
│    → default-deny; allows loopback, port 53 │
│      to trusted resolvers, and IPs in the   │
│      allowed_ips / allowed_ips6 LPM tries   │
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
| Agent | Go 1.25 |
| eBPF programs | C, compiled via `bpf2go` |
| eBPF Go bindings | `cilium/ebpf v0.22.0` |
| Policy config | YAML (`gopkg.in/yaml.v3`) |
| Build | `CGO_ENABLED=0` fully-static binary |
