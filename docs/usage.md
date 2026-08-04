---
layout: default
title: field-cage Usage
description: Policy file format and standalone binary usage for field-cage.
---

# Usage

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
> **DNS handling**: By default, port 53 is permitted only to the resolvers configured in `/etc/resolv.conf` plus loopback — this prevents a port-53 listener on an arbitrary host from being used as a general outbound tunnel. Set `allow_all_dns: true` to permit port 53 to any destination (the pre-0.x behavior). Even under the default, DNS *tunneling* through a legitimate resolver (data encoded in subdomains, resolved recursively) is not blocked; see Limitations below.

## Standalone binary

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
