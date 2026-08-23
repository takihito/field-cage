---
layout: default
title: field-cage - eBPF network monitoring for GitHub Actions
description: field-cage is a lightweight eBPF agent that monitors and restricts outbound network connections on GitHub Actions runners.
---

# field-cage

[![OpenSSF Scorecard](https://api.securityscorecards.dev/projects/github.com/takihito/field-cage/badge)](https://securityscorecards.dev/viewer/?uri=github.com/takihito/field-cage)

field-cage is a lightweight eBPF agent that monitors and restricts outbound network connections on GitHub Actions runners, designed to detect and prevent supply-chain attacks such as unauthorized data exfiltration or external code fetching during builds.

[日本語ドキュメント](ja/)

## Overview

field-cage hooks into the Linux kernel via eBPF to observe every outbound connection attempt in real time. It maps raw IP addresses to domain names through DNS packet monitoring, then evaluates each connection against a YAML allowlist.

- **Audit mode** — logs all connections without blocking. Safe to add to any existing workflow
- **Block mode** — default-deny: every outbound IPv4/IPv6 connection whose destination is not on the allowlist is rejected (`EPERM` returned to the process). Loopback is always permitted; DNS (port 53) is permitted only to the system's configured resolvers (opt out with `allow_all_dns: true`)

## Features

- Automatic IP-to-domain mapping via DNS packet monitoring (A and AAAA records)
- YAML policy: exact domain and IP matching (case-insensitive), IPv4 and IPv6
- CIDR subnet matching (e.g. `10.0.0.0/8`, `203.0.113.0/24`, `2001:db8::/32`)
- Dual-stack aware: IPv4-mapped IPv6 connections (`::ffff:a.b.c.d`, used by Node.js/Java dual-stack sockets) are enforced against the IPv4 allowlist
- Zero dependency on Node.js / `node_modules` — single fully-static Go binary

## Quick Start

Add the composite action to a workflow with an inline allowlist:

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

See [Usage](usage) for the policy file format and standalone binary options, and [GitHub Actions](github-actions) for composite action inputs, examples, and release verification.

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
| `SKIP(self)` | connection made by the agent's own process (its startup DNS lookups to seed the allowlist), not by the workflow being monitored |

## Supply-Chain Security

- Release binaries are verified with SHA-256 checksums by the composite action before execution
- Each release includes a [cosign](https://github.com/sigstore/cosign) keyless signature bundle
- [SLSA Level 3](https://slsa.dev/) provenance attached to releases
- [OpenSSF Scorecard](https://securityscorecards.dev/viewer/?uri=github.com/takihito/field-cage) published

See the [GitHub repository](https://github.com/takihito/field-cage) for source, issues, and releases.
