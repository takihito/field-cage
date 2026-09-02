# Changelog

Release notes are maintained automatically by [tagpr](https://github.com/Songmu/tagpr).

## [v0.1.5](https://github.com/takihito/field-cage/compare/v0.1.4...v0.1.5) - 2026-09-02

- build(deps): Bump Songmu/tagpr from 1.20.1 to 1.20.2 by @dependabot[bot] in https://github.com/takihito/field-cage/pull/108
- build(deps): Bump the codeql-action group with 3 updates by @dependabot[bot] in https://github.com/takihito/field-cage/pull/107

## [v0.1.4](https://github.com/takihito/field-cage/compare/v0.1.3...v0.1.4) - 2026-08-26

- report: decorate markdown title with seedling/clover emoji by @takihito in https://github.com/takihito/field-cage/pull/105

## [v0.1.3](https://github.com/takihito/field-cage/compare/v0.1.2...v0.1.3) - 2026-08-24

- ci: bump codeql-action init and analyze together to v4.37.7 by @takihito in https://github.com/takihito/field-cage/pull/100
- build(deps): Bump golang.org/x/net from 0.57.0 to 0.58.0 by @dependabot[bot] in https://github.com/takihito/field-cage/pull/86
- ci: group codeql-action dependabot updates into one PR by @takihito in https://github.com/takihito/field-cage/pull/102
- ci: tighten GITHUB_TOKEN permissions per Scorecard's Token-Permissions check by @takihito in https://github.com/takihito/field-cage/pull/103
- build(deps): Bump the codeql-action group with 3 updates by @dependabot[bot] in https://github.com/takihito/field-cage/pull/104

## [v0.1.2](https://github.com/takihito/field-cage/compare/v0.1.1...v0.1.2) - 2026-08-23

- Add SKIP(self) verdict for the agent's own startup DNS probe connects by @takihito in https://github.com/takihito/field-cage/pull/97
- build(deps): Bump github/codeql-action/upload-sarif from 4.37.3 to 4.37.7 by @dependabot[bot] in https://github.com/takihito/field-cage/pull/89
- build(deps): Bump step-security/harden-runner from 2.20.0 to 2.21.0 by @dependabot[bot] in https://github.com/takihito/field-cage/pull/88

## [v0.1.1](https://github.com/takihito/field-cage/compare/v0.1.0...v0.1.1) - 2026-08-21

- Auto-stop the agent to prevent block-mode jobs from hanging (Phase 1) by @takihito in https://github.com/takihito/field-cage/pull/95

## [v0.1.0](https://github.com/takihito/field-cage/compare/v0.0.8...v0.1.0) - 2026-08-21

- chore: bump version to 0.1.0 by @takihito in https://github.com/takihito/field-cage/pull/76
- build(deps): Bump actions/setup-go from 6.4.0 to 7.0.0 by @dependabot[bot] in https://github.com/takihito/field-cage/pull/72
- build(deps): Bump github/codeql-action/analyze from 4.36.2 to 4.37.2 by @dependabot[bot] in https://github.com/takihito/field-cage/pull/73
- docs: add GitHub Pages site under docs/ by @takihito in https://github.com/takihito/field-cage/pull/78
- docs: add curl-based install script by @takihito in https://github.com/takihito/field-cage/pull/84
- docs: add install instructions to README, fix doc/code drift by @takihito in https://github.com/takihito/field-cage/pull/85
- build(deps): Bump ossf/scorecard-action from 2.4.3 to 2.4.4 by @dependabot[bot] in https://github.com/takihito/field-cage/pull/83
- build(deps): Bump github/codeql-action/upload-sarif from 4.36.2 to 4.37.3 by @dependabot[bot] in https://github.com/takihito/field-cage/pull/81
- Add report subcommand + GitHub Actions job summary/annotations by @takihito in https://github.com/takihito/field-cage/pull/91
- ci: render smoke-test connection log as a job summary by @takihito in https://github.com/takihito/field-cage/pull/93
- docs: document report follow-up fixes from PR #91 review by @takihito in https://github.com/takihito/field-cage/pull/92
- docs: note field-cage's monitoring window vs. job-start-wide audit tools by @takihito in https://github.com/takihito/field-cage/pull/94
- build(deps): Bump actions/checkout from 7.0.0 to 7.0.1 by @dependabot[bot] in https://github.com/takihito/field-cage/pull/82

## [v0.0.8](https://github.com/takihito/field-cage/compare/v0.0.7...v0.0.8) - 2026-07-27

- feat: manage release version via internal/version file by @takihito in https://github.com/takihito/field-cage/pull/74

## [v0.0.7](https://github.com/takihito/field-cage/compare/v0.0.6...v0.0.7) - 2026-07-24

- Bump github/codeql-action from 3.36.2 to 4.36.2 by @dependabot[bot] in https://github.com/takihito/field-cage/pull/42
- fix: strip port suffix from domain entries in allowlist by @takihito in https://github.com/takihito/field-cage/pull/52
- fix: remove connect_ms from log output by @takihito in https://github.com/takihito/field-cage/pull/51
- feat: add IPv4 CIDR subnet support to allowlist by @takihito in https://github.com/takihito/field-cage/pull/53
- feat: add IPv6 support (monitoring and block-mode enforcement) by @takihito in https://github.com/takihito/field-cage/pull/57
- feat: restrict port 53 to trusted resolvers (opt-out via allow_all_dns) by @takihito in https://github.com/takihito/field-cage/pull/58
- fix: harden event loops and unify diagnostics with slog by @takihito in https://github.com/takihito/field-cage/pull/59
- fix: policy UX — optional mode, reject wildcards, store parsed IPs by @takihito in https://github.com/takihito/field-cage/pull/60
- docs: sync DNS restriction and IPv6 details across README/CLAUDE.md by @takihito in https://github.com/takihito/field-cage/pull/61
- refactor: unify resolver discovery, parallelize seed, share IPv4 policy (PR4) by @takihito in https://github.com/takihito/field-cage/pull/63
- Bump actions/upload-artifact from 4.6.2 to 7.0.1 by @dependabot[bot] in https://github.com/takihito/field-cage/pull/44
- refactor: parse DNS responses with x/net/dns/dnsmessage (PR5) by @takihito in https://github.com/takihito/field-cage/pull/64
- Bump ossf/scorecard-action from 2.4.2 to 2.4.3 by @dependabot[bot] in https://github.com/takihito/field-cage/pull/43
- fix: batch of small eBPF hardening fixes (LRU_HASH, DNS payload zeroing, IPv6 port truncation) by @takihito in https://github.com/takihito/field-cage/pull/68
- build(deps): Bump github.com/cilium/ebpf from 0.21.0 to 0.22.0 by @dependabot[bot] in https://github.com/takihito/field-cage/pull/54
- Bump goreleaser/goreleaser-action from 7.2.2 to 7.2.3 by @dependabot[bot] in https://github.com/takihito/field-cage/pull/55
- build(deps): Bump golang.org/x/sys from 0.46.0 to 0.47.0 by @dependabot[bot] in https://github.com/takihito/field-cage/pull/65
- Bump step-security/harden-runner from 2.19.4 to 2.20.0 by @dependabot[bot] in https://github.com/takihito/field-cage/pull/66
- build(deps): Bump golang.org/x/net from 0.48.0 to 0.55.0 by @dependabot[bot] in https://github.com/takihito/field-cage/pull/69
- build(deps): Bump golang.org/x/net from 0.55.0 to 0.57.0 by @dependabot[bot] in https://github.com/takihito/field-cage/pull/70
- build(deps): Bump Songmu/tagpr from 1.20.0 to 1.20.1 by @dependabot[bot] in https://github.com/takihito/field-cage/pull/71

## [v0.0.6](https://github.com/takihito/field-cage/compare/v0.0.5...v0.0.6) - 2026-06-26

- fix: remove EXIT trap that deleted binary before agent start by @takihito in https://github.com/takihito/field-cage/pull/48

## [v0.0.5](https://github.com/takihito/field-cage/compare/v0.0.4...v0.0.5) - 2026-06-26

- Fix: install cosign in composite action (do not assume pre-installed) by @takihito in https://github.com/takihito/field-cage/pull/46

## [v0.0.4](https://github.com/takihito/field-cage/compare/v0.0.3...v0.0.4) - 2026-06-26

- Fix cosign: migrate to --bundle format (cosign v3 compatibility) by @takihito in https://github.com/takihito/field-cage/pull/40
- Bump actions/checkout from 6.0.3 to 7.0.0 by @dependabot[bot] in https://github.com/takihito/field-cage/pull/41

## [v0.0.3](https://github.com/takihito/field-cage/compare/v0.0.2...v0.0.3) - 2026-06-23

- Add SKIP(dns)/SKIP(loopback) verdicts and connect_ms timing by @takihito in https://github.com/takihito/field-cage/pull/13
- Refactor: extract verdict logic, split DNS files, testable main, cleanup-stack loader by @takihito in https://github.com/takihito/field-cage/pull/15
- Add SECURITY.md with vulnerability reporting policy by @takihito in https://github.com/takihito/field-cage/pull/27
- Add dependabot.yml and enable Dependabot security updates by @takihito in https://github.com/takihito/field-cage/pull/28
- Bump goreleaser/goreleaser-action from 6 to 7 by @dependabot[bot] in https://github.com/takihito/field-cage/pull/29
- Bump actions/setup-go from 5 to 6 by @dependabot[bot] in https://github.com/takihito/field-cage/pull/30
- Bump golang.org/x/sys from 0.15.0 to 0.46.0 by @dependabot[bot] in https://github.com/takihito/field-cage/pull/31
- Fix CI: use go-version-file and bump Dockerfile to Go 1.25 by @takihito in https://github.com/takihito/field-cage/pull/33
- Bump github.com/cilium/ebpf from 0.14.0 to 0.21.0 by @dependabot[bot] in https://github.com/takihito/field-cage/pull/32
- Pin GitHub Actions to commit hashes and add explicit permissions by @takihito in https://github.com/takihito/field-cage/pull/34
- Add dependency-review-action to PR checks by @takihito in https://github.com/takihito/field-cage/pull/35
- Add CodeQL workflow for Go static analysis by @takihito in https://github.com/takihito/field-cage/pull/36
- Add step-security/harden-runner to all workflows (#21) by @takihito in https://github.com/takihito/field-cage/pull/37
- Add OpenSSF Scorecard workflow and README badge (#24) by @takihito in https://github.com/takihito/field-cage/pull/38
- Add cosign signing and SLSA Level 3 provenance to release workflow by @takihito in https://github.com/takihito/field-cage/pull/39

## [v0.0.2](https://github.com/takihito/field-cage/compare/v0.0.1...v0.0.2) - 2026-06-11

- Add inline allowlist input to composite action by @takihito in https://github.com/takihito/field-cage/pull/11

## [v0.0.1](https://github.com/takihito/field-cage/commits/v0.0.1) - 2026-06-10

- Added AGENTS.md CLAUDE.md by @takihito in https://github.com/takihito/field-cage/pull/1
- Milestone 1: eBPF prototype — outbound connection logging by @takihito in https://github.com/takihito/field-cage/pull/2
- Milestone 2: DNS cache for IP-to-domain resolution by @takihito in https://github.com/takihito/field-cage/pull/3
- Add smoke-test CI job and bump actions/checkout to v6 by @takihito in https://github.com/takihito/field-cage/pull/4
- Milestone 3: policy engine and eBPF block-mode enforcement by @takihito in https://github.com/takihito/field-cage/pull/5
- Add DENY reason to verdict log, write README (en/ja) by @takihito in https://github.com/takihito/field-cage/pull/6
- Block モードを default-deny（allowlist 反転）モデルへ移行 by @takihito in https://github.com/takihito/field-cage/pull/7
- Milestone 4: GitHub Action 配布（GoReleaser + tagpr） by @takihito in https://github.com/takihito/field-cage/pull/8

## [v0.0.1](https://github.com/takihito/field-cage/commits/v0.0.1) - 2026-06-09

- Added AGENTS.md CLAUDE.md by @takihito in https://github.com/takihito/field-cage/pull/1
- Milestone 1: eBPF prototype — outbound connection logging by @takihito in https://github.com/takihito/field-cage/pull/2
- Milestone 2: DNS cache for IP-to-domain resolution by @takihito in https://github.com/takihito/field-cage/pull/3
- Add smoke-test CI job and bump actions/checkout to v6 by @takihito in https://github.com/takihito/field-cage/pull/4
- Milestone 3: policy engine and eBPF block-mode enforcement by @takihito in https://github.com/takihito/field-cage/pull/5
- Add DENY reason to verdict log, write README (en/ja) by @takihito in https://github.com/takihito/field-cage/pull/6
- Block モードを default-deny（allowlist 反転）モデルへ移行 by @takihito in https://github.com/takihito/field-cage/pull/7
- Milestone 4: GitHub Action 配布（GoReleaser + tagpr） by @takihito in https://github.com/takihito/field-cage/pull/8
