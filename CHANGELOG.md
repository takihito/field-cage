# Changelog

Release notes are maintained automatically by [tagpr](https://github.com/Songmu/tagpr).

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
