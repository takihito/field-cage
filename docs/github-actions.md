---
layout: default
title: field-cage GitHub Actions
description: Using the field-cage composite action to monitor and restrict outbound network access in GitHub Actions workflows.
---

# GitHub Actions

Use the composite action to run field-cage on a runner. It downloads the pinned release binary, verifies its SHA-256 checksum, and starts the agent in the background for the rest of the job.

## Inline allowlist

No separate policy file needed:

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

## External config file

For complex or shared policies:

```yaml
- uses: takihito/field-cage@v0.1.0
  with:
    version: v0.1.0                          # must match the `uses:` ref
    config: .github/field-cage-policy.yml    # omit for audit mode with no policy
    mode: audit                              # audit (log-only) or block
```

`allow` and `config` are mutually exclusive — using both at the same time is an error.

## Notes

- **Audit mode never blocks traffic** — it only logs outbound connections. This action requires a Linux runner (`ubuntu-*`, hosted or self-hosted) with passwordless `sudo` and eBPF support; on macOS/Windows runners, unsupported architectures, or restricted self-hosted Linux runners, the action fails to download or start the agent, which fails the job regardless of mode.
- The agent runs in the background; **view its log in a later step**, e.g. `cat /tmp/field-cage.log` (path configurable via the `log-file` input), or render it with the `report` sub-action below, or upload it as an artifact. Composite actions cannot run an automatic post-job step, so log collection and shutdown are left to the caller.
- See [`.github/field-cage-policy.example.yml`](https://github.com/takihito/field-cage/blob/main/.github/field-cage-policy.example.yml) in the repository for a sample policy.
- **Monitoring window**: field-cage only observes traffic from after the agent starts. Any step earlier in the job (checking out other actions, installing dependencies, etc.) is outside its coverage and won't appear in its log or allowlist — even if a separate egress-monitoring tool (e.g. [Harden Runner](https://github.com/step-security/harden-runner) in audit mode) flags it, since that tool watches from job start. Place this action as early as possible in the job to minimize the gap.

## Report: a formatted job summary

Add `takihito/field-cage/report` at the end of the job (with `if: always()`, since a denial or a failed step earlier shouldn't skip reporting) to render the log as a GitHub Actions job summary, with denials raised as annotations:

```yaml
- uses: takihito/field-cage@v0.1.0
  with:
    version: v0.1.0
    mode: audit
    allow: |
      github.com
      api.github.com

# ... steps that generate outbound traffic ...

- uses: takihito/field-cage/report@v0.1.0
  if: always()
  with:
    version: v0.1.0        # keep in sync with the main step's version
    fail-on-deny: false    # set true to fail the job on any DENY verdict (typically for block mode)
```

It writes a table of denied/allowed/skipped destinations to `$GITHUB_STEP_SUMMARY`, emits one annotation per denied destination (`warning` in block mode, `notice` in audit mode, since audit mode never actually blocked anything), and exposes `denied-count`, `allowed-count`, `suggested-allowlist` (a JSON array of destinations observed, for use as a starting point for a policy — review before adopting it), and `log-file` (the log path it actually resolved and rendered) as step outputs. The full raw log is not copied into the job log by default (set `dump-log: true` to opt in) or uploaded as an artifact (set `upload-log: true`) — the summary above is preferred. See [`report/action.yml`](https://github.com/takihito/field-cage/blob/main/report/action.yml) for every input.

## CLI: text, JSON, or CSV

The same aggregation is available directly from the binary via the `report` subcommand, for local use or any CI system:

```sh
field-cage report --log /tmp/field-cage.log --format text
field-cage report --log /tmp/field-cage.log --format json
field-cage report --log /tmp/field-cage.log --format csv
```

`--format auto` (the default) picks `markdown` on a GitHub Actions runner (`GITHUB_ACTIONS=true`) and `text` otherwise, so the action above and a local run of the same binary need no extra flags to each get the right output. `--raw` skips aggregation and emits one row per connection event (`text`, `json`, or `csv` only) — useful for piping into other tools. Run `field-cage report --help` for the full flag list.

## Releases

Binaries (`linux/amd64`, `linux/arm64`) and a `checksums.txt` are published to GitHub Releases by [GoReleaser](https://goreleaser.com). Versioning is managed by [tagpr](https://github.com/Songmu/tagpr): merging the auto-maintained release PR pushes a `vX.Y.Z` tag, which triggers the release build.

Each release includes a [cosign](https://github.com/sigstore/cosign) keyless signature bundle (`checksums.txt.bundle`) and a [SLSA Level 3](https://slsa.dev/spec/v1.0/levels) provenance attestation (`checksums.txt.intoto.jsonl`), both published as release assets.

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
