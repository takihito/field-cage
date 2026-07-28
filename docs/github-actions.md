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

- **Audit mode is safe to add to any workflow** — it only logs outbound connections and never blocks them.
- The agent runs in the background; **view its log in a later step**, e.g. `cat /tmp/field-cage.log` (path configurable via the `log-file` input), or upload it as an artifact. Composite actions cannot run an automatic post-job step, so log collection and shutdown are left to the caller.
- See [`.github/field-cage-policy.example.yml`](https://github.com/takihito/field-cage/blob/main/.github/field-cage-policy.example.yml) in the repository for a sample policy.

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
