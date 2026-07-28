---
layout: default
title: field-cage GitHub Actions
description: field-cage Composite Action を使って GitHub Actions ワークフロー内の外部通信を監視・制限する方法。
---

# GitHub Actions

Composite Action でランナー上に field-cage を起動できます。指定バージョンのリリースバイナリを取得し、SHA-256 チェックサムを検証してから、ジョブの残りの期間バックグラウンドでエージェントを実行します。

## インライン allowlist

別ファイル不要:

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

## 外部 config ファイル

複雑なポリシーや複数ワークフロー共有の場合:

```yaml
- uses: takihito/field-cage@v0.1.0
  with:
    version: v0.1.0                          # `uses:` のタグと一致させること
    config: .github/field-cage-policy.yml    # 省略時はポリシー無しの audit
    mode: audit                              # audit（ログのみ）または block
```

`allow` と `config` は同時に指定できません。両方を指定するとエラーになります。

## 補足

- **audit モードはどのワークフローにも安全に追加できます** — アウトバウンド接続を記録するだけで遮断しません。
- エージェントはバックグラウンドで動くため、**ログは後続ステップで確認**してください。例: `cat /tmp/field-cage.log`（パスは `log-file` 入力で変更可）、または artifact としてアップロード。Composite Action は後処理（post）ステップを持てないため、ログ回収と停止は呼び出し側で行います。
- サンプルポリシーはリポジトリの [`.github/field-cage-policy.example.yml`](https://github.com/takihito/field-cage/blob/main/.github/field-cage-policy.example.yml) を参照してください。

## リリース

バイナリ（`linux/amd64`・`linux/arm64`）と `checksums.txt` は [GoReleaser](https://goreleaser.com) により GitHub Releases へ公開されます。バージョン管理は [tagpr](https://github.com/Songmu/tagpr) が担い、自動メンテされるリリースPRをマージすると `vX.Y.Z` タグが push され、リリースビルドが起動します。

各リリースには [cosign](https://github.com/sigstore/cosign) によるキーレス署名バンドル（`checksums.txt.bundle`）と [SLSA Level 3](https://slsa.dev/spec/v1.0/levels) 来歴証明（`checksums.txt.intoto.jsonl`）がリリースアセットとして同梱されます。

**チェックサムの署名を検証する:**

```sh
cosign verify-blob \
  --bundle checksums.txt.bundle \
  --certificate-identity "https://github.com/takihito/field-cage/.github/workflows/release.yml@refs/tags/vX.Y.Z" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
  checksums.txt
```

**SLSA 来歴証明を検証する:**

```sh
slsa-verifier verify-artifact \
  --provenance-path checksums.txt.intoto.jsonl \
  --source-uri github.com/takihito/field-cage \
  --source-tag vX.Y.Z \
  field-cage_linux_amd64   # または field-cage_linux_arm64
```
