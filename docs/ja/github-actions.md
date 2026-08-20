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

- **audit モードは通信を遮断しません** — アウトバウンド接続を記録するだけです。ただしこの Action は Linux ランナー（`ubuntu-*`、ホスト型・セルフホスト問わず）で passwordless `sudo` と eBPF サポートが必要です。macOS/Windows ランナー、非対応アーキテクチャ、権限が制限されたセルフホスト Linux ランナーでは、モードに関わらずバイナリ取得やエージェント起動に失敗しジョブが失敗します。
- エージェントはバックグラウンドで動くため、**ログは後続ステップで確認**してください。例: `cat /tmp/field-cage.log`（パスは `log-file` 入力で変更可）、後述の `report` サブアクションで整形表示、または artifact としてアップロード。Composite Action は後処理（post）ステップを持てないため、ログ回収と停止は呼び出し側で行います。
- サンプルポリシーはリポジトリの [`.github/field-cage-policy.example.yml`](https://github.com/takihito/field-cage/blob/main/.github/field-cage-policy.example.yml) を参照してください。

## レポート: 整形されたジョブサマリ

ジョブの末尾に `takihito/field-cage/report` を追加すると（前段のステップが失敗・DENY してもレポートは実行したいため `if: always()` を付ける）、ログを GitHub Actions のジョブサマリとして整形表示し、拒否された宛先をアノテーションとして表示できます:

```yaml
- uses: takihito/field-cage@v0.1.0
  with:
    version: v0.1.0
    mode: audit
    allow: |
      github.com
      api.github.com

# ... 通信を発生させるステップ ...

- uses: takihito/field-cage/report@v0.1.0
  if: always()
  with:
    version: v0.1.0        # 本体ステップの version と一致させる
    fail-on-deny: false    # DENY が1件でもあればジョブを失敗させたい場合は true（主に block モード向け）
```

`$GITHUB_STEP_SUMMARY` へ拒否/許可/スキップ宛先の表を書き込み、拒否された宛先ごとにアノテーションを1件発行します（block モードでは `warning`、audit モードでは実際には遮断していないため `notice`）。また `denied-count` / `allowed-count` / `suggested-allowlist`（観測された宛先の JSON 配列。ポリシー作成の出発点として使えるが、採用前にレビューすること）をステップ出力として公開します。生ログ全文はジョブログへのコピー（既定オフ、`dump-log: true` で有効化）やアーティファクトへのアップロード（`upload-log: true`）を明示的に有効化しない限り出力されません — 上記のサマリを優先する設計です。全入力は [`report/action.yml`](https://github.com/takihito/field-cage/blob/main/report/action.yml) を参照してください。

## CLI: text、JSON、CSV

同じ集計処理はバイナリの `report` サブコマンドから直接利用できます。ローカルや他の CI システムでも使えます:

```sh
field-cage report --log /tmp/field-cage.log --format text
field-cage report --log /tmp/field-cage.log --format json
field-cage report --log /tmp/field-cage.log --format csv
```

`--format auto`（既定）は GitHub Actions ランナー上（`GITHUB_ACTIONS=true`）では `markdown`、それ以外では `text` を選ぶため、上記の Action もローカルで同じバイナリを実行する場合も追加フラグ無しでそれぞれ適切な出力になります。`--raw` は集計せず1イベント1行で出力します（`text`・`json`・`csv` のみ）。他ツールへのパイプ処理に便利です。フラグ一覧は `field-cage report --help` を参照してください。

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
