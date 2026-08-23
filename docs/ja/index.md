---
layout: default
title: field-cage - GitHub Actions 向け eBPF ネットワーク監視
description: field-cage は GitHub Actions ランナー上の外部通信を監視・制限する軽量 eBPF エージェントです。
---

# field-cage

[![OpenSSF Scorecard](https://api.securityscorecards.dev/projects/github.com/takihito/field-cage/badge)](https://securityscorecards.dev/viewer/?uri=github.com/takihito/field-cage)

field-cage は GitHub Actions ランナー上の外部通信を監視・制限する軽量 eBPF エージェントです。ビルド中の不正なデータ送出や外部コード取得といったサプライチェーン攻撃を検出・防御します。

[English documentation](../)

## 概要

eBPF を通じて Linux カーネルレベルで全アウトバウンド接続をリアルタイムに監視します。DNS パケット監視により IP アドレスをドメイン名に自動変換し、YAML で定義した allowlist に照らして各接続の許否を判定します。

- **Audit モード** — 全接続をログ出力するだけ。既存ワークフローへの影響なし
- **Block モード** — デフォルト拒否（default-deny）。宛先 IP が allowlist に無い全アウトバウンド IPv4/IPv6 接続を拒否（プロセスへ `EPERM` を返す）。ループバックは常に許可。DNS（port 53）はシステム設定済みリゾルバのみ許可（`allow_all_dns: true` でオプトアウト可）

## 特徴

- DNS パケット監視により IP を自動でドメイン名に変換（A / AAAA レコード対応）
- YAML ポリシーによるドメイン・IP アドレス（IPv4/IPv6）の完全一致指定（大文字小文字不問）
- CIDR サブネット指定（例: `10.0.0.0/8`, `203.0.113.0/24`, `2001:db8::/32`）
- デュアルスタック対応: IPv4-mapped IPv6 接続（`::ffff:a.b.c.d`、Node.js/Java のデュアルスタックソケットが使用）は IPv4 allowlist で強制
- Node.js / `node_modules` への依存ゼロ — 単一の完全静的 Go バイナリ

## クイックスタート

Composite Action にインライン allowlist を指定して追加します。

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

ポリシーファイル形式やスタンドアロン実行は[使い方](usage)を、Composite Action の入力・利用例・リリース検証は[GitHub Actions](github-actions)を参照してください。

## ログ出力例

```
verdict=ALLOW                pid=1234   tgid=1234   comm=curl             dst=api.github.com (140.82.121.5):443
verdict=DENY(not-in-policy)  pid=1235   tgid=1235   comm=python3          dst=suspicious.example.com (93.184.216.34):443
verdict=DENY(no-domain)      pid=1236   tgid=1236   comm=curl             dst=93.184.216.34:80
```

| verdict | 意味 |
|---------|------|
| `ALLOW` | ポリシーで許可された接続 |
| `DENY(not-in-policy)` | ドメインが allowlist に含まれない |
| `DENY(no-domain)` | ドメイン不明（IP 直指定、または DNS 応答未観測） |
| `SKIP(dns)` | ポリシー評価対象外の DNS 通信（信頼リゾルバまたはループバック宛。`allow_all_dns` 設定時やポリシー無しの場合は全 port-53 宛先） |
| `SKIP(loopback)` | ループバック宛先（`127.0.0.0/8`, `::1`）。enforcement 対象外 |
| `SKIP(self)` | エージェント自身のプロセスによる接続（allowlist 作成のための起動時 DNS 解決）。監視対象のワークフローによる通信ではない |

## サプライチェーンセキュリティ

- リリースバイナリは Composite Action 実行前に SHA-256 チェックサムで検証されます
- 各リリースには [cosign](https://github.com/sigstore/cosign) によるキーレス署名バンドルが同梱されます
- [SLSA Level 3](https://slsa.dev/) 来歴証明がリリースに添付されます
- [OpenSSF Scorecard](https://securityscorecards.dev/viewer/?uri=github.com/takihito/field-cage) を公開しています

ソースコード・Issue・リリースは [GitHub リポジトリ](https://github.com/takihito/field-cage) を参照してください。
