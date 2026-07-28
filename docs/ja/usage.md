---
layout: default
title: field-cage 使い方
description: field-cage のポリシーファイル形式とスタンドアロンバイナリの使い方。
---

# 使い方

## ポリシーファイル

```yaml
mode: block          # 任意。audit または block。省略時は audit
                     # （いずれの場合も --mode フラグが優先されます）
allow_all_dns: false # 任意。下記「DNS の扱い」を参照（デフォルト false）

allowlist:
  - github.com
  - api.github.com
  - codeload.github.com
  - objects.githubusercontent.com
  - 1.2.3.4             # 単一 IPv4 アドレス
  - 2001:db8::1         # 単一 IPv6 アドレス
  - 10.0.0.0/8          # IPv4 CIDR サブネット（プライベート範囲）
  - 203.0.113.0/24      # 任意のプレフィックス長に対応
  - 2001:db8::/32       # IPv6 CIDR サブネット
```

> **注意**: ワイルドカード（`*.github.com`）は非対応です。`*` を含むエントリはポリシー読み込み時にエラーになります。サブドメインは個別に列挙してください。
>
> **キーの厳格チェック**: 未知のキーはポリシー読み込み時にエラーになります。キーの誤記（例: `mdoe:`）は黙ってデフォルトにフォールバックせず fail-fast します。
>
> **CIDR**: CIDR エントリは eBPF の LPM trie に直接シードされるため、サブネット内の全アドレスが DNS 解決なしで許可されます。
>
> **DNS の扱い**: デフォルトでは port 53 は `/etc/resolv.conf` に設定されたリゾルバとループバックのみ許可されます。これにより、任意ホストの port 53 を汎用の外向きトンネルとして悪用されるのを防ぎます。`allow_all_dns: true` を設定すると port 53 を全宛先に許可します（0.x 以前の挙動）。ただしデフォルトでも、正規リゾルバを介した DNS *トンネリング*（サブドメインにデータを載せた再帰解決）は遮断できません。下記の制約事項を参照してください。

## スタンドアロンバイナリ

```sh
# Audit モード（ポリシーなし・全通信をログ出力）
sudo ./field-cage

# Audit モード（ポリシーファイルあり）
sudo ./field-cage --config policy.yml

# Block モード（デフォルト拒否。allowlist の宛先のみ許可）
# ポリシーファイルは必須（無いと全接続が拒否されるため起動しません）
sudo ./field-cage --config policy.yml --mode block

# バージョン表示
./field-cage --version
```

事前ビルド済みバイナリ（`linux/amd64`・`linux/arm64`）は[Releases](https://github.com/takihito/field-cage/releases)ページで公開されています。

## Block モードの遮断モデル

Block モードは **デフォルト拒否（default-deny）** です。`cgroup/connect4` および `cgroup/connect6` プログラムは、宛先 IP が allowlist に無い全アウトバウンド IPv4/IPv6 接続を拒否します。IPv4-mapped IPv6 宛先（`::ffff:a.b.c.d`、Node.js や Java などのデュアルスタックランタイムが IPv4 ホストへ接続する際の経路）は IPv4 allowlist と照合されるため、IPv4 エントリ 1 つで両方のソケットファミリーをカバーします。allowlist は次の方法で構築されます。

1. **起動時シード** — 明示的な IP / CIDR エントリを直接追加し、allowlist の各ドメインを解決（A / AAAA）してそのアドレスを追加。
2. **DNS のライブ観測** — allowlist 対象ドメインの DNS 応答を wire 上で観測した時点で、その A / AAAA レコード IP をアプリの接続より先に allowlist へ追加。ただし信用するのは、設定済みリゾルバ（`/etc/resolv.conf` の `nameserver`）またはループバックを送信元とする応答のみ。それ以外の送信元の応答はログ用にキャッシュするだけで allowlist には追加しないため、送信元ポート53を偽装した偽造応答による allowlist ポイズニングを防ぎます。

ループバック（`127.0.0.0/8` および `::1`）はローカルサービスを動作させるため常に許可します。DNS（宛先 port 53）はシステムのリゾルバ（およびループバック）のみ許可します。これは名前解決を機能させつつ、任意ホストの port 53 を汎用の外向きトンネルとして悪用されるのを防ぐためです。`allow_all_dns: true` をポリシーに設定すると、従来どおり port 53 を無条件に許可します。起動時にリゾルバを特定できない場合はループバックのみ許可します（fail-closed）。Block モードではポリシーファイルが必須で、無い場合は全遮断を避けるため起動を拒否します。

## 制約事項

- **初回接続のレース（fail-closed）**: アプリが、観測した DNS 応答のマップ反映より先に接続した場合、allowlist 対象ドメインへの初回接続が拒否されることがあります。これは *fail-closed*（漏洩ではなく拒否）であり、アプリのリトライはマップ更新後に成功します。起動時シードにより、起動時点で解決可能なドメインではこのレースを回避します。
- **正規リゾルバを介した DNS トンネリングは遮断しない**: 名前解決のため port 53 は設定済みリゾルバ（およびループバック）に許可されます。攻撃者はサブドメインにデータを載せて正規リゾルバに再帰解決させることが依然可能で、これはリゾルバ IP 制限では防げません。低帯域であり DNS 監視ログには残ります。
- **ライブ観測は IPv4 トランスポート上の平文 UDP DNS（port 53）のみ**: IPv6 トランスポート・TCP・暗号化（DoH/DoT）の DNS は観測できないため allowlist を拡張できません。観測できないチャネルで解決されるドメインは起動時シードのみが対象となり、起動後に IP がローテーションすると新しい IP を block モードが拒否します（fail-closed）。該当ドメインはポリシーで IP 固定するか、IPv4 上の平文 UDP で解決されるようにしてください。
- **DNS パケット監視に `CAP_NET_RAW` が必要**: Block モードでは DNS パケット監視が起動できない場合はエラー終了します（fail-closed）。Audit モードではベストエフォートで動作します。
