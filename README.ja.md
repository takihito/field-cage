# field-cage

GitHub Actions ランナー上の外部通信を監視・制限する軽量 eBPF エージェント。
ビルド中の不正なデータ送出や外部コード取得といったサプライチェーン攻撃を検出・防御します。

## 概要

eBPF を通じて Linux カーネルレベルで全アウトバウンド接続をリアルタイムに監視します。DNS パケット監視により IP アドレスをドメイン名に自動変換し、YAML で定義した allowlist に照らして各接続の許否を判定します。

- **Audit モード** — 全接続をログ出力するだけ。既存ワークフローへの影響なし
- **Block モード** — デフォルト拒否（default-deny）。宛先 IP が allowlist に無い全アウトバウンド接続を拒否（プロセスへ `EPERM` を返す）。DNS（port 53）とループバックは常に許可

## 特徴

- DNS パケット監視により IP を自動でドメイン名に変換
- YAML ポリシーによるドメイン・IP アドレスの完全一致指定（大文字小文字不問）

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

## ポリシーファイル

```yaml
mode: block   # audit または block

allowlist:
  - github.com
  - api.github.com
  - codeload.github.com
  - objects.githubusercontent.com
  - 1.2.3.4        # IP アドレスも指定可能
```

> **注意**: ワイルドカード（`*.github.com`）は非対応です。サブドメインは個別に列挙してください。

## 使い方

```sh
# Audit モード（ポリシーなし・全通信をログ出力）
sudo ./field-cage

# Audit モード（ポリシーファイルあり）
sudo ./field-cage --config policy.yml

# Block モード（デフォルト拒否。allowlist の宛先のみ許可）
# ポリシーファイルは必須（無いと全接続が拒否されるため起動しません）
sudo ./field-cage --config policy.yml --mode block
```

## 開発

eBPF 開発には Linux が必要です。macOS では Docker コンテナがその環境を提供します。

```sh
# 初回セットアップ（go.sum 生成）
make tidy

# Docker イメージをビルド（bpf2go + go build を内部実行）
make build

# エージェントを起動（eBPF に必要な特権アクセス付き）
make run

# ローカル検証用コンテナを起動（curl/wget でトラフィック生成可能）
make run-dev

# run-dev で起動したコンテナを停止
make stop-dev

# ユニットテストを実行（特権不要）
make test

# git フック設定（プッシュ前に make test を自動実行）
make setup-hooks
```

## Block モードの遮断モデル

Block モードは **デフォルト拒否（default-deny）** です。`cgroup/connect4` プログラムは、宛先 IP が allowlist に無い全アウトバウンド IPv4 接続を拒否します。allowlist は次の方法で構築されます。

1. **起動時シード** — 明示的な IP エントリを直接追加し、allowlist の各ドメインを（IPv4）解決してそのアドレスを追加。
2. **DNS のライブ観測** — allowlist 対象ドメインの DNS 応答を wire 上で観測した時点で、その A レコード IP をアプリの接続より先に allowlist へ追加。ただし信用するのは、設定済みリゾルバ（`/etc/resolv.conf` の `nameserver`）またはループバックを送信元とする応答のみ。それ以外の送信元の応答はログ用にキャッシュするだけで allowlist には追加しないため、送信元ポート53を偽装した偽造応答による allowlist ポイズニングを防ぎます。

DNS（宛先 port 53）とループバック（`127.0.0.0/8`）は名前解決とローカルサービスを動作させるため常に許可します。Block モードではポリシーファイルが必須で、無い場合は全遮断を避けるため起動を拒否します。

## 制約事項

- **初回接続のレース（fail-closed）**: アプリが、観測した DNS 応答のマップ反映より先に接続した場合、allowlist 対象ドメインへの初回接続が拒否されることがあります。これは *fail-closed*（漏洩ではなく拒否）であり、アプリのリトライはマップ更新後に成功します。起動時シードにより、起動時点で解決可能なドメインではこのレースを回避します。
- **IPv4 のみ対応**: IPv6 接続（`connect6`）は未フックのため、Block モードでも**遮断対象外**です。IPv6 対応は今後の予定です。
- **port 53 の DNS は常に許可**: default-deny 下で名前解決を機能させるために必要です。副作用として、DNS トンネリングによる低帯域の情報持ち出しは遮断されません（DNS 監視ログには残ります）。
- **ライブ allowlist 登録はリゾルバ送信元の応答のみ信用**: allowlist を拡張するのは設定済みリゾルバまたはループバック発の DNS 応答だけです。信用される応答を偽造するには送信元ポート53のバインド（`CAP_NET_BIND_SERVICE`）か raw ソケット（`CAP_NET_RAW`）が必要で、通常のビルドステップは保持していません。これらを既に持つ攻撃者は別の手段でも遮断を無効化できます。
- **DNS パケット監視に `CAP_NET_RAW` が必要**: Block モードでは DNS パケット監視が起動できない場合はエラー終了します（fail-closed）。Audit モードではベストエフォートで動作します。

## アーキテクチャ

```
                     Linux カーネル
┌─────────────────────────────────────────────┐
│  tracepoint/sys_enter_connect               │
│    → connect イベントを ring buffer へ      │
│                                             │
│  socket_filter (port 53)                    │
│    → DNS 応答を ring buffer へ              │
│                                             │
│  cgroup/connect4  (Block モードのみ)         │
│    → default-deny。port 53・ループバック・   │
│      allowed_ips マップの IP を許可 (1=許可) │
└─────────────────────────────────────────────┘
                     ↕ cilium/ebpf
┌─────────────────────────────────────────────┐
│  field-cage agent (Go)                      │
│    DNS Cache    : IP → ドメイン名           │
│    Policy Engine: YAML allowlist 評価       │
│    Reporter     : stdout へ verdict 出力    │
└─────────────────────────────────────────────┘
```

## 技術スタック

| レイヤー | 技術 |
|----------|------|
| エージェント | Go 1.22 |
| eBPF プログラム | C（`bpf2go` でコンパイル） |
| eBPF Go バインディング | `cilium/ebpf v0.14.0` |
| ポリシー設定 | YAML（`gopkg.in/yaml.v3`） |
| ビルド | `CGO_ENABLED=0` 完全静的バイナリ |
