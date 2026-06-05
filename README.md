# field-cage

GitHub Actions ランナー上の外部通信を監視・制限する軽量 eBPF エージェント。
サプライチェーン攻撃（不正なデータ送出・外部コードの取得）を検出・防御します。

## 概要

ビルド中に発生する予期しない外部通信（依存関係の差し替え、シークレットの外部送信など）を、Linux カーネルレベルの eBPF でリアルタイムに検知します。

- **Audit モード** — 全接続をログ出力するだけ。既存のワークフローへの影響なし
- **Block モード** — YAML ポリシーに含まれない接続を拒否（`EPERM`）

## 特徴

- Node.js 不要・依存ゼロ。完全静的バイナリ一本で動作
- DNS スニッフィングにより IP を自動でドメイン名に変換
- allowlist は YAML で管理。ドメイン名・IP アドレスの完全一致指定

## ログ出力例

```
verdict=ALLOW                pid=1234   tgid=1234   comm=curl             dst=api.github.com (140.82.121.5):443
verdict=DENY(not-in-policy)  pid=1235   tgid=1235   comm=python3          dst=suspicious.example.com (93.184.216.34):443
verdict=DENY(no-domain)      pid=1236   tgid=1236   comm=curl             dst=93.184.216.34:80
```

| verdict | 意味 |
|---------|------|
| `ALLOW` | ポリシーで許可された接続 |
| `DENY(not-in-policy)` | ドメインがポリシーに含まれない |
| `DENY(no-domain)` | DNS 未解決（IP のみ判明） |

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

# Audit モード（ポリシーファイル読み込み）
sudo ./field-cage --config policy.yml

# Block モード（ポリシーに含まれない接続を拒否）
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

## 制約事項

- **Block モードの初回スルー**: cgroup/connect4 による遮断はリアクティブな仕組みのため、新たに拒否対象となった IP への最初の接続は通過します。次のマイルストーンでデフォルト拒否モデル（allowlist 反転）に移行して解消予定です。
- **IPv4 のみ対応**: 現時点では IPv6 接続は監視・遮断対象外です。
- **DNS スニッフィング**: DNS パケットをキャプチャするため `CAP_NET_RAW` が必要です。Block モードでは DNS ウォッチャーが起動できない場合はエラー終了します（fail-closed）。

## アーキテクチャ

```
                     Linux kernel
┌─────────────────────────────────────────────┐
│  tracepoint/sys_enter_connect               │
│    → connect イベントを ring buffer へ      │
│                                             │
│  socket_filter (port 53)                    │
│    → DNS 応答を ring buffer へ              │
│                                             │
│  cgroup/connect4  (Block モードのみ)         │
│    → blocked_ips マップを参照し 0=拒否/1=許可 │
└─────────────────────────────────────────────┘
                     ↕ cilium/ebpf
┌─────────────────────────────────────────────┐
│  field-cage agent (Go)                      │
│    DNS Cache   : IP → ドメイン名            │
│    Policy Engine: YAML allowlist 評価       │
│    Reporter    : stdout へ verdict 出力     │
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
