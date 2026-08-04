# field-cage

[![OpenSSF Scorecard](https://api.securityscorecards.dev/projects/github.com/takihito/field-cage/badge)](https://securityscorecards.dev/viewer/?uri=github.com/takihito/field-cage)

**[ドキュメント](https://takihito.github.io/field-cage/ja/)** | [English documentation](https://takihito.github.io/field-cage/)

GitHub Actions ランナー上の外部通信を監視・制限する軽量 eBPF エージェント。
ビルド中の不正なデータ送出や外部コード取得といったサプライチェーン攻撃を検出・防御します。

## 概要

eBPF を通じて Linux カーネルレベルで全アウトバウンド接続をリアルタイムに監視します。DNS パケット監視により IP アドレスをドメイン名に自動変換し、YAML で定義した allowlist に照らして各接続の許否を判定します。

- **Audit モード** — 全接続をログ出力するだけ。既存ワークフローへの影響なし
- **Block モード** — デフォルト拒否（default-deny）。宛先 IP が allowlist に無い全アウトバウンド IPv4/IPv6 接続を拒否（プロセスへ `EPERM` を返す）。ループバックは常に許可。DNS（port 53）はシステム設定済みリゾルバのみ許可（`allow_all_dns: true` でオプトアウト可）

## 特徴

- DNS パケット監視により IP を自動でドメイン名に変換（A / AAAA レコード対応）
- YAML ポリシーによるドメイン・IP アドレス（IPv4/IPv6）の完全一致指定（大文字小文字不問）
- CIDR サブネット指定（例: `10.0.0.0/8`, `203.0.113.0/24`, `2001:db8::/32`）
- デュアルスタック対応: IPv4-mapped IPv6 接続（`::ffff:a.b.c.d`、Node.js/Java のデュアルスタックソケットが使用）は IPv4 allowlist で強制

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
> **DNS の扱い**: デフォルトでは port 53 は `/etc/resolv.conf` に設定されたリゾルバとループバックのみ許可されます。これにより、任意ホストの port 53 を汎用の外向きトンネルとして悪用されるのを防ぎます。`allow_all_dns: true` を設定すると port 53 を全宛先に許可します（0.x 以前の挙動）。ただしデフォルトでも、正規リゾルバを介した DNS *トンネリング*（サブドメインにデータを載せた再帰解決）は遮断できません。制約事項を参照してください。

## 使い方

### インストール

```sh
curl -fsSL https://takihito.github.io/field-cage/install.sh | sh
```

デフォルトでは `~/.local/bin` にインストールされます（インストール自体に `sudo` は不要）。インストール先を変更する場合:

```sh
curl -fsSL https://takihito.github.io/field-cage/install.sh | sudo env FIELD_CAGE_INSTALL_DIR=/usr/local/bin sh
```

Linux（`amd64` または `arm64`）が必要です — field-cage は eBPF に依存するため macOS / Windows 版はありません。事前ビルド済みバイナリの手動ダウンロードは[Releases](https://github.com/takihito/field-cage/releases)ページを参照してください。

### 実行

```sh
# Audit モード（ポリシーなし・全通信をログ出力）
sudo field-cage

# Audit モード（ポリシーファイルあり）
sudo field-cage --config policy.yml

# Block モード（デフォルト拒否。allowlist の宛先のみ許可）
# ポリシーファイルは必須（無いと全接続が拒否されるため起動しません）
sudo field-cage --config policy.yml --mode block

# バージョン表示
field-cage --version
```

> システムによっては `sudo` が `PATH` をリセットするため、`sudo field-cage` が "command not found" になる場合はフルパス指定（例: `sudo ~/.local/bin/field-cage`）するか、`sudo -E`/`--preserve-env=PATH` を使ってください。

## GitHub Actions での利用

Composite Action でランナー上に field-cage を起動できます。指定バージョンの
リリースバイナリを取得し、SHA-256 チェックサムを検証してから、ジョブの残りの
期間バックグラウンドでエージェントを実行します。

**インライン allowlist**（別ファイル不要）:

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

**外部 config ファイル**（複雑なポリシーや複数ワークフロー共有の場合）:

```yaml
- uses: takihito/field-cage@v0.1.0
  with:
    version: v0.1.0                          # `uses:` のタグと一致させること
    config: .github/field-cage-policy.yml    # 省略時はポリシー無しの audit
    mode: audit                              # audit（ログのみ）または block
```

`allow` と `config` は同時に指定できません。両方を指定するとエラーになります。

- **audit モードは通信を遮断しません** — アウトバウンド接続を記録するだけです。
  ただしこの Action は Linux ランナー（`ubuntu-*`、ホスト型・セルフホスト問わず）で
  passwordless `sudo` と eBPF サポートが必要です。macOS/Windows ランナー、非対応
  アーキテクチャ、権限が制限されたセルフホスト Linux ランナーでは、モードに
  関わらずバイナリ取得やエージェント起動に失敗しジョブが失敗します。
- エージェントはバックグラウンドで動くため、**ログは後続ステップで確認**してください。
  例: `cat /tmp/field-cage.log`（パスは `log-file` 入力で変更可）、または artifact として
  アップロード。Composite Action は後処理（post）ステップを持てないため、ログ回収と停止は
  呼び出し側で行います。
- サンプルポリシーは
  [`.github/field-cage-policy.example.yml`](.github/field-cage-policy.example.yml) を参照。

### リリース

バイナリ（`linux/amd64`・`linux/arm64`）と `checksums.txt` は
[GoReleaser](https://goreleaser.com) により GitHub Releases へ公開されます。
バージョン管理は [tagpr](https://github.com/Songmu/tagpr) が担い、自動メンテされる
リリースPRをマージすると `vX.Y.Z` タグが push され、リリースビルドが起動します。

各リリースには [cosign](https://github.com/sigstore/cosign) によるキーレス署名バンドル
（`checksums.txt.bundle`）と
[SLSA Level 3](https://slsa.dev/spec/v1.0/levels) 来歴証明
（`checksums.txt.intoto.jsonl`）がリリースアセットとして同梱されます。

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

> メンテナ向け注記: tagpr は PAT（repo スコープ、secret `TAGPR_TOKEN`）でタグを push する
> 必要があります。デフォルトの `GITHUB_TOKEN` で push したタグはリリースワークフローを
> 発火させないためです。

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

Block モードは **デフォルト拒否（default-deny）** です。`cgroup/connect4` および `cgroup/connect6` プログラムは、宛先 IP が allowlist に無い全アウトバウンド IPv4/IPv6 接続を拒否します。IPv4-mapped IPv6 宛先（`::ffff:a.b.c.d`、Node.js や Java などのデュアルスタックランタイムが IPv4 ホストへ接続する際の経路）は IPv4 allowlist と照合されるため、IPv4 エントリ 1 つで両方のソケットファミリーをカバーします。allowlist は次の方法で構築されます。

1. **起動時シード** — 明示的な IP / CIDR エントリを直接追加し、allowlist の各ドメインを解決（A / AAAA）してそのアドレスを追加。
2. **DNS のライブ観測** — allowlist 対象ドメインの DNS 応答を wire 上で観測した時点で、その A / AAAA レコード IP をアプリの接続より先に allowlist へ追加。ただし信用するのは、設定済みリゾルバ（`/etc/resolv.conf` の `nameserver`）またはループバックを送信元とする応答のみ。それ以外の送信元の応答はログ用にキャッシュするだけで allowlist には追加しないため、送信元ポート53を偽装した偽造応答による allowlist ポイズニングを防ぎます。

ループバック（`127.0.0.0/8` および `::1`）はローカルサービスを動作させるため常に許可します。DNS（宛先 port 53）はシステムのリゾルバ（およびループバック）のみ許可します。これは名前解決を機能させつつ、任意ホストの port 53 を汎用の外向きトンネルとして悪用されるのを防ぐためです。`allow_all_dns: true` をポリシーに設定すると、従来どおり port 53 を無条件に許可します。リゾルバは `/etc/resolv.conf` から発見しますが、ループバックスタブ（systemd-resolved の `127.0.0.53`）のみの場合は `/run/systemd/resolve/resolv.conf` にある上流サーバーも許可します — enforcement はスタブデーモン自身の外向きクエリにも適用されるため、上流への到達性が必要だからです。起動時にリゾルバを特定できない場合はループバックのみ許可します（fail-closed）。拒否された port 53 接続は `SKIP(dns)` ではなく `DENY` として記録されます。Block モードではポリシーファイルが必須で、無い場合は全遮断を避けるため起動を拒否します。

## 制約事項

- **初回接続のレース（fail-closed）**: アプリが、観測した DNS 応答のマップ反映より先に接続した場合、allowlist 対象ドメインへの初回接続が拒否されることがあります。これは *fail-closed*（漏洩ではなく拒否）であり、アプリのリトライはマップ更新後に成功します。起動時シードにより、起動時点で解決可能なドメインではこのレースを回避します。
- **正規リゾルバを介した DNS トンネリングは遮断しない**: 名前解決のため port 53 は設定済みリゾルバ（およびループバック）に許可されます。攻撃者はサブドメインにデータを載せて正規リゾルバに再帰解決させることが依然可能で、これはリゾルバ IP 制限では防げません。低帯域であり DNS 監視ログには残ります。なお、デフォルトでは「任意ホストの port 53 を直接トンネルにする」という粗い悪用は遮断します（`allow_all_dns: true` で無効化可能）。
- **ライブ allowlist 登録はリゾルバ送信元の応答のみ信用**: allowlist を拡張するのは設定済みリゾルバまたはループバック発の DNS 応答だけです。信用される応答を偽造するには送信元ポート53のバインド（`CAP_NET_BIND_SERVICE`）か raw ソケット（`CAP_NET_RAW`）が必要で、通常のビルドステップは保持していません。これらを既に持つ攻撃者は別の手段でも遮断を無効化できます。
- **ライブ観測は IPv4 トランスポート上の平文 UDP DNS（port 53）のみ**: IPv6 トランスポート・TCP・暗号化（DoH/DoT）の DNS は観測できないため allowlist を拡張できません。これは A / AAAA 両レコードに当てはまります（クエリが IPv4 トランスポートを通る一般的なケースでは AAAA 応答も観測**されます**）。観測できないチャネルで解決されるドメインは起動時シードのみが対象となり、起動後に IP がローテーションすると新しい IP を block モードが拒否します（fail-closed）。該当ドメインはポリシーで IP 固定するか、IPv4 上の平文 UDP で解決されるようにしてください。
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
│  cgroup/connect4 + connect6 (Block モード)   │
│    → default-deny。ループバック・信頼リゾルバ │
│      への port 53・allowed_ips /             │
│      allowed_ips6 LPM trie の IP を許可      │
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
| エージェント | Go 1.25 |
| eBPF プログラム | C（`bpf2go` でコンパイル） |
| eBPF Go バインディング | `cilium/ebpf v0.22.0` |
| ポリシー設定 | YAML（`gopkg.in/yaml.v3`） |
| ビルド | `CGO_ENABLED=0` 完全静的バイナリ |
