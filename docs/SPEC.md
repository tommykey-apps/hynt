# hynt

ホストがどのネットワークに繋がっているかを、**VPN を含めて** 1 つの表に出す CLI。同じ収集処理を Go のライブラリとしても公開する。

主眼は「この宛先はどのインタフェースへ流れるか」。図は別のリポジトリ (図のツール) で作る。図のツールは hynt を import して `hynt.Collect` を呼ぶ。

名前はウェールズ語 hynt (進路、道筋)。

## 前提

Linux のみ。iproute2 (`ip`) が入っていること。読み取りだけなので root 不要。例外は `ip xfrm policy` で、これだけ CAP_NET_ADMIN が要る。権限が無ければその表だけ「権限なし」と出し、他は出す。

## やらないこと

探索パケットの送信 (ping / ARP)、常駐、通知、Web 画面、図の描画、VPN の向こう側の機器列挙、Linux 以外の OS。

## 起動

```
hynt            # 表
hynt --json     # 機械向け              (#4)
hynt --version  #                       (#5)
```

開発時は `go run ./cmd/hynt`。

## 機能

- インタフェース一覧 (名前 / 種別 / 実装 / 状態 / アドレス)                    (#1)
- 経路。全ルーティングテーブルと `ip rule` を読み、宛先ごとにインタフェースを付ける (#2)
- 隣人 (`ip neigh`) の件数と一覧                                              (#3)
- インタフェースを持たない IPsec (`ip xfrm policy`、root のときだけ)              (#3)
- `hynt.Collect` の公開と JSON 出力                                           (#4)
- GitHub Releases / `go install` で配布                                       (#5)

## 種別判定の規則

名前 (`tun0`, `wg0`, `cscotun0`) で判定しない。製品ごとに名前が違い、ユーザーが変えられる。
カーネルが返す link kind (`ip -j -d link` の `info_kind`) と `/sys/class/net` だけで決める。

| link kind | 判定 | 補足 |
|---|---|---|
| `wireguard` `ovpn` `ppp` `xfrm` | vpn | kind をそのまま実装名にする |
| `tun` | vpn | `tun_flags` の 0x2 が立っていれば tap (L2)、それ以外は tun (L3) |
| `bridge` | bridge | docker0 など |
| なし + `device` あり + `wireless` あり | wifi | |
| なし + `device` あり | ethernet | |
| なし + `device` なし | virtual | |
| その他 (`veth` `vlan` `dummy` `bond` …) | virtual | kind を実装名にする |

`lo` (LOOPBACK) は出さない。link-local アドレスは出さない。

主要 VPN が Linux でどう見えるか (調査済み):

| VPN | インタフェース | link kind | 経路の置き場 |
|---|---|---|---|
| Cisco Secure Client | `cscotun0` | tun | main |
| OpenConnect | `tun0` | tun | main |
| GlobalProtect | `gpd0` | tun | main |
| FortiClient SSL VPN | `ppp0` | ppp | main |
| OpenVPN | `tun0` / `tap0` | tun / tap | main。全経路時は `0.0.0.0/1` + `128.0.0.0/1`。DCO は kind `ovpn` |
| WireGuard (wg-quick) | `wg0` | wireguard | AllowedIPs 0/0 のとき table 51820 |
| Tailscale | `tailscale0` | tun | table 52 (rule 5270) |
| Mullvad | `wg0-mullvad` | wireguard | table 1836018789 |
| NordVPN | `nordlynx` / `nordtun` | wireguard / tun | 自前管理 |
| Cloudflare WARP | `CloudflareWARP` | tun | table 65743 |
| ProtonVPN | `proton0` | wireguard | NetworkManager 経由 |
| ZeroTier | `zt…` | tap | main |
| NetBird / Nebula | `wt0` / `nebula1` | wireguard または tun / tun | main |
| L2TP / PPTP | `ppp0` | ppp | main |
| IPsec (strongSwan / libreswan) | なし | `ip xfrm policy` にだけ出る | route-based の xfrmi 時は table 220 |

main テーブルだけ読むと Tailscale、wg-quick、Mullvad、WARP の経路が空になる。必ず `table all` と `ip rule` を読む。

未確認: FortiClient 7.4 の IPsec 版が作るインタフェース名。NordVPN / Proton / NetBird / Nebula が独自テーブルを使うか。どちらも上の規則なら結果に影響しない。

## 表のルール

- 表は 1 つ。分けると一覧の意味が薄れる。列は IF / KIND / STATE / NEIGH / ADDR / DST / VIA / TABLE
- 1 インタフェース 1 グループ。アドレスや経路が複数あれば 2 行目以降は IF / KIND / STATE / NEIGH を空けて続ける
- インタフェースを持たない IPsec は `(ipsec)` という仮の行名で末尾に並べる。root でなく読めなければ STATE を `DENIED` にする
- rule は表に出さない。`--json` にだけ出す
- 名前でソートしてから出す。出力を決定的にするため
- 1 行目の空欄は `-`、続きの行の空欄は空白
- 列は固定幅 (`text/tabwriter`)。日本語を入れない (全角幅を数えないので列がずれる)

## ライブラリとしての使い方

```go
import "github.com/tommykey-apps/hynt"

r, err := hynt.Collect(ctx) // r.Links / r.Routes / r.Rules / r.Neighs / r.Policies
```

- 公開するのはリポジトリ直下の `hynt` と `link` `route` `neigh` `xfrm`。図のツールとの約束はこれらの型と関数
- 表示の都合 (空欄を `-` にする、列の並び) は公開パッケージに持ち込まない。CLI 専用の `internal/render` でやる
- `Collect` は root でなくても失敗しない。IPsec だけ読めなければ `IPsecDenied` を true にする
- 公開の型や関数を削ったり意味を変えたりするときは、図のツールが追随するまで古いものを残す

## JSON の形式

- `hynt.Report` をそのまま出したもの。Go 以外の道具が読む用
- 先頭に `schema` (整数)。項目を削ったり意味を変えたりしたときだけ上げる。足すだけなら上げない
- 読む側は知らない項目を無視する
- 空の一覧は `null` でなく `[]`
- 項目: `schema` `host` `links` `routes` `rules` `neighs` `ipsec` `ipsec_denied`

## 技術方針

- 標準ライブラリのみ。外部モジュールを追加しない
- CLI は `cmd/hynt`。リポジトリ直下はライブラリ (`package hynt`) にする
- netlink を自前で呼ばない。`ip -j` の JSON を `encoding/json` で読む
- `/sys/class/net` は補助情報 (`tun_flags` / `wireless` / `device`) にだけ使う
- 外部コマンドと sysfs の読み取りは interface で差し替え、テストは記録済みの JSON で回す
- cgo なし。単一バイナリ

## 配布

CLI は GitHub Releases (GoReleaser、linux amd64 / arm64)。副で `go install github.com/tommykey-apps/hynt/cmd/hynt@latest`。AUR には出さない。
ライブラリは Go のモジュールとして、図のツールが `go get github.com/tommykey-apps/hynt` で取り込む。Releases のタグがそのまま版になる。
Docker では配らない。ホストのインタフェースを読む道具なので、コンテナに入れると見たいものが見えない。
