# リファレンス

すべて読み取り専用です。期間は時間単位で 1〜168 に、件数は下の範囲に丸めます。
切り捨てたときは `capped` と書き、どう絞ればよいかを添えます。

## health_check

引数なし。決まったキーの dict を返します：`status`（healthy / degraded /
error）、`service`、`version`、`base_url`、`auth`（ok / error / missing-env）、
`organizations`、`networks`、`devices`（状態別の台数）、健全でないときは
`detail`。オフラインか警告の機器があると degraded です。

## daily_brief

| 引数 | 既定 | 範囲 |
|---|---|---|
| `hours` | 24 | 1〜168 |
| `failure_threshold` | 10.0 | WARNING にする接続失敗の割合（%） |
| `top` | 5 | 項目ごとに挙げる名前の数（1〜20） |

ネットワークごとに `[DEVICES]`、`[DEVICES-DOWN]`、`[HEALTH]`、`[CONNECT]` /
`[CONNECT-HIGH-FAILURE]` と `[CONNECT-TOP-AP]`、`[SECURITY]`、`[UPLINK]` /
`[UPLINK-DOWN]`、または `[API-ERROR]` を出し、CRITICAL（API のエラー）、
WARNING（機器の停止、しきい値を超える失敗、セキュリティのイベント、
アップリンクの断）、OK に分けます。スイッチのポートは、アップリンクの印が
付いたものだけを見ます。

## connection_failures

| 引数 | 既定 | 範囲 |
|---|---|---|
| `network` | 対象が 1 つならそれ | 名前か ID |
| `hours` | 24 | 1〜168 |
| `top` | 10 | AP の数（1〜50） |

全体の成功率、段階・種類・SSID・VLAN 別の失敗、端末の数（数えるだけで
一覧はしない）、失敗の多い AP とその段階、現地時刻の時間帯別の失敗。

## air_marshal

| 引数 | 既定 | 範囲 |
|---|---|---|
| `network` | 対象が 1 つならそれ | 名前か ID |
| `hours` | 1 | 1〜168 |
| `top` | 20 | 区分ごとの SSID の数（1〜100） |

総数、自分の有線 LAN で見えた SSID（`wiredMacs`）、自分の有効な SSID 名を
ほかの電波が名乗っているもの。生の一覧は返しません。

## security_events

| 引数 | 既定 | 範囲 |
|---|---|---|
| `network` | 対象が 1 つならそれ | 名前か ID |
| `hours` | 24 | 1〜168 |
| `top` | 20 | 明細を出す件数（1〜100） |
| `event_types` | 下記 | イベントの種類の名前 |

既定の種類：`multiple_dhcp_servers_detected`、`rogue_dhcp`、
`dhcp_snoop_blocked`、`dhcp_blocked`、`mac_spoofing_attack`、
`rogue_ap_association`、`client_ip_conflict`、`client_ip6_conflict`、
`client_ip6_lla_conflict`、`ra_blocked`、`loop_detected`、`stp_bpdu_guard`、
`stp_root_guard`、`stp_loop_guard`。`192.0.0.0/29` の IP の重複
（464XLAT / CLAT）は別に数えます。

## list_events

| 引数 | 既定 | 範囲 |
|---|---|---|
| `product_type` | 必須 | wireless、switch、appliance、camera、cellularGateway、sensor |
| `network` | 対象が 1 つならそれ | 名前か ID |
| `event_types` | すべて | イベントの種類の名前 |
| `per_page` | 50 | 1〜100 |
| `cursor` | 最新のページ | 前の答えの `older_cursor` |

最後に `older_cursor` と `complete` を出します。
