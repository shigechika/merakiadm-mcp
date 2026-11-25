# リファレンス

すべて読み取り専用です。期間は時間単位で 1〜168 に、件数は下の範囲に丸めます。
切り捨てたときは `capped` と書き、どう絞ればよいかを添えます。

## health_check

引数なし。決まったキーの dict を返します：`status`（healthy / degraded /
error）、`service`、`version`、`base_url`、`auth`（ok / error / missing-env）、
`organizations`、`networks`、`devices`（状態別の台数）、健全でないときは
`detail`。キーが効くときは、`api_get` のパスに使う `organization_list` と
`network_list`（ID と名前。20 と 50 まで）も返します。オフラインか警告の機器があると degraded です。

## daily_brief

| 引数 | 既定 | 範囲 |
|---|---|---|
| `hours` | 24 | 1〜168 |
| `failure_threshold` | 10.0 | WARNING にする接続失敗の割合（%） |
| `top` | 5 | 項目ごとに挙げる名前の数（1〜20） |

ネットワークごとに `[DEVICES]`、`[DEVICES-DOWN]`、`[AVAILABILITY]`、`[HEALTH]`、
`[CONNECT]` / `[CONNECT-HIGH-FAILURE]`（`hours` が 84 以下なら前の同じ長さの
期間と比べる）と `[CONNECT-TOP-AP]`、`[WIRELESS]`、`[SECURITY]`、`[OPERATIONS]` /
`[OPERATIONS-WARN]`、`[LOG-DROPPED]`、`[UPLINK]` / `[UPLINK-DOWN]`、`[CHANGES]`（管理者と画面
ごとの件数。値は出さない）、`[FIRMWARE]`（今の版と予定された更新）、`[LICENSE]` /
`[LICENSE-EXPIRING]`（組織ごとに 1 回、最初のネットワークに）、または `[API-ERROR]` を出し、
CRITICAL（API のエラー）、WARNING（今または期間中の機器の停止、しきい値を
超える失敗、セキュリティのイベント、警告に当たる運用のイベント、
アップリンクの断、有効でないか 30 日以内に切れるライセンス）、OK に分けます。スイッチのポートは、アップリンクの印が
付いたものだけを見ます。`[WIRELESS]`（パケットロス、上りのロスの悪い AP、
一番混んでいるチャネル、通信のなかった AP）は参考の行で、段階を変えません。
読めなかったときは `not read` と書きます。1 回に点検するのは 25 ネットワークまでで、40 秒を過ぎたら次のネットワークに
進みません。残りは `capped` として数だけ示します。50 秒を過ぎても終わらない
ネットワークは、途中の段で止めて、その旨を書きます。

## connection_failures

| 引数 | 既定 | 範囲 |
|---|---|---|
| `network` | 対象が 1 つならそれ | 名前か ID |
| `hours` | 24 | 1〜168 |
| `top` | 10 | AP の数（1〜50） |

全体の成功率と段階別の失敗は、接続の統計から出します。その下は、別の情報源で
ある接続失敗の記録から出します（件数は全体の行と少し違うことがあります）：
段階・種類・SSID・VLAN 別の失敗、端末の数（数えるだけで一覧はしない）、
失敗の多い AP とその段階、現地時刻の時間帯別の失敗。

## wireless_quality

| 引数 | 既定 | 範囲 |
|---|---|---|
| `network` | 対象が 1 つならそれ | 名前か ID |
| `hours` | 24 | 1〜168 |
| `top` | 10 | 項目ごとの AP の数（1〜50） |
| `min_packets` | 1000 | ロスの順位に入れる AP のパケット数の下限（1〜1000000） |

ネットワーク全体の上り（端末から AP）と下り（AP から端末）のパケットロス、
通信のなかった AP、方向ごとにロスの悪い AP、期間の平均のチャネルの使用率
（帯域ごとの全体と混んでいる無線。Wi-Fi と Wi-Fi 以外の干渉に分ける）、
ベストエフォートの平均の遅延が大きい AP（標本が 100 以上のものだけ）。
0.1% 未満のロスは `0.0%` でなく `<0.1%` と書きます。

## config_changes

| 引数 | 既定 | 範囲 |
|---|---|---|
| `network` | 対象が 1 つならそれ | 名前か ID |
| `hours` | 168 | 1〜744（31 日） |
| `top` | 30 | 件数（1〜100） |

組織の変更履歴のうち、そのネットワークのものと組織全体のものを、管理者と画面
ごとの件数、新しい順の変更（時刻、管理者、ネットワークか SSID、画面、項目、
変更前 → 変更後の値を短く）で出します。項目か画面の名前が秘密を指す（PSK・
パスワード・コミュニティ・鍵など）ときは、変更前後の値を `[redacted]` にします。
`api_get` で変更履歴を読んだときも同じです。`MERAKI_NETWORK_IDS` があるときは、組織全体の
変更をここでも `[CHANGES]` でも出さず、`[LICENSE]` も出しません（`api_get` がその範囲では
それらを断るのと同じ扱い）。この API は最後のページの後も同じ
1 件を返す「次のページ」を出し続けるので、新しい件が増えなくなったら読むのを
やめます。

## availability_history

| 引数 | 既定 | 範囲 |
|---|---|---|
| `network` | 対象が 1 つならそれ | 名前か ID |
| `hours` | 24 | 1〜168 |
| `top` | 20 | 機器の数（1〜100） |

状態の変化の履歴から、期間中に online でなかったことのある機器ごとに、
online から落ちた回数、期間内に online でなかった分数、期間の始まりに既に
落ちていたか（履歴を途中で切ったときは「不明」）、最後の変化の時刻、
まだ落ちているかを出します。

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

`security_events` と `operational_events` の明細では、時刻だけが違う連続した
イベントを 1 行にまとめ、`(xN)` と書きます。`event_types` に渡した名前が
何にも当たらず、Dashboard がそのネットワークの種類の一覧にも載せていないときは、
近い名前を添えて注意を出します。綴りを誤った種類には、API が何も返さないためです。

## operational_events

| 引数 | 既定 | 範囲 |
|---|---|---|
| `network` | 対象が 1 つならそれ | 名前か ID |
| `hours` | 24 | 1〜168 |
| `top` | 20 | 明細を出す件数（1〜100） |
| `event_types` | 下記 | イベントの種類の名前 |

既定の区分：再起動・ファームウェア、RADIUS、DHCP、電波（DFS と自動の
チャネル変更）、無線の攻撃、スイッチの機器、スイッチの設定、スイッチの
ポート、ローミング、イベントの記録（`events_dropped2`：AP が association
などの大量に出る種類のイベントを `n` 件間引いた記録。種類ごとに合計し、
`daily_brief` では `[LOG-DROPPED]` として出す）。`daily_brief` では、再起動、RADIUS の
無応答、DHCP のプールの枯渇、攻撃、スイッチの機器・設定・ポートの障害を
WARNING にし、レーダー、チャネル変更、取りこぼしは参考として出します。

## list_events

| 引数 | 既定 | 範囲 |
|---|---|---|
| `product_type` | 必須 | wireless、switch、appliance、camera、cellularGateway、sensor |
| `network` | 対象が 1 つならそれ | 名前か ID |
| `event_types` | すべて | イベントの種類の名前 |
| `per_page` | 50 | 3〜100 |
| `cursor` | 最新のページ | 前の答えの `older_cursor` |

最後に `older_cursor` と `complete` を出します。API は最古のイベントより前にも
1 か月ずつ古いページを返し続けるので、空のページで終わりとみなします。

## find_api

| 引数 | 既定 | 範囲 |
|---|---|---|
| `query` | 必須 | 英語のキーワード、operation ID、または具体的なパス |
| `top` | 10 | API の数（1〜50） |

組織自身の OpenAPI 仕様（`/organizations/{id}/openapiSpec`、1 回読んで 6 時間
覚えておく。最初の呼び出しは数秒かかる）の GET の API を探します。operation ID
かパスを渡すと、その API の説明と引数を示します。

## api_get

| 引数 | 既定 | 範囲 |
|---|---|---|
| `path` | 必須 | ID を埋めた API のパス（例 `/networks/N_123/wireless/ssids`） |
| `params` | なし | クエリの引数。一覧の値は `key[]` で送る |
| `fields` | すべて | 各要素に残すキー。点でつなぐと中に入る（`device.name`） |
| `offset` | 0 | 一覧の何件目から |
| `limit` | 20 | 一覧の件数（1〜200） |
| `max_chars` | 20000 | 文字数の上限（2000〜60000） |
| `max_pages` | 1 | 次のページをたどる数（1〜5）。20 秒を過ぎたら次を読み始めず、途中のページが失敗したら `page_error` を付けてそれまでの分を返す |

`params` と `fields` は JSON の文字列でも受け付けます（そう送るクライアントが
あるため）。`fields` はカンマ区切りの文字列でも構いません。

dict を返します：`path`、`observed_at`（UTC）、`operation`（API の一覧を覚えて
いるときの operation ID）、`params`、`pages_read`、`has_next_page`、`total_items` / `offset` / `returned`（一覧が
オブジェクトの中にあるとき、たとえば `events` は `list_name` も）、`redacted`
（伏せた値の数）、`next_params` / `prev_params`、`capped`、`note`、`data`。

- 受け付けるのは `/organizations`・`/networks`・`/devices`・`/administered`
  の下の相対パスだけです。ホスト、`..`、`%`、`?`、`#`、埋めていない
  `{placeholder}` は断るので、API キーが API のホストの外へ出ることはありません。
- `MERAKI_ORG_ID` / `MERAKI_NETWORK_IDS` の外の組織・ネットワーク・機器の
  シリアルは断ります。`MERAKI_NETWORK_IDS` があるとき、組織全体を読む API は
  `networkIds` を取るものだけ許し、設定したネットワークに絞ります。
- 読むのは既定で 1 ページ（`max_pages` で 5 ページまで）です。秘密らしいキー（PSK、RADIUS の共有鍵、SNMP の
  コミュニティ名、パスワード、トークン、鍵。文字列に入った JSON の中も）の値は、
  ほかの処理より先に `[redacted]` に置き換えます。
- 答えは `limit` 件に切り、`max_chars` に収まるよう縮めます：長い入れ子の一覧と
  文字列を短くし、それでも足りなければ要素を減らし、なお大きければキーだけを
  返します。どれかが起きると `capped` になります。
- 対象範囲の機器の `serial` には `deviceName` を、ほかの `Serial` で終わるキーには
  対応する `…Name`（`recentDeviceSerial` → `recentDeviceName`）を添えます。
- `find_api` の API の一覧は、メモリと `$XDG_CACHE_HOME/merakiadm-mcp/`（なければ
  `~/.cache/merakiadm-mcp/`）に 6 時間覚えておきます。呼び出しごとに起動する使い方
  でも 4 MB の仕様をたまにしか読みません。書けないときは毎回取り直します。

## resolve_entity

| 引数 | 既定 | 範囲 |
|---|---|---|
| `query` | 必須 | 名前やその一部、ID、シリアル、MAC、IP |
| `top` | 10 | 種類ごとの件数（1〜50） |

対象範囲の一覧から、組織（ID・名前）、ネットワーク（ID・名前）、機器（シリアル・
名前・MAC・LAN の IP）を引きます。端末は `find_client` で探します。

## find_client

| 引数 | 既定 | 範囲 |
|---|---|---|
| `query` | 必須 | MAC、IPv4/IPv6 のアドレス、ユーザ名や端末名の一部 |
| `network` | 対象が 1 つならそれ | 名前か ID |
| `hours` | 1 | 1〜24 |
| `top` | 5 | ほかの候補とイベントの件数（1〜20） |

MAC はそのまま引きます（組織の端末検索）。IP は直近 `hours` の端末から探し、
アドレスが完全に一致するものだけ残します（API は前方一致で返すため）。利用者の
多い拠点では 1 日分で 25 秒ほどかかります。名前は直近 `hours` の端末を 5,000 台
まで見て、それより多ければ `capped` と書きます。一番最近見えた候補について、端末の
記録と、無線の端末なら段階ごとの接続、種類と AP ごとのイベントと電波の強さの幅、
最近の `bad` のイベント、ベストエフォートの平均の遅延を出します。
