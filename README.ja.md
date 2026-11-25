# merakiadm-mcp

[English](README.md) | [ドキュメント](https://shigechika.github.io/merakiadm-mcp/ja/)

Cisco Meraki Dashboard の管理者向けの、読み取り専用の MCP サーバです。
機器が落ちていないか、端末がどの段階で接続に失敗しているか、野良の DHCP
サーバやなりすましの SSID がいないか、といった毎朝の確認に、API の応答を
そのまま渡すのではなく、**上限つきの集計**で答えます。

## なぜ作ったか

利用者の多い拠点では、Dashboard のいくつかの API がモデルの文脈に収まらない
量を返します。Air Marshal は 1 時間で SSID が 1,000 を超え（数百 KB）、
接続失敗は 1 日で数千行、無線のイベントは 1 日で数万件になります。そのまま
渡すと、エージェントの次の呼び出しが失敗します。ここのツールはこれらの API
をサーバの中で読み、件数・順位・要る行だけを返します。切り捨てたときは
`capped` と書き、どう絞って聞き直せばよいかを添えます。

任意の API を呼べる汎用の Meraki MCP サーバを置き換えるものではなく、
組み合わせて使う想定です。定型の点検はこちら、自由な深掘りは汎用の方です。

## ツール

すべて読み取り専用（GET のみ）で、`readOnlyHint` を付けています。

| ツール | 答えること |
|---|---|
| `health_check` | 版、API キーが効くか、対象の組織とネットワーク、状態別の機器の台数 |
| `daily_brief` | 全ネットワークの直近 24 時間の点検を 1 回で：今と期間中に落ちた機器、健康アラート、接続の成功率（前の同じ長さの期間と比較）、無線のパケットロスとチャネルの使用率、セキュリティと運用のイベント、スイッチのアップリンク。CRITICAL / WARNING / OK に分ける |
| `connection_failures` | 無線の接続失敗を段階（assoc / auth / dhcp / dns）・種類・SSID・VLAN・AP・時間帯で集計 |
| `wireless_quality` | 上り・下りのパケットロス、通信のなかった AP、帯域ごとのチャネルの使用率（Wi-Fi と Wi-Fi 以外の干渉）、ベストエフォートの遅延。それぞれ悪い AP の順 |
| `air_marshal` | 周りの SSID：総数、自分の有線 LAN で見えた SSID（野良 AP）、自分の SSID 名を名乗る SSID |
| `availability_history` | オフライン（または警告・休止）になって戻った機器：回数、時間、まだ落ちているか |
| `operational_events` | まれな運用のイベント：再起動、RADIUS の無応答、DHCP のプールの枯渇、レーダー、無線の攻撃、スイッチの機器・設定・ポートの障害、イベントの取りこぼし |
| `security_events` | 野良や重複の DHCP サーバ、AP のなりすまし、野良 AP への関連付け、IP・IPv6 の重複、RA Guard、ループ、STP のガード |
| `list_events` | イベントの記録を 1 ページずつ。続きを読む `older_cursor` と、読み切ったかの `complete` を返す |

`192.0.0.0/29` の IP の重複は別に数え、警告にしません。464XLAT（CLAT）の
端末は設計上みな `192.0.0.2` を使うためです（RFC 7335）。

## インストール

```bash
uvx merakiadm-mcp --check        # API キーを確かめる
# または
pip install merakiadm-mcp
```

Python 3.11 以上。

## 設定

| 環境変数 | 必須 | 意味 |
|---|---|---|
| `MERAKI_DASHBOARD_API_KEY` | ○ | Dashboard の API キー（Bearer で送る） |
| `MERAKI_ORG_ID` | | 対象を絞る組織 ID（カンマ区切り） |
| `MERAKI_NETWORK_IDS` | | 対象を絞るネットワーク ID（カンマ区切り） |
| `MERAKI_BASE_URL` | | API の URL（既定 `https://api.meraki.com/api/v1`） |

このサーバは書き込みをしないので、書き込みのできるキーでも使えます。
読み取り専用の管理者のキーで足ります。

### Claude Code

```bash
claude mcp add merakiadm --env MERAKI_DASHBOARD_API_KEY=... -- uvx merakiadm-mcp
```

### Claude Desktop

```json
{
  "mcpServers": {
    "merakiadm": {
      "command": "uvx",
      "args": ["merakiadm-mcp"],
      "env": { "MERAKI_DASHBOARD_API_KEY": "..." }
    }
  }
}
```

## 開発

```bash
python3 -m venv .venv
.venv/bin/pip install -e ".[test]"
.venv/bin/pytest -v
```

`scripts/smoke_test.py` は、実際の組織に対して全ツールを呼び、壊れている
ものを報告します（出すのはツール名・状態・時間だけ）。

```bash
MERAKI_DASHBOARD_API_KEY=... python scripts/smoke_test.py
```

## ライセンス

MIT
