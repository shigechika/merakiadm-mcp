# セットアップ

### インストール

```bash
uvx merakiadm-mcp --check        # API キーを確かめる
# または
pip install merakiadm-mcp
```

Python 3.11 以上。

### 設定

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

### claude.ai（ブラウザ・デスクトップ・スマホ）

claude.ai は、OAuth つきの HTTP でリモートの MCP サーバにつなぎます。この
サーバは stdio で話します。[mcp-stdio](https://github.com/shigechika/mcp-stdio)
の `serve` モードがその間をつなぎます。stdio のサーバを、OAuth 2.1 の認可サーバを
内蔵した Streamable HTTP の口として出し、セッションごとに `merakiadm-mcp` の
プロセスを 1 つ起動します。API キーはそのホストから出ません。

```bash
export MERAKI_DASHBOARD_API_KEY=...
mcp-stdio serve --enable-oauth \
  --public-url https://mcp.example.com/meraki \
  --trusted-user-header X-Forwarded-User \
  --allow-redirect-uri https://claude.ai/api/mcp/auth_callback \
  --port 8080 -- merakiadm-mcp
```

利用者をサインインさせて（手元の SSO）、利用者名を `X-Forwarded-User` で渡す
TLS のリバースプロキシの後ろで動かします。オプションは mcp-stdio の文書を
見てください。そのうえで、claude.ai のカスタムコネクタに
`https://mcp.example.com/meraki/mcp` を足します。同じコネクタがブラウザ・
デスクトップアプリ・スマホのアプリで使えるので、朝の点検や「この端末は
どこにいる？」の確認がスマホからできます。上限つきの答えは、そこでいちばん
効きます。モデルの文脈に収まる答えは、小さな画面にも収まります。

### 開発

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
