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
