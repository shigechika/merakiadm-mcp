# Setup

### Install

```bash
uvx merakiadm-mcp --check        # verify the API key
# or
pip install merakiadm-mcp
```

Python 3.10 or later.

### Configuration

| Variable | Required | Meaning |
|---|---|---|
| `MERAKI_DASHBOARD_API_KEY` | yes | Dashboard API key (sent as a Bearer token) |
| `MERAKI_ORG_ID` | no | Comma-separated organization IDs to limit the scope |
| `MERAKI_NETWORK_IDS` | no | Comma-separated network IDs to limit the scope |
| `MERAKI_BASE_URL` | no | API base URL (default `https://api.meraki.com/api/v1`) |

The server never writes: a key with write access is safe to use, but a
read-only Dashboard administrator is enough.

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

### Development

```bash
python3 -m venv .venv
.venv/bin/pip install -e ".[test]"
.venv/bin/pytest -v
```

`scripts/smoke_test.py` calls every tool against a live organization and
reports which ones are broken (names, statuses and timings only):

```bash
MERAKI_DASHBOARD_API_KEY=... python scripts/smoke_test.py
```
