# Setup

### Install

```bash
uvx merakiadm-mcp --check        # verify the API key
# or
pip install merakiadm-mcp
```

Python 3.11 or later.

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

### claude.ai (web, desktop and mobile)

claude.ai connects to remote MCP servers over HTTP with OAuth, and this
server speaks stdio. [mcp-stdio](https://github.com/shigechika/mcp-stdio)'s
`serve` mode bridges the two: it exposes a stdio server as a Streamable HTTP
endpoint with an embedded OAuth 2.1 authorization server, and starts one
`merakiadm-mcp` process per session. The API key stays on that host.

```bash
export MERAKI_DASHBOARD_API_KEY=...
mcp-stdio serve --enable-oauth \
  --public-url https://mcp.example.com/meraki \
  --trusted-user-header X-Forwarded-User \
  --allow-redirect-uri https://claude.ai/api/mcp/auth_callback \
  --port 8080 -- merakiadm-mcp
```

Run it behind a TLS reverse proxy that signs users in (your SSO) and passes
the user name in `X-Forwarded-User`; see the mcp-stdio documentation for the
options. Then add `https://mcp.example.com/meraki/mcp` as a custom connector
in claude.ai. The same connector works in the browser, the desktop app and
the mobile apps, so the morning check or a "where is this client?" lookup
can be done from a phone. Bounded answers matter most there: a reply that
fits a model's context also fits a small screen.

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
