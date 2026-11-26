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
  --public-url https://meraki.example.com \
  --trusted-user-header X-Forwarded-User \
  --allow-redirect-uri https://claude.ai/api/mcp/auth_callback \
  --token-store ~/.local/state/merakiadm-mcp/tokens.json \
  --session-idle-ttl 180 --max-sessions-per-owner 3 \
  --port 8080 -- merakiadm-mcp
```

Run it behind a TLS reverse proxy that signs users in (your SSO), admits
only the people who may read the Dashboard, and passes the user name in
`X-Forwarded-User`. Every session runs with the one API key, so everyone the
proxy lets through can read everything that key can read: every organization
it belongs to, unless narrowed with `MERAKI_ORG_ID` / `MERAKI_NETWORK_IDS`.
Signing in is not enough, the proxy has to authorize too. `--token-store`
keeps issued tokens across restarts (without it every restart makes users
reconnect; the file is credential material, so keep it readable by the
service account only, in a directory that account can write: under systemd,
a `StateDirectory=` path rather than `~`). The two session options clear out
sessions a client left behind; the per-user cap also closes that user's
least recently used session when a new one goes over it, so set it to the
number of devices a person really uses at once. The proxy must strip any
`X-Forwarded-User` header a client sends: mcp-stdio trusts that header, so
a copy that gets through lets a client pose as another user. Give the server
its own host name, as above: mcp-stdio's documentation notes that claude.ai
connectors expect the endpoint path to be exactly `/mcp`. A connector added
with claude.ai's "No sign-in" option also needs
`--allow-client-id-url https://claude.ai/oauth/mcp-oauth-client-metadata`;
see the mcp-stdio documentation for these options.

Then add `https://meraki.example.com/mcp` as a custom connector in
claude.ai. The same connector works in the browser, the desktop app and
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
