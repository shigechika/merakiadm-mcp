# Repository overview

`merakiadm-mcp` is a read-only MCP server for Cisco Meraki Dashboard
administrators, over **stdio transport**. It is built on the official `mcp`
Python SDK's `MCPServer` (`merakiadm_mcp/server.py`) with `MerakiClient`
(`merakiadm_mcp/client.py`, httpx, GET only). See `CLAUDE.md` for the
architecture and `REVIEW.md` for what is blocking.

# Build & validate

```bash
python3 -m venv .venv
.venv/bin/pip install -e ".[test]"
.venv/bin/pytest -v
```

This mirrors `.github/workflows/test.yml`: `pip install -e ".[test]"` and
`pytest tests/ -v` on Python 3.10-3.14 plus one Windows job, and a `lint` job
running `ruff check .` at a pinned version. Lint findings are already
enforced; `ruff format` is not gated, so formatting nits are noise.

# What to focus review on

## 1. stdout is the JSON-RPC channel

Any `print()` or logging to stdout in `server.py` / `client.py` corrupts the
protocol stream. `--check` in `__main__.py` returns before `mcp.run()` and
prints to stdout on purpose; `scripts/smoke_test.py` is a standalone CLI.

## 2. Answers must stay bounded

The reason this server exists: Air Marshal, failed connections and the event
log return hundreds of KB to MB per call at a busy site, which makes the
caller's next model request exceed its context. Every tool aggregates
server-side, clamps `hours`, `top` and `per_page` with `_bound`, and writes
`capped` when it dropped something. Flag a new tool or change that returns a
raw API list, removes a clamp, or drops data without saying so.

## 3. The API key is the sensitive surface

`MERAKI_DASHBOARD_API_KEY` is sent only as the `Authorization: Bearer`
header. Flag anything that can put it in a log line, an exception message
or a tool response. httpx/httpcore loggers are held at WARNING in
`client.py`. Redirects are followed by hand and only to `https` URLs on
`meraki.com` hosts,
because httpx strips the header on cross-host redirects and following an
arbitrary `Location` with the header would leak it.

## 4. Read-only by construction

`MerakiClient` only has GET. `_Server.tool` sets
`ToolAnnotations(readOnlyHint=True, ...)` on every tool, and
`tests/test_server.py::test_every_tool_is_read_only` checks it. Flag any
non-GET request.

## 5. Cursors are opaque but filtered

`Page.cursor()` encodes only `CURSOR_PARAMS` (`startingAfter`,
`endingBefore`, `t0`, `t1`) and `parse_cursor()` drops everything else, so a
cursor passed back by a model cannot inject other query parameters. Keep it
that way.

## 6. MCPServer wraps returns

Tools return plain `str` / `dict`; do not suggest hand-built MCP content
envelopes. Exceptions become `ToolError` with their message via
`_expose_errors`. `daily_brief` and `health_check` report failures inside
their answer on purpose; other tools let errors propagate.

## 7. Public repository

No deployment-specific values (network, device or SSID names, IDs,
addresses) in code, tests, docs or `scripts/smoke_probes.py`;
`tests/test_smoke_probes.py` enforces the probe file. Test fixtures use
documentation names and RFC 5737 addresses.
