# CLAUDE.md

## Overview

Read-only MCP server for Cisco Meraki Dashboard administrators (Dashboard API v1).
Exposes bounded, aggregated summaries over STDIO transport. GET only.

## Commands

```bash
python3 -m venv .venv
.venv/bin/pip install -e ".[test]"
.venv/bin/pytest -v                 # all tests
.venv/bin/ruff check .              # lint (CI pins the ruff version)
MERAKI_DASHBOARD_API_KEY=... .venv/bin/python scripts/smoke_test.py   # live smoke test
```

## Architecture

- `merakiadm_mcp/client.py` — `MerakiClient`: httpx, GET only, Bearer auth.
  `page()` returns one page (`Page`) with the `Link` header parsed into
  `links` (only `startingAfter` / `endingBefore` / `t0` / `t1` survive, see
  `CURSOR_PARAMS`); `get_all()` follows `rel=next` for at most `max_pages`
  and reports `capped`. Redirects are followed by hand and only to `https`
  `meraki.com` hosts (httpx drops the
  Authorization header on cross-host redirects). 429 and 5xx are retried with
  `Retry-After` within a retry budget. httpx/httpcore logging is held at WARNING.
- `merakiadm_mcp/server.py` — `MCPServer` with 6 tools: `health_check`,
  `daily_brief`, `connection_failures`, `air_marshal`, `security_events`,
  `list_events`. `_Server.tool` marks every tool read-only and turns
  exceptions into `ToolError` with their message. Organizations, networks,
  device names and SSID names are cached for 300 s in-process.
- `merakiadm_mcp/__main__.py` — console-script entry (`merakiadm-mcp`);
  `--check` verifies the key; `os._exit(0)` on KeyboardInterrupt is deliberate
  (stdio reader daemon thread vs. Python 3.14 shutdown).

## Rules

- **Bounded output.** Air Marshal, failed connections and events are huge at
  a busy site (measured: an hour of Air Marshal ~1,300 SSIDs / 570 KB, a day
  of failed connections ~2,000 rows / 385 KB, a day of wireless events
  ~50,000). A tool aggregates server-side, takes `hours` and `top` /
  `per_page` bounds clamped by `_bound`, and says `capped` when it dropped
  anything. Never add a tool that returns a raw list.
- IP conflicts on `192.0.0.0/29` (464XLAT/CLAT, RFC 7335) are counted apart
  (`_split_clat`) and never raise a WARNING.
- Public repository: English in code, comments, commits and docs (plus the
  `.ja.md` translations). No deployment-specific values (network, device,
  SSID names, IDs, addresses) anywhere — `tests/test_smoke_probes.py`
  enforces it for the probe specs.
- Python 3.10+ (`from __future__ import annotations`); `zoneinfo` needs the
  `tzdata` dependency on Windows.
- stdout is the JSON-RPC channel while serving: no `print()` in `server.py` /
  `client.py`.
- `scripts/smoke_harness.py` is shared verbatim with the other servers of this
  family; fix engine bugs there and sync, do not patch this copy.
