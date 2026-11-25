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
- `merakiadm_mcp/server.py` — `MCPServer` with 9 tools: `health_check`,
  `daily_brief`, `connection_failures`, `wireless_quality`, `availability_history`, `air_marshal`,
  `security_events`, `operational_events`, `list_events`. Event type sets
  live in `SECURITY_EVENT_TYPES` and `OPERATIONAL_EVENT_GROUPS` (the latter
  holds only rare types; `OPERATIONAL_WARN_TYPES` decides what raises a
  WARNING in `daily_brief`). `_Server.tool` marks every tool read-only and turns
  exceptions into `ToolError` with their message. Organizations, networks,
  device names and SSID names are cached for 300 s in-process.
- `merakiadm_mcp/__main__.py` — console-script entry (`merakiadm-mcp`);
  `--check` verifies the key; `os._exit(0)` on KeyboardInterrupt is deliberate
  (stdio reader daemon thread vs. Python 3.14 shutdown).

## Rules

- **Bounded output.** Air Marshal, failed connections and events are huge at
  a busy site (an hour of Air Marshal can be over a thousand SSIDs and
  hundreds of KB, a day of failed connections thousands of rows, a day of
  wireless events tens of thousands). A tool aggregates server-side, takes `hours` and `top` /
  `per_page` bounds clamped by `_bound`, and says `capped` when it dropped
  anything. Never add a tool that returns a raw list.
- Events are read newest page first (no `startingAfter`, which answers
  oldest first) and trimmed to the window, so a capped read loses the oldest
  events of the window, never the newest. The events endpoint refuses
  `perPage` below 3. A page that is not full reaches back a month
  (`pageStartAt`), and `prev` is offered forever, a month at a time, even
  past the oldest event: `_read_events` is capped only when `pageStartAt`
  is inside the window, and `list_events` treats an empty page as the end. Availability change history answers newest first and
  its `next` link pins `t0`/`t1`; `get_all` drops `timespan` then.
- `events_dropped2` is an access point reporting it dropped `n` events of a
  high-volume type (`eventData.type`); it is reported as `[LOG-DROPPED]`,
  never as an operational event.
- IP conflicts on `192.0.0.0/29` (464XLAT/CLAT, RFC 7335) are counted apart
  (`_split_clat`) and never raise a WARNING.
- Public repository: English in code, comments, commits and docs (plus the
  `.ja.md` translations). No deployment-specific values (network, device,
  SSID names, IDs, addresses) anywhere — `tests/test_smoke_probes.py`
  enforces it for the probe specs.
- Python 3.11+ (`from __future__ import annotations`); `zoneinfo` needs the
  `tzdata` dependency on Windows.
- stdout is the JSON-RPC channel while serving: no `print()` in `server.py` /
  `client.py`.
- `scripts/smoke_harness.py` is shared verbatim with the other servers of this
  family; fix engine bugs there and sync, do not patch this copy.
