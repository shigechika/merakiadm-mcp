# merakiadm-mcp

Read-only MCP server for Cisco Meraki Dashboard administrators.

## Why

Several Dashboard endpoints return far more than a model's context can hold
at a busy site: an hour of Air Marshal can be over a thousand SSIDs
(hundreds of KB), a day of failed connections thousands of rows, a day of
wireless events tens of thousands. Passing them through verbatim makes an
agent's next request fail. Every tool here reads those endpoints
server-side and returns counts, rankings and the few rows that matter, and
says `capped` when it left something out and how to ask for less.

It complements, rather than replaces, a general-purpose Meraki MCP server
that can call any API operation: use this one for the routine checks, the
other for open-ended exploration.

## Tools

All tools are read-only (GET only) and annotated `readOnlyHint`.

| Tool | What it answers |
|---|---|
| `health_check` | Server version, API key validity, organizations and networks in scope, device counts by status |
| `daily_brief` | One-shot morning check of every network: devices offline/alerting, health alerts, connection success rate, security events, switch uplinks; CRITICAL / WARNING / OK |
| `connection_failures` | Failed wireless connections aggregated by step (assoc/auth/dhcp/dns), type, SSID, VLAN, access point and hour |
| `air_marshal` | Neighbouring SSIDs: totals, SSIDs seen on your wired LAN (rogues), SSIDs using one of your SSID names |
| `security_events` | Rogue/duplicate DHCP servers, AP spoofing, rogue AP association, IP/IPv6 conflicts, RA guard, loops, STP guards |
| `list_events` | One page of the event log with an `older_cursor` to continue and a `complete` flag |

IP conflicts on `192.0.0.0/29` are counted apart and never raise a warning:
464XLAT (CLAT) clients all use `192.0.0.2` by design (RFC 7335).

Next: [Setup](setup.md) · [Reference](reference.md)
