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

For everything else, `find_api` searches the Dashboard's own OpenAPI spec
for a read operation and `api_get` calls it under the same rules: one page,
a size limit, secrets masked, the configured scope enforced. One server
covers both the routine checks and open-ended exploration, so an agent does
not need a second, unbounded Meraki server.

## Tools

All tools are read-only (GET only) and annotated `readOnlyHint`.

| Tool | What it answers |
|---|---|
| `health_check` | Server version, API key validity, organizations and networks in scope, device counts by status |
| `daily_brief` | One-shot morning check of every network: devices offline/alerting, health alerts, connection success rate, wireless packet loss and channel use, security events, switch uplinks; CRITICAL / WARNING / OK |
| `connection_failures` | Failed wireless connections aggregated by step (assoc/auth/dhcp/dns), type, SSID, VLAN, access point and hour |
| `wireless_quality` | Packet loss in each direction, access points with no traffic, channel utilization per band (Wi-Fi and non-Wi-Fi), best-effort latency; the worst access points of each |
| `air_marshal` | Neighbouring SSIDs: totals, SSIDs seen on your wired LAN (rogues), SSIDs using one of your SSID names |
| `security_events` | Rogue/duplicate DHCP servers, AP spoofing, rogue AP association, IP/IPv6 conflicts, RA guard, loops, STP guards |
| `list_events` | One page of the event log with an `older_cursor` to continue and a `complete` flag |
| `resolve_entity` | Organization, network and device IDs from a name, serial, MAC or LAN IP |
| `find_client` | A client by MAC, IP or user/description: its record, last AP or switch port, and its wireless connections, events per AP with signal, latest problems, latency |
| `find_api` | Search the Dashboard's read (GET) operations by English keywords, or show one operation's parameters |
| `api_get` | Call any read operation: one page, `fields` / `offset` / `limit`, a size limit, secrets masked as `[redacted]`, scope enforced |

IP conflicts on `192.0.0.0/29` are counted apart and never raise a warning:
464XLAT (CLAT) clients all use `192.0.0.2` by design (RFC 7335).

Next: [Setup](setup.md) · [Reference](reference.md)
