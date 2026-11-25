# Reference

Every tool is read-only. Windows are in hours and clamped to 1-168; counts are
clamped to the ranges below. When a tool leaves something out it says
`capped` and how to narrow the question.

## health_check

No arguments. Returns a dict with fixed keys: `status` (healthy / degraded /
error), `service`, `version`, `base_url`, `auth` (ok / error / missing-env),
`organizations`, `networks`, `devices` (counts by status), and `detail` when
not healthy. When the key works it also lists `organization_list` and
`network_list` (IDs and names, at most 20 and 50) for `api_get` paths. Degraded means a device is offline or alerting.

## daily_brief

| Argument | Default | Range |
|---|---|---|
| `hours` | 24 | 1-168 |
| `failure_threshold` | 10.0 | percent of failed connections that raises a WARNING |
| `top` | 5 | 1-20 names per item |

Per network: `[DEVICES]`, `[DEVICES-DOWN]`, `[AVAILABILITY]`, `[HEALTH]`,
`[CONNECT]` / `[CONNECT-HIGH-FAILURE]` (with the previous window of the same
length when `hours` is 84 or less) and `[CONNECT-TOP-AP]`, `[WIRELESS]`, `[SECURITY]`,
`[OPERATIONS]` / `[OPERATIONS-WARN]`, `[LOG-DROPPED]`, `[UPLINK]` / `[UPLINK-DOWN]`, or
`[API-ERROR]`. Each network is CRITICAL (API error), WARNING (device down now
or during the window, failures above the threshold, any security event, a
warning-level operational event, an uplink down) or OK. Switch ports are only checked when the switch flags them
as uplinks. `[WIRELESS]` (packet loss, the worst access points by upstream loss, the
busiest channel, access points with no traffic) is informational and never changes
the tier; when it cannot be read it says `not read`. At most 25 networks, and only those started within 40 seconds, are checked
per call; the rest are reported as `capped`. A network still running at
50 seconds stops between steps and says so.

## connection_failures

| Argument | Default | Range |
|---|---|---|
| `network` | the only network in scope | name or ID |
| `hours` | 24 | 1-168 |
| `top` | 10 | 1-50 access points |

Overall success rate and failures by step, from the connection stats. Then,
from the failed-connection log (a separate source whose count can differ a
little from the overall line): failures by step, type, SSID and VLAN, distinct
clients (counted, not listed), top access points with their failure steps,
failures per local hour.

## wireless_quality

| Argument | Default | Range |
|---|---|---|
| `network` | the only network in scope | name or ID |
| `hours` | 24 | 1-168 |
| `top` | 10 | 1-50 access points per section |
| `min_packets` | 1000 | 1-1000000 packets an access point must carry to be ranked by loss |

Packet loss for the whole network, upstream (client to AP) and downstream
(AP to client); access points that carried no traffic; the worst access
points by loss in each direction; channel utilization averaged over the
window, per band and for the busiest radios, split into Wi-Fi and non-Wi-Fi
(interference); the access points with the highest average best-effort
latency (only those with at least 100 samples). Loss below 0.1% is shown as
`<0.1%`, never `0.0%`.

## availability_history

| Argument | Default | Range |
|---|---|---|
| `network` | the only network in scope | name or ID |
| `hours` | 24 | 1-168 |
| `top` | 20 | 1-100 devices |

From the availability change history: for each device that was not online
at some point in the window, how many times it left online, minutes not
online within the window, whether it was already down when the window began
(reported as unknown when the history was capped), last change, and whether
it is still down.

## air_marshal

| Argument | Default | Range |
|---|---|---|
| `network` | the only network in scope | name or ID |
| `hours` | 1 | 1-168 |
| `top` | 20 | 1-100 SSIDs per section |

Totals, SSIDs seen on your wired LAN (`wiredMacs`), and SSIDs broadcast by
other radios under one of your enabled SSID names. The raw list is never
returned.

## security_events

| Argument | Default | Range |
|---|---|---|
| `network` | the only network in scope | name or ID |
| `hours` | 24 | 1-168 |
| `top` | 20 | 1-100 events shown |
| `event_types` | see below | event type names |

Default types: `multiple_dhcp_servers_detected`, `rogue_dhcp`,
`dhcp_snoop_blocked`, `dhcp_blocked`, `mac_spoofing_attack`,
`rogue_ap_association`, `client_ip_conflict`, `client_ip6_conflict`,
`client_ip6_lla_conflict`, `ra_blocked`, `loop_detected`, `stp_bpdu_guard`,
`stp_root_guard`, `stp_loop_guard`. IP conflicts on `192.0.0.0/29`
(464XLAT/CLAT) are counted apart.

In the detail lines of `security_events` and `operational_events`, neighbouring
events that differ only in time are folded into one line with `(xN)`. An
`event_types` name that matched nothing and that the Dashboard does not list
for the network gets a note with close names, since the API answers a misspelt type with nothing.

## operational_events

| Argument | Default | Range |
|---|---|---|
| `network` | the only network in scope | name or ID |
| `hours` | 24 | 1-168 |
| `top` | 20 | 1-100 events shown |
| `event_types` | see below | event type names |

Default groups: reboot/firmware, RADIUS, DHCP, radio (DFS and automatic
channel changes), wireless attack, switch hardware, switch config, switch
port, roaming, event log (`events_dropped2`: an access point dropped `n`
events of a high-volume type such as association; reported per type, and
in `daily_brief` as `[LOG-DROPPED]`). In `daily_brief`, reboots, RADIUS timeouts,
DHCP pool exhaustion, attacks and switch hardware/config/port faults raise a
WARNING; radar, channel changes and dropped entries are informational.

## list_events

| Argument | Default | Range |
|---|---|---|
| `product_type` | required | wireless, switch, appliance, camera, cellularGateway, sensor |
| `network` | the only network in scope | name or ID |
| `event_types` | all | event type names |
| `per_page` | 50 | 3-100 |
| `cursor` | newest page | `older_cursor` from a previous answer |

Ends with `older_cursor` and `complete`. The API offers an older page even
past the oldest event, a month at a time, so an empty page counts as the end.

## find_api

| Argument | Default | Range |
|---|---|---|
| `query` | required | English keywords, an operation ID, or a concrete path |
| `top` | 10 | 1-50 operations |

Searches the GET operations of the organization's own OpenAPI spec
(`/organizations/{id}/openapiSpec`, read once and cached for six hours; the
first call takes a few seconds). Given an operation ID or a path, shows that
operation's summary, description and parameters.

## api_get

| Argument | Default | Range |
|---|---|---|
| `path` | required | API path with IDs filled in, e.g. `/networks/N_123/wireless/ssids` |
| `params` | none | query parameters; a list value is sent as `key[]` |
| `fields` | all | keys to keep per item; dotted paths reach inside (`device.name`) |
| `offset` | 0 | first list item |
| `limit` | 20 | 1-200 list items |
| `max_chars` | 20000 | 2000-60000 characters |
| `max_pages` | 1 | 1-5 pages; no further page is started after 20 seconds, and a page that fails ends the read with `page_error` and the pages before it |

`params` and `fields` are also accepted as JSON-encoded strings (some
clients send them that way); `fields` also as a comma-separated string.

Returns a dict: `path`, `observed_at` (UTC), `operation` (the operation ID,
when the index is already cached), `params`, `pages_read`, `has_next_page`, `total_items` / `offset` / `returned` (and
`list_key` when the list sits inside an object, such as `events`),
`redacted` (how many values were masked), `next_params` / `prev_params`,
`capped`, `note` and `data`.

- Only relative paths under `/organizations`, `/networks`, `/devices` and
  `/administered` are accepted; a host, `..`, `%`, `?`, `#` or an unfilled
  `{placeholder}` is refused, so the API key never leaves the API host.
- Organizations, networks and device serials outside `MERAKI_ORG_ID` /
  `MERAKI_NETWORK_IDS` are refused. With `MERAKI_NETWORK_IDS` set, an
  organization-wide read is only allowed when the operation takes
  `networkIds`, which is then limited to the configured networks.
- One page is read. Values of secret-looking keys (PSK, RADIUS secrets, SNMP
  communities, passwords, tokens, keys, also inside JSON carried in strings)
  are replaced with `[redacted]` before anything else.
- The answer is cut to `limit` items and shrunk to `max_chars`: long nested
  lists and strings are shortened, then items are dropped; if even that is
  too large, only the keys are returned. Any of these sets `capped`.
- Every `serial` of a device in scope gets a `deviceName`; another key
  ending in `Serial` gets the matching `…Name` (`recentDeviceSerial` →
  `recentDeviceName`).
- The operation index behind `find_api` is kept for six hours in memory and
  in `$XDG_CACHE_HOME/merakiadm-mcp/` (or `~/.cache/merakiadm-mcp/`), so a
  server started per call reads the 4 MB spec only once in a while; when the
  directory is not writable it is fetched again.

## resolve_entity

| Argument | Default | Range |
|---|---|---|
| `query` | required | name or part of one, ID, serial, MAC or IP |
| `top` | 10 | 1-50 matches per kind |

Organizations by ID and name, networks by ID and name, devices by serial,
name, MAC and LAN IP, from the inventory in scope. Clients are looked up
with `find_client`.

## find_client

| Argument | Default | Range |
|---|---|---|
| `query` | required | MAC, IPv4/IPv6 address, or part of a user name or description |
| `network` | the only network in scope | name or ID |
| `hours` | 1 | 1-24 |
| `top` | 5 | 1-20 other matches and events |

A MAC is looked up directly (organization client search). An IP searches the
clients of the last `hours` and keeps the exact address (the API matches a
prefix); a day takes about 25 seconds at a busy site. A name scans at most
5,000 clients of the last `hours` and says `capped` when there were more.
For the most recently seen match: the client record and, for a wireless
client, its connection stats per step, connectivity events by type and by
access point with the signal range, the latest `bad` events, and average
best-effort latency.
