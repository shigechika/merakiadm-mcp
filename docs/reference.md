# Reference

Every tool is read-only. Windows are in hours and clamped to 1-168; counts are
clamped to the ranges below. When a tool leaves something out it says
`capped` and how to narrow the question.

## health_check

No arguments. Returns a dict with fixed keys: `status` (healthy / degraded /
error), `service`, `version`, `base_url`, `auth` (ok / error / missing-env),
`organizations`, `networks`, `devices` (counts by status), and `detail` when
not healthy. Degraded means a device is offline or alerting.

## daily_brief

| Argument | Default | Range |
|---|---|---|
| `hours` | 24 | 1-168 |
| `failure_threshold` | 10.0 | percent of failed connections that raises a WARNING |
| `top` | 5 | 1-20 names per item |

Per network: `[DEVICES]`, `[DEVICES-DOWN]`, `[HEALTH]`, `[CONNECT]` /
`[CONNECT-HIGH-FAILURE]` with `[CONNECT-TOP-AP]`, `[SECURITY]`, `[UPLINK]` /
`[UPLINK-DOWN]`, or `[API-ERROR]`. Each network is CRITICAL (API error),
WARNING (device down, failures above the threshold, any security event, an
uplink down) or OK. Switch ports are only checked when the switch flags them
as uplinks. At most 25 networks are checked per call; the rest are reported
as `capped`.

## connection_failures

| Argument | Default | Range |
|---|---|---|
| `network` | the only network in scope | name or ID |
| `hours` | 24 | 1-168 |
| `top` | 10 | 1-50 access points |

Overall success rate, failures by step, type, SSID and VLAN, distinct
clients (counted, not listed), top access points with their failure steps,
failures per local hour.

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

## list_events

| Argument | Default | Range |
|---|---|---|
| `product_type` | required | wireless, switch, appliance, camera, cellularGateway, sensor |
| `network` | the only network in scope | name or ID |
| `event_types` | all | event type names |
| `per_page` | 50 | 1-100 |
| `cursor` | newest page | `older_cursor` from a previous answer |

Ends with `older_cursor` and `complete`.
