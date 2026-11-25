"""MCP server for administrators of a Cisco Meraki Dashboard organization.

Read-only. Every tool reads the Dashboard API v1 and answers with a bounded,
aggregated Markdown summary rather than raw API payloads: several endpoints
(Air Marshal, failed connections, events) return megabytes for a busy site,
which would overflow a model's context. When a tool stops early it says so
("capped") and how to ask for less.

STDIO transport is used for JSON-RPC communication.
"""

from __future__ import annotations

import collections
import datetime
import functools
import inspect
import ipaddress
import json
import os
import re
import time
from typing import Any, Optional
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from mcp.server.mcpserver import MCPServer
from mcp.server.mcpserver.exceptions import ToolError
from mcp.shared.exceptions import MCPError
from mcp.types import ToolAnnotations

from merakiadm_mcp import __version__
from merakiadm_mcp.client import (
    DEFAULT_BASE_URL,
    MerakiAPIError,
    MerakiClient,
    MerakiClientError,
    parse_cursor,
)

#: Security event types: rogue or duplicate DHCP servers, spoofed or rogue
#: access points, address conflicts, IPv6 RA guard, loops and spanning-tree
#: guards. Names from GET /networks/{id}/events/eventTypes.
SECURITY_EVENT_TYPES = (
    "multiple_dhcp_servers_detected",
    "rogue_dhcp",
    "dhcp_snoop_blocked",
    "dhcp_blocked",
    "mac_spoofing_attack",
    "rogue_ap_association",
    "client_ip_conflict",
    "client_ip6_conflict",
    "client_ip6_lla_conflict",
    "ra_blocked",
    "loop_detected",
    "stp_bpdu_guard",
    "stp_root_guard",
    "stp_loop_guard",
)
#: Operational event types, by group: rare, actionable events (reboots,
#: RADIUS or DHCP trouble, radar, wireless attacks, switch hardware and port
#: faults, lost log entries). High-volume types (association, port up/down,
#: per-client authentication) are left to connection_failures and list_events.
OPERATIONAL_EVENT_GROUPS = {
    "reboot/firmware": ("boot", "boot_ios_up", "boot_ios_down", "upgrade_transition"),
    "RADIUS": (
        "8021x_radius_timeout",
        "radius_mab_timeout",
        "radius_proxy_homeserver_dead",
        "radius_proxy_homeserver_zombie",
        "radius_proxy_tls_fail",
    ),
    "DHCP": ("dhcp_no_leases", "dhcp_problem"),
    "radio": ("dfs_event", "auto_rf_channel_change", "ai_rrm_lite_auto_rf_channel_change", "sunray_auto_rf_channel_change", "noise_avoid_begin"),
    "wireless attack": ("bcast_deauth_attack", "bcast_disassoc_attack", "packet_flood", "device_packet_flood"),
    "switch hardware": ("psu_error", "psu_remove", "temp_critical", "memory_low", "diskspace_low", "stack_cable_state", "conn_state_change"),
    "switch config": ("config_apply_failure", "config_apply_error", "config_startup_save_failure"),
    "switch port": ("udld_alert", "pm_err_disable_monitor", "mac_flap_detected", "stp_port_role_change", "topology_changed"),
    "roaming": ("l3roaming_set_anchor_fail", "l3roaming_lost_anchor"),
    "event log": ("events_dropped2",),
}
OPERATIONAL_EVENT_TYPES = tuple(t for types in OPERATIONAL_EVENT_GROUPS.values() for t in types)
_GROUP_OF = {t: g for g, types in OPERATIONAL_EVENT_GROUPS.items() for t in types}
#: Operational types that raise a WARNING in daily_brief; the rest are informational.
OPERATIONAL_WARN_TYPES = frozenset(
    {
        "boot",
        "boot_ios_down",
        "8021x_radius_timeout",
        "radius_mab_timeout",
        "radius_proxy_homeserver_dead",
        "radius_proxy_homeserver_zombie",
        "radius_proxy_tls_fail",
        "dhcp_no_leases",
        "bcast_deauth_attack",
        "bcast_disassoc_attack",
        "packet_flood",
        "device_packet_flood",
        "psu_error",
        "psu_remove",
        "temp_critical",
        "memory_low",
        "diskspace_low",
        "config_apply_failure",
        "config_apply_error",
        "udld_alert",
        "pm_err_disable_monitor",
        "mac_flap_detected",
        "l3roaming_set_anchor_fail",
    }
)
EVENT_PRODUCT_TYPES = ("wireless", "switch", "appliance", "camera", "cellularGateway", "sensor")
FAILURE_STEPS = ("assoc", "auth", "dhcp", "dns")
MAX_HOURS = 168  # the failed-connection and connection-stats endpoints look back at most 7 days
CACHE_SECONDS = 300
MAX_BRIEF_NETWORKS = 25  # each network costs about ten requests and a section of output
_EVENT_TYPE_RE = re.compile(r"^[A-Za-z0-9_]{1,64}$")
#: RFC 7335 IPv4 Service Continuity Prefix: 464XLAT (CLAT) clients all use
#: 192.0.0.2 on purpose, so a "conflict" on it is not a real duplicate.
CLAT_PREFIX = ipaddress.ip_network("192.0.0.0/29")


def _expose_errors(fn):
    """Wrap a tool so any exception reaches the model as a ToolError with its message.

    mcp 2.x hides an exception's text (the model sees only "Error executing
    tool <name>") unless a ToolError is raised.
    """
    if inspect.iscoroutinefunction(fn):

        @functools.wraps(fn)
        async def wrapper(*args, **kwargs):
            try:
                return await fn(*args, **kwargs)
            except (ToolError, MCPError):
                raise
            except Exception as exc:
                raise ToolError(str(exc) or type(exc).__name__) from exc

    else:

        @functools.wraps(fn)
        def wrapper(*args, **kwargs):
            try:
                return fn(*args, **kwargs)
            except (ToolError, MCPError):
                raise
            except Exception as exc:
                raise ToolError(str(exc) or type(exc).__name__) from exc

    return wrapper


class _Server(MCPServer):
    """MCPServer whose tools are read-only and report their exception messages."""

    def tool(self, *args, **kwargs):
        kwargs.setdefault(
            "annotations",
            ToolAnnotations(readOnlyHint=True, idempotentHint=True, openWorldHint=True),
        )
        register = super().tool(*args, **kwargs)

        def decorator(fn):
            register(_expose_errors(fn))
            return fn

        return decorator


mcp = _Server("merakiadm", version=__version__)

_client: MerakiClient | None = None
_cache: dict[str, tuple[float, Any]] = {}


def _get_client() -> MerakiClient:
    """Return the shared client, created from the environment on first use.

    MERAKI_DASHBOARD_API_KEY: Dashboard API key (required).
    MERAKI_BASE_URL: API base URL (optional; default api.meraki.com/api/v1).
    """
    global _client
    if _client is None:
        _client = MerakiClient(
            os.environ.get("MERAKI_DASHBOARD_API_KEY", ""),
            base_url=os.environ.get("MERAKI_BASE_URL", "") or DEFAULT_BASE_URL,
        )
    return _client


def _cached(key: str, loader):
    hit = _cache.get(key)
    now = time.monotonic()
    if hit and now - hit[0] < CACHE_SECONDS:
        return hit[1]
    value = loader()
    _cache[key] = (now, value)
    return value


def _env_list(name: str) -> list[str]:
    return [v.strip() for v in os.environ.get(name, "").split(",") if v.strip()]


def _organizations() -> list[dict]:
    """Organizations in scope: MERAKI_ORG_ID (comma-separated) or every one the key sees."""

    def load():
        wanted = _env_list("MERAKI_ORG_ID")
        orgs = _get_client().get("/organizations") or []
        if wanted:
            orgs = [o for o in orgs if str(o.get("id")) in wanted]
            if not orgs:
                raise ToolError("MERAKI_ORG_ID matches no organization this API key can read")
        return orgs

    return _cached("orgs", load)


def _networks() -> list[dict]:
    """Networks in scope: MERAKI_NETWORK_IDS (comma-separated) or every network of the organizations."""

    def load():
        wanted = _env_list("MERAKI_NETWORK_IDS")
        nets: list[dict] = []
        for org in _organizations():
            nets.extend(_get_client().get(f"/organizations/{org['id']}/networks", {"perPage": 100000}) or [])
        if wanted:
            nets = [n for n in nets if n.get("id") in wanted]
        return nets

    return _cached("networks", load)


def _pick_networks(network: Optional[str]) -> list[dict]:
    """Networks matching ``network`` (an ID or a name, case-insensitive), or all in scope."""
    nets = _networks()
    if not network:
        if not nets:
            raise ToolError("No network is visible to this API key (check MERAKI_ORG_ID / MERAKI_NETWORK_IDS).")
        return nets
    key = network.strip().lower()
    hits = [n for n in nets if n.get("id", "").lower() == key or (n.get("name") or "").lower() == key]
    if not hits:
        names = ", ".join(n.get("name") or n.get("id") for n in nets)
        raise ToolError(f"No network named {network!r}. Networks: {names}")
    return hits


def _one_network(network: Optional[str]) -> dict:
    nets = _pick_networks(network)
    if len(nets) > 1:
        names = ", ".join(n.get("name") or n.get("id") for n in nets)
        raise ToolError(f"Several networks are in scope; pass network= one of: {names}")
    return nets[0]


def _device_names(org_id: str) -> tuple[dict[str, str], bool]:
    """(serial -> device name, capped). Unread devices fall back to their serial."""

    def load():
        devices, capped = _get_client().get_all(f"/organizations/{org_id}/devices", {"perPage": 1000}, max_pages=50)
        return {d["serial"]: d.get("name") or d["serial"] for d in devices if d.get("serial")}, capped

    return _cached(f"devices:{org_id}", load)


NAMES_CAPPED = "capped: the device inventory was not read to the end; some devices are shown by serial"


def _ssid_names(net: dict) -> dict[int, str]:
    """Enabled SSID number -> name for a wireless network."""
    if "wireless" not in (net.get("productTypes") or []):
        return {}

    def load():
        ssids = _get_client().get(f"/networks/{net['id']}/wireless/ssids") or []
        return {s["number"]: s.get("name") or f"SSID {s['number']}" for s in ssids if s.get("enabled")}

    return _cached(f"ssids:{net['id']}", load)


def _tz(net: dict) -> datetime.tzinfo:
    try:
        return ZoneInfo(net.get("timeZone") or "UTC")
    except ZoneInfoNotFoundError:
        return datetime.timezone.utc


def _local(ts: Any, tz: datetime.tzinfo) -> str:
    """Render an ISO-8601 timestamp or epoch seconds in the network's time zone."""
    if ts in (None, ""):
        return "?"
    try:
        if isinstance(ts, (int, float)):
            moment = datetime.datetime.fromtimestamp(ts, datetime.timezone.utc)
        else:
            moment = datetime.datetime.fromisoformat(str(ts).replace("Z", "+00:00"))
            if moment.tzinfo is None:
                moment = moment.replace(tzinfo=datetime.timezone.utc)
    except ValueError:
        return str(ts)
    return moment.astimezone(tz).strftime("%m-%d %H:%M")


def _now_label() -> str:
    return datetime.datetime.now().astimezone().strftime("%Y-%m-%d %H:%M %Z").strip()


def _bound(value: int, low: int, high: int) -> int:
    return max(low, min(int(value), high))


def _top(counter: collections.Counter, n: int) -> str:
    text = ", ".join(f"{k} {v:,}" for k, v in counter.most_common(n)) or "none"
    if len(counter) > n:
        text += f", +{len(counter) - n} more"
    return text


def _iso_ago(hours: int) -> str:
    moment = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(hours=hours)
    return moment.strftime("%Y-%m-%dT%H:%M:%SZ")


def _event_types(event_types: Optional[list[str]], default: tuple[str, ...] = SECURITY_EVENT_TYPES) -> list[str]:
    if not event_types:
        return list(default)
    bad = [t for t in event_types if not _EVENT_TYPE_RE.match(t)]
    if bad:
        raise ToolError(f"Invalid event type(s): {bad}")
    return list(event_types)


def _is_clat_conflict(ev: dict) -> bool:
    if ev.get("type") != "client_ip_conflict":
        return False
    try:
        return ipaddress.ip_address(str((ev.get("eventData") or {}).get("ip"))) in CLAT_PREFIX
    except ValueError:
        return False


def _split_clat(events: list[dict]) -> tuple[list[dict], int]:
    """Drop IP conflicts on the CLAT prefix; return (kept, dropped count)."""
    kept = [e for e in events if not _is_clat_conflict(e)]
    return kept, len(events) - len(kept)


def _read_events(net: dict, product_type: str, types: list[str], hours: int, per_page: int = 1000):
    """Events of ``types`` in the last ``hours`` (one page). Returns (events, capped)."""
    page = _get_client().page(
        f"/networks/{net['id']}/events",
        {
            "productType": product_type,
            "includedEventTypes[]": types,
            "startingAfter": _iso_ago(hours),
            "perPage": per_page,
        },
    )
    data = page.data or {}
    events = data.get("events") or []
    return events, len(events) >= per_page and "next" in page.links


def _collect_events(net: dict, types: list[str], hours: int) -> tuple[list[dict], list[str]]:
    """Events of ``types`` across the network's product types. Returns (events, capped product types)."""
    collected: list[dict] = []
    capped: list[str] = []
    for product in [p for p in EVENT_PRODUCT_TYPES if p in (net.get("productTypes") or [])]:
        events, more = _read_events(net, product, types, hours)
        collected.extend(events)
        if more:
            capped.append(product)
    return collected, capped


def _capped_note(capped: list[str]) -> str:
    return f" (capped: more {', '.join(capped)} events not read; shorten hours=)" if capped else ""


def _event_line(ev: dict, tz: datetime.tzinfo, ssids: dict[int, str]) -> str:
    parts = [_local(ev.get("occurredAt"), tz), ev.get("type") or "?"]
    if ev.get("deviceName") or ev.get("deviceSerial"):
        parts.append(f"device={ev.get('deviceName') or ev.get('deviceSerial')}")
    if ev.get("ssidNumber") is not None:
        parts.append(f"ssid={ssids.get(ev['ssidNumber'], ev['ssidNumber'])}")
    if ev.get("clientMac"):
        parts.append(f"client={ev['clientMac']}")
    data = ev.get("eventData")
    if data:
        parts.append("data=" + json.dumps(data, ensure_ascii=False, separators=(",", ":"))[:240])
    return "- " + " ".join(str(p) for p in parts)


# --------------------------------------------------------------------------
# health
# --------------------------------------------------------------------------


@mcp.tool()
def health_check() -> dict:
    """Report server version and Meraki Dashboard API reachability.

    Call at session start or after a timeout. Lightweight: lists the
    organizations and networks in scope and reads each organization's device
    status overview (one small request each).

    Always returns the same keys: ``status`` (healthy / degraded / error),
    ``service``, ``version``, ``base_url``, ``auth`` (ok / error /
    missing-env), ``organizations`` and ``networks`` (counts) and ``devices``
    (counts by status: online / alerting / offline / dormant, limited to
    MERAKI_NETWORK_IDS when set). A degraded or error result adds ``detail``.
    """
    result: dict = {
        "status": "healthy",
        "service": "merakiadm-mcp",
        "version": __version__,
        "base_url": os.environ.get("MERAKI_BASE_URL", "") or DEFAULT_BASE_URL,
        "auth": "unknown",
        "organizations": 0,
        "networks": 0,
        "devices": {},
    }
    try:
        orgs = _organizations()
        result["auth"] = "ok"
        result["organizations"] = len(orgs)
        result["networks"] = len(_networks())
        totals: collections.Counter = collections.Counter()
        scoped = bool(_env_list("MERAKI_NETWORK_IDS"))
        for org in orgs:
            params = {}
            if scoped:
                ids = [n["id"] for n in _networks() if n.get("organizationId") == org["id"]]
                if not ids:
                    continue
                params = {"networkIds[]": ids}
            overview = _get_client().get(f"/organizations/{org['id']}/devices/statuses/overview", params) or {}
            totals.update((overview.get("counts") or {}).get("byStatus") or {})
        result["devices"] = dict(totals)
        if totals.get("offline") or totals.get("alerting"):
            result["status"] = "degraded"
            result["detail"] = f"{totals.get('offline', 0)} offline, {totals.get('alerting', 0)} alerting device(s)"
    except MerakiClientError as exc:
        result.update(status="error", auth="missing-env", detail=str(exc))
    except MerakiAPIError as exc:
        result.update(status="error", auth="error" if exc.status in (401, 403) else "ok", detail=str(exc))
    except Exception as exc:  # noqa: BLE001 - health_check must always answer
        result.update(status="error", auth="error", detail=f"{type(exc).__name__}: {exc}")
    return result


# --------------------------------------------------------------------------
# connection failures
# --------------------------------------------------------------------------


def _connection_stats(net: dict, hours: int, offset_hours: int = 0) -> dict:
    """Connection counts per step for the last ``hours``, or for the ``hours`` ending ``offset_hours`` ago."""
    if not offset_hours:
        params: dict[str, Any] = {"timespan": hours * 3600}
    else:
        params = {"t0": _iso_ago(offset_hours + hours), "t1": _iso_ago(offset_hours)}
    return _get_client().get(f"/networks/{net['id']}/wireless/connectionStats", params) or {}


def _trend(net: dict, hours: int, now_stats: dict) -> str:
    """" (previous Nh: X% failed; biggest change: dhcp +N)" or "" when the window is too long to compare."""
    if hours * 2 > MAX_HOURS:
        return ""
    prev = _connection_stats(net, hours, offset_hours=hours)
    _, prev_pct = _success_line(prev)
    if not any(prev.get(k) for k in (*FAILURE_STEPS, "success")):
        return ""
    deltas = {step: int(now_stats.get(step) or 0) - int(prev.get(step) or 0) for step in FAILURE_STEPS}
    step, delta = max(deltas.items(), key=lambda kv: abs(kv[1]))
    change = f"; biggest change: {step} {delta:+,}" if delta else ""
    return f" (previous {hours}h: {prev_pct:.1f}% failed{change})"


def _failed_connections(net: dict, hours: int) -> list[dict]:
    return _get_client().get(f"/networks/{net['id']}/wireless/failedConnections", {"timespan": hours * 3600}) or []


def _success_line(stats: dict) -> tuple[str, float]:
    failed = sum(int(stats.get(s) or 0) for s in FAILURE_STEPS)
    ok = int(stats.get("success") or 0)
    total = ok + failed
    pct = failed / total * 100 if total else 0.0
    steps = ", ".join(f"{s} {int(stats.get(s) or 0):,}" for s in FAILURE_STEPS)
    return f"{ok:,} succeeded / {total:,} attempts, {pct:.1f}% failed ({steps})", pct


@mcp.tool()
def connection_failures(network: Optional[str] = None, hours: int = 24, top: int = 10) -> str:
    """Summarize wireless connection failures: which step, which SSID, which AP, when.

    Reads the failed-connection log server-side and returns only aggregates
    (a day at a busy site is thousands of rows): totals per step (assoc /
    auth / dhcp / dns) and per failure type, per SSID and VLAN, the ``top``
    access points by failures with their dominant step, the number of distinct
    clients, and failures per hour in the network's time zone.

    Args:
        network: Network name or ID; may be omitted when only one is in scope.
        hours: Look-back window, 1-168 (default 24).
        top: How many access points to list (1-50, default 10).
    """
    net = _one_network(network)
    hours = _bound(hours, 1, MAX_HOURS)
    top = _bound(top, 1, 50)
    tz = _tz(net)
    names, names_capped = _device_names(net["organizationId"])
    ssids = _ssid_names(net)
    stats = _connection_stats(net, hours)
    rows = _failed_connections(net, hours)
    summary, _ = _success_line(stats)

    lines = [f"# Connection failures — {net.get('name')} (last {hours}h)", f"- Overall: {summary}{_trend(net, hours, stats)}"]
    if not rows:
        lines.append("- No failed connections recorded in this window.")
        return "\n".join(lines)
    lines.append(f"- Failed attempts listed: {len(rows):,} from {len({r.get('clientMac') for r in rows}):,} distinct clients")
    lines.append(f"- By step: {_top(collections.Counter(r.get('failureStep') for r in rows), 10)}")
    lines.append(f"- By type: {_top(collections.Counter(r.get('type') for r in rows), 10)}")
    by_ssid = collections.Counter(ssids.get(r.get("ssidNumber"), str(r.get("ssidNumber"))) for r in rows)
    lines.append(f"- By SSID: {_top(by_ssid, 10)}")
    vlans = collections.Counter(str(r.get("vlan")) for r in rows if r.get("vlan") not in (None, -1))
    if vlans:
        lines.append(f"- By VLAN: {_top(vlans, 10)}")

    per_ap: dict[str, collections.Counter] = collections.defaultdict(collections.Counter)
    for r in rows:
        per_ap[names.get(r.get("serial"), r.get("serial") or "?")][r.get("failureStep")] += 1
    ranked = sorted(per_ap.items(), key=lambda kv: -sum(kv[1].values()))
    lines.append(f"\n## Top access points ({min(top, len(ranked))} of {len(ranked)})")
    if names_capped:
        lines.append(f"- {NAMES_CAPPED}")
    for name, steps in ranked[:top]:
        lines.append(f"- {name}: {sum(steps.values()):,} ({_top(steps, 4)})")
    if len(ranked) > top:
        lines.append(f"- capped: {len(ranked) - top} more access points not listed (raise top= to see more)")

    hourly = collections.Counter()
    for r in rows:
        stamp = _local(r.get("ts"), tz)
        hourly[stamp[-5:-3] if len(stamp) >= 5 else "?"] += 1
    lines.append("\n## Failures by hour (local time)")
    lines.append(", ".join(f"{h}h {hourly[h]:,}" for h in sorted(hourly)))
    return "\n".join(lines)


# --------------------------------------------------------------------------
# Air Marshal
# --------------------------------------------------------------------------


@mcp.tool()
def air_marshal(network: Optional[str] = None, hours: int = 1, top: int = 20) -> str:
    """Summarize Air Marshal: rogue SSIDs on your LAN and SSIDs that copy your names.

    Air Marshal lists every neighbouring SSID the access points hear — over a
    thousand an hour in a dense area — so this never returns the raw list.
    It reports the totals, every SSID whose traffic was also seen on your
    wired LAN (``wiredMacs``: a rogue access point plugged into your network),
    and the SSIDs broadcast by other radios under one of your own enabled SSID
    names (a possible evil twin, or simply a neighbour using a shared name
    such as eduroam), ranked by number of BSSIDs.

    Args:
        network: Network name or ID; may be omitted when only one is in scope.
        hours: Look-back window, 1-168 (default 1; a day can be several MB).
        top: How many SSIDs to list per section (1-100, default 20).
    """
    net = _one_network(network)
    hours = _bound(hours, 1, MAX_HOURS)
    top = _bound(top, 1, 100)
    tz = _tz(net)
    rows = _get_client().get(f"/networks/{net['id']}/wireless/airMarshal", {"timespan": hours * 3600}) or []
    own = {name.lower() for name in _ssid_names(net).values()}

    bssids = sum(len(r.get("bssids") or []) for r in rows)
    hidden = sum(1 for r in rows if not r.get("ssid"))
    wired = [r for r in rows if r.get("wiredMacs")]
    twins = [r for r in rows if (r.get("ssid") or "").lower() in own]
    lines = [
        f"# Air Marshal — {net.get('name')} (last {hours}h)",
        f"- Seen: {len(rows):,} SSIDs ({hidden:,} hidden), {bssids:,} BSSIDs",
        f"- On your wired LAN (rogue): {len(wired):,}",
        f"- Using one of your SSID names: {len(twins):,}",
    ]

    def render(entries: list[dict], title: str) -> None:
        entries = sorted(entries, key=lambda r: -len(r.get("bssids") or []))
        lines.append(f"\n## {title} ({min(top, len(entries))} of {len(entries)})")
        for r in entries[:top]:
            channels = sorted({c for b in (r.get("bssids") or []) for c in (b.get("channels") or [])} | set(r.get("channels") or []))
            detail = [
                f"bssids={len(r.get('bssids') or [])}",
                f"channels={','.join(str(c) for c in channels[:8])}" if channels else "",
                f"encryption={r.get('encryption')}" if r.get("encryption") else "",
                f"maker={','.join(r.get('manufacturers') or [])[:60]}" if r.get("manufacturers") else "",
                f"wiredVlans={r.get('wiredVlans')}" if r.get("wiredMacs") and r.get("wiredVlans") else "",
                f"wiredMacs={len(r.get('wiredMacs') or [])}" if r.get("wiredMacs") else "",
                f"last={_local(r.get('lastSeen'), tz)}",
            ]
            lines.append(f"- {r.get('ssid') or '(hidden)'}: " + " ".join(d for d in detail if d))
        if len(entries) > top:
            lines.append(f"- capped: {len(entries) - top} more not listed (raise top= or shorten hours=)")

    if wired:
        render(wired, "Seen on your wired LAN")
    if twins:
        render(twins, "Using one of your SSID names")
    return "\n".join(lines)


# --------------------------------------------------------------------------
# events
# --------------------------------------------------------------------------


def _newest(lines: list[str], events: list[dict], top: int, tz, ssids) -> None:
    newest = sorted(events, key=lambda e: e.get("occurredAt") or "", reverse=True)
    lines.append(f"\n## Newest {min(top, len(newest))} of {len(newest)}")
    lines.extend(_event_line(e, tz, ssids) for e in newest[:top])
    if len(newest) > top:
        lines.append(f"- capped: {len(newest) - top} more not shown (raise top= or shorten hours=)")


@mcp.tool()
def security_events(
    network: Optional[str] = None,
    hours: int = 24,
    top: int = 20,
    event_types: Optional[list[str]] = None,
) -> str:
    """List security-relevant network events: rogue DHCP, spoofed APs, address conflicts, RA guard, loops.

    By default reads these event types for every product type of the network:
    multiple_dhcp_servers_detected, rogue_dhcp, dhcp_snoop_blocked,
    dhcp_blocked, mac_spoofing_attack, rogue_ap_association,
    client_ip_conflict, client_ip6_conflict, client_ip6_lla_conflict,
    ra_blocked, loop_detected, stp_bpdu_guard, stp_root_guard, stp_loop_guard.
    Counts per type, then the newest ``top`` events with their device, SSID
    and event data (for a rogue DHCP server: its IP and MAC). IP conflicts on
    192.0.0.0/29 are left out and only counted: 464XLAT (CLAT) clients all
    use 192.0.0.2, so Meraki reports them as conflicts although they are not.

    Args:
        network: Network name or ID; may be omitted when only one is in scope.
        hours: Look-back window, 1-168 (default 24).
        top: How many events to show in detail (1-100, default 20).
        event_types: Override the event types to read (names from the
            Dashboard's event type list).
    """
    net = _one_network(network)
    hours = _bound(hours, 1, MAX_HOURS)
    top = _bound(top, 1, 100)
    collected, capped = _collect_events(net, _event_types(event_types), hours)
    collected, clat = _split_clat(collected)
    counts = collections.Counter(e.get("type") for e in collected)
    lines = [
        f"# Security events — {net.get('name')} (last {hours}h)",
        f"- Total: {len(collected):,}{_capped_note(capped)}",
        f"- By type: {_top(counts, 20)}",
    ]
    if clat:
        lines.append(f"- Not counted: {clat:,} client_ip_conflict on {CLAT_PREFIX} (464XLAT/CLAT clients share 192.0.0.2 by design)")
    if collected:
        _newest(lines, collected, top, _tz(net), _ssid_names(net))
    return "\n".join(lines)


@mcp.tool()
def operational_events(
    network: Optional[str] = None,
    hours: int = 24,
    top: int = 20,
    event_types: Optional[list[str]] = None,
) -> str:
    """List rare operational events: reboots, RADIUS/DHCP trouble, radar, attacks, switch faults, lost log entries.

    By default reads, for every product type of the network, these groups:
    reboot/firmware (boot, boot_ios_up, boot_ios_down, upgrade_transition),
    RADIUS (8021x_radius_timeout, radius_mab_timeout,
    radius_proxy_homeserver_dead / _zombie, radius_proxy_tls_fail),
    DHCP (dhcp_no_leases, dhcp_problem), radio (dfs_event and automatic
    channel changes, noise_avoid_begin), wireless attack (broadcast
    deauth/disassoc attacks, packet floods), switch hardware (power supply,
    temperature, memory, disk, stack cable, conn_state_change), switch config
    (apply/save failures), switch port (UDLD, err-disable, MAC flap, STP role
    and topology changes), roaming (L3 anchor failures) and event log
    (events_dropped2: the Dashboard dropped events, so the log is incomplete).
    Counts per group and type, then the newest ``top`` events in detail;
    events_dropped2 entries are counted but not listed.
    Use list_events for high-volume types (association, port status).

    Args:
        network: Network name or ID; may be omitted when only one is in scope.
        hours: Look-back window, 1-168 (default 24).
        top: How many events to show in detail (1-100, default 20).
        event_types: Override the event types to read.
    """
    net = _one_network(network)
    hours = _bound(hours, 1, MAX_HOURS)
    top = _bound(top, 1, 100)
    collected, capped = _collect_events(net, _event_types(event_types, OPERATIONAL_EVENT_TYPES), hours)
    counts = collections.Counter(e.get("type") for e in collected)
    groups: dict[str, collections.Counter] = collections.defaultdict(collections.Counter)
    for etype, n in counts.items():
        groups[_GROUP_OF.get(etype, "other")][etype] = n
    lines = [
        f"# Operational events — {net.get('name')} (last {hours}h)",
        f"- Total: {len(collected):,}{_capped_note(capped)}",
    ]
    for group in [*OPERATIONAL_EVENT_GROUPS, "other"]:
        if groups.get(group):
            lines.append(f"- {group}: {_top(groups[group], 10)}")
    if counts.get("events_dropped2"):
        lines.append("- Note: events_dropped2 means the Dashboard dropped events; every event count above is a lower bound.")
    collected = [e for e in collected if e.get("type") != "events_dropped2"]
    if collected:
        _newest(lines, collected, top, _tz(net), _ssid_names(net))
    return "\n".join(lines)


@mcp.tool()
def list_events(
    product_type: str,
    network: Optional[str] = None,
    event_types: Optional[list[str]] = None,
    per_page: int = 50,
    cursor: Optional[str] = None,
) -> str:
    """Page through a network's event log, newest page first.

    A busy wireless network logs tens of thousands of events a day, so read
    one page at a time and narrow with ``event_types`` where possible. The
    answer ends with ``older_cursor`` (pass it back as ``cursor`` for the
    previous page) and ``complete`` (true when no older page exists).

    Args:
        product_type: wireless, switch, appliance, camera, cellularGateway or sensor.
        network: Network name or ID; may be omitted when only one is in scope.
        event_types: Only these event types (names from the Dashboard's event type list).
        per_page: Events per page, 1-100 (default 50).
        cursor: ``older_cursor`` from a previous answer.
    """
    if product_type not in EVENT_PRODUCT_TYPES:
        raise ToolError(f"product_type must be one of {', '.join(EVENT_PRODUCT_TYPES)}")
    net = _one_network(network)
    per_page = _bound(per_page, 1, 100)
    params: dict[str, Any] = {"productType": product_type, "perPage": per_page}
    if event_types:
        params["includedEventTypes[]"] = _event_types(event_types)
    params.update(parse_cursor(cursor))
    page = _get_client().page(f"/networks/{net['id']}/events", params)
    data = page.data or {}
    events = data.get("events") or []
    tz = _tz(net)
    ssids = _ssid_names(net)
    older = page.cursor("prev")
    lines = [
        f"# Events — {net.get('name')} ({product_type}, {len(events)} shown, "
        f"{_local(data.get('pageStartAt'), tz)} to {_local(data.get('pageEndAt'), tz)})",
    ]
    lines.extend(_event_line(e, tz, ssids) for e in sorted(events, key=lambda e: e.get("occurredAt") or "", reverse=True))
    lines.append(f"\nolder_cursor: {older or '-'}")
    lines.append(f"complete: {'false' if older and events else 'true'}")
    return "\n".join(lines)


# --------------------------------------------------------------------------
# availability history
# --------------------------------------------------------------------------


def _status_of(change: dict, side: str) -> str:
    for item in (change.get("details") or {}).get(side) or []:
        if item.get("name") == "status":
            return str(item.get("value"))
    return "?"


def _outages(net: dict, hours: int) -> tuple[list[dict], int, bool]:
    """Per-device outages from the availability change history.

    Returns (rows sorted worst first, number of changes, capped). A row has
    name, product, downs (times the device left "online"), minutes down within
    the window, last change and whether it is still down.
    """
    changes, capped = _get_client().get_all(
        f"/organizations/{net['organizationId']}/devices/availabilities/changeHistory",
        {"networkIds[]": [net["id"]], "timespan": hours * 3600, "perPage": 1000},
        max_pages=5,
    )
    now = datetime.datetime.now(datetime.timezone.utc)
    start = now - datetime.timedelta(hours=hours)
    per: dict[str, dict] = {}
    for change in sorted(changes, key=lambda c: c.get("ts") or ""):
        device = change.get("device") or {}
        key = device.get("serial") or device.get("name") or "?"
        try:
            ts = datetime.datetime.fromisoformat(str(change.get("ts")).replace("Z", "+00:00"))
        except ValueError:
            continue
        old, new = _status_of(change, "old"), _status_of(change, "new")
        if key not in per:
            per[key] = {
                "name": device.get("name") or key,
                "product": device.get("productType") or "",
                "downs": 0,
                "seconds": 0.0,
                # Not online before its first change in the window: down since the window began.
                "down_since": start if old not in ("online", "?") else None,
                "from_start": old not in ("online", "?"),
                "last": None,
            }
        row = per[key]
        row["last"] = change.get("ts")
        if new == "online":
            if row["down_since"] is not None:
                row["seconds"] += (ts - max(row["down_since"], start)).total_seconds()
            row["down_since"] = None
        elif new != "?":
            if old == "online":
                row["downs"] += 1
            if row["down_since"] is None:
                row["down_since"] = ts
    rows = []
    for row in per.values():
        # With a capped history an earlier online->offline change may be unread, so the
        # state at the window start is a guess, not a fact.
        row["start_unknown"] = capped and row["from_start"]
        if row["down_since"] is not None:
            row["seconds"] += (now - max(row["down_since"], start)).total_seconds()
        if row["downs"] or row["seconds"] or row["from_start"]:
            rows.append({**row, "minutes": round(row["seconds"] / 60), "still_down": row["down_since"] is not None})
    rows.sort(key=lambda r: (-r["downs"], -r["minutes"]))
    return rows, len(changes), capped


def _outage_text(row: dict, tz) -> str:
    if row["start_unknown"]:
        notes = ["state at window start unknown: history capped"]
    else:
        notes = ["down at window start"] if row["from_start"] else []
    notes.append(f"last change {_local(row['last'], tz)}")
    if row["still_down"]:
        notes.append("still down")
    return f"{row['name']} {row['downs']}x {row['minutes']} min ({', '.join(notes)})"


@mcp.tool()
def availability_history(network: Optional[str] = None, hours: int = 24, top: int = 20) -> str:
    """Which devices went offline (or alerting / dormant) and came back, from the availability change history.

    For each device that was not online at some point in the window: how
    many times it left online, the minutes it spent not online within the
    window, whether it was already down when the window began, the time of
    its last change and whether it is still down. Answers "it drops out sometimes"
    questions that a point-in-time status cannot.

    Args:
        network: Network name or ID; may be omitted when only one is in scope.
        hours: Look-back window, 1-168 (default 24).
        top: How many devices to list (1-100, default 20).
    """
    net = _one_network(network)
    hours = _bound(hours, 1, MAX_HOURS)
    top = _bound(top, 1, 100)
    tz = _tz(net)
    rows, changes, capped = _outages(net, hours)
    lines = [
        f"# Availability history — {net.get('name')} (last {hours}h)",
        f"- Status changes: {changes:,}{' (capped: more changes not read; shorten hours=)' if capped else ''}",
        f"- Devices not online at some point: {len(rows):,} (left online during the window: {sum(1 for r in rows if r['downs']):,})",
    ]
    if rows:
        lines.append(f"\n## Devices ({min(top, len(rows))} of {len(rows)})")
        lines.extend(f"- {_outage_text(r, tz)} [{r['product']}]" for r in rows[:top])
        if len(rows) > top:
            lines.append(f"- capped: {len(rows) - top} more devices not listed (raise top=)")
    return "\n".join(lines)


# --------------------------------------------------------------------------
# switch uplinks
# --------------------------------------------------------------------------


def _switch_ports(org_id: str, net_ids: list[str], max_pages: int = 10):
    """Port statuses per switch for the networks. Returns (switches, capped)."""
    return _get_client().get_all(
        f"/organizations/{org_id}/switch/ports/statuses/bySwitch", {"networkIds[]": net_ids, "perPage": 20}, max_pages
    )


def _uplink_problems(switches: list[dict]) -> tuple[int, list[str]]:
    uplinks = 0
    problems = []
    for sw in switches:
        for port in sw.get("ports") or []:
            if not port.get("isUplink"):
                continue
            uplinks += 1
            if port.get("enabled", True) and port.get("status") != "Connected":
                problems.append(f"{sw.get('name') or sw.get('serial')} port {port.get('portId')} {port.get('status')}")
    return uplinks, problems


# --------------------------------------------------------------------------
# morning brief
# --------------------------------------------------------------------------


@mcp.tool()
def daily_brief(hours: int = 24, failure_threshold: float = 10.0, top: int = 5) -> str:
    """Morning health check of every network in scope.

    Per network, for the last ``hours``:
    - [DEVICES] current status counts, [DEVICES-DOWN] who is offline/alerting now
    - [AVAILABILITY] devices that went offline and came back (see availability_history)
    - [HEALTH] the network's current health alerts
    - [CONNECT] wireless success rate, failures per step, the previous
      window of the same length for comparison, and [CONNECT-TOP-AP] when
      failures exceed ``failure_threshold``
    - [SECURITY] security event counts (see security_events)
    - [OPERATIONS] rare operational events: reboots, RADIUS/DHCP trouble,
      radar, attacks, switch faults, dropped log entries (see operational_events)
    - [UPLINK] switch ports flagged as uplinks that are not connected

    At most 25 networks are checked per call; the rest are counted as capped.

    Output tiers:
    - CRITICAL — the API could not be read for that network
    - WARNING  — a device offline or alerting now or during the window,
                 connection failures above ``failure_threshold`` percent,
                 any security event, a warning-level operational event
                 (reboot, RADIUS timeout, DHCP pool exhausted, attack,
                 hardware or port fault), or an uplink down
    - OK       — none of the above

    Args:
        hours: Look-back window for connections and events, 1-168 (default 24).
        failure_threshold: Failed-connection percentage that raises a WARNING (default 10.0).
        top: How many names to list per item (1-20, default 5).
    """
    hours = _bound(hours, 1, MAX_HOURS)
    top = _bound(top, 1, 20)
    header = f"## daily_brief — {_now_label()} (last {hours}h)"
    try:
        nets = _pick_networks(None)
    except Exception as exc:  # noqa: BLE001 - the brief reports, it does not raise
        return f"{header}\n## CRITICAL — API error: {exc}"
    skipped = nets[MAX_BRIEF_NETWORKS:]
    nets = nets[:MAX_BRIEF_NETWORKS]

    sections: list[tuple[str, list[str]]] = []
    for net in nets:
        tier, body = "OK", []
        org_id = net["organizationId"]
        products = net.get("productTypes") or []
        try:
            avail, avail_capped = _get_client().get_all(
                f"/organizations/{org_id}/devices/availabilities", {"networkIds[]": [net["id"]], "perPage": 1000}
            )
            status = collections.Counter(d.get("status") for d in avail)
            body.append(
                "- [DEVICES] "
                + ", ".join(f"{s} {status.get(s, 0)}" for s in ("online", "alerting", "offline", "dormant"))
                + (" (capped: more devices not read)" if avail_capped else "")
            )
            down = [d for d in avail if d.get("status") in ("offline", "alerting")]
            if down:
                tier = "WARNING"
                listed = ", ".join(f"{d.get('name') or d.get('serial')} ({d.get('status')})" for d in down[:top])
                more = f" … capped: {len(down) - top} more" if len(down) > top else ""
                body.append(f"- [DEVICES-DOWN] {listed}{more}")

            outages, changes, outage_capped = _outages(net, hours)
            if outages:
                tier = "WARNING"
                body.append(
                    f"- [AVAILABILITY] {len(outages)} device(s) not online at some point: "
                    + "; ".join(_outage_text(r, _tz(net)) for r in outages[:top])
                    + (f" … capped: {len(outages) - top} more" if len(outages) > top else "")
                    + (" (capped: more changes not read)" if outage_capped else "")
                )
            elif outage_capped:
                body.append(f"- [AVAILABILITY] every device stayed online in the {changes} status changes read (capped: more changes not read)")
            else:
                body.append(f"- [AVAILABILITY] every device stayed online ({changes} status changes)")

            alerts = _get_client().get(f"/networks/{net['id']}/health/alerts") or []
            if alerts:
                body.append(
                    f"- [HEALTH] {len(alerts)} alert(s): "
                    + "; ".join(f"{a.get('category')}: {a.get('type')} ({a.get('severity')})" for a in alerts[:top])
                    + (f" … capped: {len(alerts) - top} more" if len(alerts) > top else "")
                )

            if "wireless" in products:
                stats = _connection_stats(net, hours)
                summary, pct = _success_line(stats)
                flag = pct > failure_threshold
                tier = "WARNING" if flag else tier
                body.append(f"- [CONNECT{'-HIGH-FAILURE' if flag else ''}] {summary}{_trend(net, hours, stats)}")
                if flag:
                    names, names_capped = _device_names(org_id)
                    per_ap = collections.Counter(names.get(r.get("serial"), r.get("serial")) for r in _failed_connections(net, hours))
                    body.append(f"- [CONNECT-TOP-AP] {_top(per_ap, top)}{' (' + NAMES_CAPPED + ')' if names_capped else ''}")

            events, capped = _collect_events(net, list(SECURITY_EVENT_TYPES), hours)
            counts = collections.Counter(e.get("type") for e in _split_clat(events)[0])
            if counts:
                tier = "WARNING"
                body.append(f"- [SECURITY] {_top(counts, 20)}{_capped_note(capped)} — see security_events")
            else:
                body.append(f"- [SECURITY] none{_capped_note(capped)}")

            events, capped = _collect_events(net, list(OPERATIONAL_EVENT_TYPES), hours)
            ops = collections.Counter(e.get("type") for e in events)
            warn = collections.Counter({t: n for t, n in ops.items() if t in OPERATIONAL_WARN_TYPES})
            info = collections.Counter({t: n for t, n in ops.items() if t not in OPERATIONAL_WARN_TYPES})
            if warn:
                tier = "WARNING"
                body.append(f"- [OPERATIONS-WARN] {_top(warn, 20)}{_capped_note(capped)} — see operational_events")
            if info or not warn:
                dropped = " (events_dropped2: the Dashboard dropped events, counts are lower bounds)" if ops.get("events_dropped2") else ""
                body.append(f"- [OPERATIONS] {_top(info, 20)}{'' if warn else _capped_note(capped)}{dropped}")

            if "switch" in products:
                switches, more = _switch_ports(org_id, [net["id"]])
                uplinks, problems = _uplink_problems(switches)
                if problems:
                    tier = "WARNING"
                    body.append(
                        f"- [UPLINK-DOWN] {'; '.join(problems[:top])}"
                        + (f" … capped: {len(problems) - top} more" if len(problems) > top else "")
                        + (" (capped: more switches not read)" if more else "")
                    )
                elif uplinks:
                    body.append(f"- [UPLINK] {len(switches)} switches, {uplinks} uplink ports, none down{' (capped)' if more else ''}")
                else:
                    body.append(f"- [UPLINK] {len(switches)} switches, no port is flagged as an uplink (not checked){' (capped)' if more else ''}")
        except Exception as exc:  # noqa: BLE001
            tier = "CRITICAL"
            body.append(f"- [API-ERROR] {exc}")
        sections.append((tier, [f"#### {net.get('name')} — {tier}", *body]))

    tiers = collections.Counter(t for t, _ in sections)
    lines = [
        header,
        f"## {len(sections)} networks: {tiers.get('OK', 0)} OK, {tiers.get('WARNING', 0)} WARNING, {tiers.get('CRITICAL', 0)} CRITICAL",
        "",
    ]
    order = {"CRITICAL": 0, "WARNING": 1, "OK": 2}
    for _, body in sorted(sections, key=lambda s: order[s[0]]):
        lines.extend(body)
        lines.append("")
    if skipped:
        lines.append(
            f"capped: {len(skipped)} more networks not checked (at most {MAX_BRIEF_NETWORKS} per brief; "
            "set MERAKI_NETWORK_IDS or call the per-network tools)"
        )
    return "\n".join(lines).rstrip()


if __name__ == "__main__":
    mcp.run(transport="stdio")
