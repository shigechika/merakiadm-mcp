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
import difflib
import functools
import hashlib
import inspect
import ipaddress
import json
import os
import pathlib
import re
import time
from typing import Any, Optional
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

import httpx
from mcp.server.mcpserver import MCPServer
from mcp.server.mcpserver.exceptions import ToolError
from mcp.shared.exceptions import MCPError
from mcp.types import ToolAnnotations

from merakiadm_mcp import __version__
from merakiadm_mcp.client import (
    CURSOR_PARAMS,
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
#: Packets an access point must carry before its loss percentage is ranked.
MIN_LOSS_PACKETS = 1000
#: Latency samples an access point must have before its average is ranked.
MIN_LATENCY_SAMPLES = 100
MAX_HOURS = 168  # the failed-connection and connection-stats endpoints look back at most 7 days
CACHE_SECONDS = 300
MAX_BRIEF_NETWORKS = 25  # each network costs about ten requests and a section of output
BRIEF_TIME_BUDGET = 40.0  # seconds; networks not started by then are reported as capped
BRIEF_STEP_LIMIT = 50.0  # seconds; a network still running then stops between steps


class _BriefTimeUp(Exception):
    """daily_brief ran past BRIEF_STEP_LIMIT inside a network."""
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


def _cached(key: str, loader, ttl: float = CACHE_SECONDS):
    hit = _cache.get(key)
    now = time.monotonic()
    if hit and now - hit[0] < ttl:
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


def _devices(org_id: str) -> tuple[list[dict], bool]:
    """(device inventory of the organization, capped)."""

    def load():
        return _get_client().get_all(f"/organizations/{org_id}/devices", {"perPage": 1000}, max_pages=50)

    return _cached(f"devices:{org_id}", load)


def _device_names(org_id: str) -> tuple[dict[str, str], bool]:
    """(serial -> device name, capped). Unread devices fall back to their serial."""
    devices, capped = _devices(org_id)
    return {d["serial"]: d.get("name") or d["serial"] for d in devices if d.get("serial")}, capped


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


def _known_event_types(net: dict) -> set[str]:
    """Event type names the Dashboard lists for the network (empty when it cannot be read)."""

    def load() -> set[str]:
        try:
            listed = _get_client().get(f"/networks/{net['id']}/events/eventTypes") or []
        except Exception:  # noqa: BLE001 - only used for a hint
            return set()
        return {e["type"] for e in listed if isinstance(e, dict) and e.get("type")}

    return _cached(f"eventtypes:{net['id']}", load)


def _unknown_types_note(net: dict, event_types: Optional[list[str]], events: list[dict]) -> Optional[str]:
    """A line naming requested types that matched nothing and that the Dashboard does not list.

    Not a refusal: the list misses some types that do occur, and the API
    silently matches nothing for a misspelt one.
    """
    seen = {e.get("type") for e in events}
    asked = [t for t in event_types or [] if t not in seen]
    known = _known_event_types(net) if asked else set()
    unknown = [t for t in asked if known and t not in known]
    if not unknown:
        return None
    hints = []
    for name in unknown:
        close = difflib.get_close_matches(name, known, n=2)
        hints.append(name + (f" (did you mean {', '.join(close)}?)" if close else ""))
    return "- Not in this network's event type list, may match nothing: " + "; ".join(hints)


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


def _parse_ts(value: Any) -> Optional[datetime.datetime]:
    """An ISO 8601 time, or the co-term license form "Feb 8, 2020 UTC"; None otherwise."""
    try:
        moment = datetime.datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        try:
            moment = datetime.datetime.strptime(str(value).strip().removesuffix(" UTC"), "%b %d, %Y")
        except ValueError:
            return None
    return moment if moment.tzinfo else moment.replace(tzinfo=datetime.timezone.utc)


def _read_events(net: dict, product_type: str, types: list[str], hours: int, per_page: int = 1000):
    """The newest page of ``types``, kept to the last ``hours``. Returns (events, capped).

    Without a start the endpoint answers newest first, so when the page is full
    the events left unread are the oldest of the window, not the newest
    (``startingAfter`` would answer oldest first and lose the newest instead).
    A page that is not full reaches back a month (``pageStartAt``); the read
    is capped when an older page exists and this one starts inside the window.
    """
    page = _get_client().page(
        f"/networks/{net['id']}/events",
        {"productType": product_type, "includedEventTypes[]": types, "perPage": per_page},
    )
    data = page.data or {}
    events = data.get("events") or []
    start = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(hours=hours)
    kept = [e for e in events if (_parse_ts(e.get("occurredAt")) or start) >= start]
    page_start = _parse_ts(data.get("pageStartAt"))
    if page_start is None:
        capped = len(events) >= per_page and len(kept) == len(events)
    else:
        capped = page_start > start
    return kept, capped and "prev" in page.links


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
    return f" (capped: older {', '.join(capped)} events in the window not read; shorten hours=)" if capped else ""


def _type_summary(events: list[dict], n: int = 20) -> str:
    """'type N (c clients, d devices)' per type, most frequent first."""
    by_type: dict[str, list[dict]] = collections.defaultdict(list)
    for e in events:
        by_type[e.get("type") or "?"].append(e)
    ranked = sorted(by_type.items(), key=lambda kv: -len(kv[1]))
    parts = []
    for etype, rows in ranked[:n]:
        clients = len({e.get("clientMac") for e in rows if e.get("clientMac")})
        devices = len({e.get("deviceSerial") or e.get("deviceName") for e in rows if e.get("deviceSerial") or e.get("deviceName")})
        who = ", ".join(x for x in (f"{clients} clients" if clients else "", f"{devices} devices" if devices else "") if x)
        parts.append(f"{etype} {len(rows):,}" + (f" ({who})" if who else ""))
    if len(ranked) > n:
        parts.append(f"+{len(ranked) - n} more")
    return ", ".join(parts) or "none"


def _dropped_summary(events: list[dict]) -> str:
    """What the access points dropped, from events_dropped2 entries (eventData n and type)."""
    dropped: collections.Counter = collections.Counter()
    for e in events:
        if e.get("type") != "events_dropped2":
            continue
        data = e.get("eventData") or {}
        kind = str(data.get("type") or "unspecified type")
        try:
            count = int(data.get("n", 1))
        except (TypeError, ValueError):
            count = 1
        if count > 0:
            dropped[kind] += count
    return _top(dropped, 8) if dropped else ""


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
    missing-env), ``organizations`` and ``networks`` (counts), when the key
    works ``organization_list`` and ``network_list`` (IDs and names, at most 20
    and 50, for api_get paths) and ``devices``
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
        nets = _networks()
        result["networks"] = len(nets)
        result["organization_list"] = [{"id": str(o.get("id")), "name": o.get("name")} for o in orgs[:20]]
        result["network_list"] = [
            {"id": n.get("id"), "name": n.get("name"), "products": n.get("productTypes") or []} for n in nets[:50]
        ]
        if len(nets) > 50:
            result["network_list_capped"] = f"{len(nets) - 50} more networks not listed"
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
    auth / dhcp / dns) from the connection stats, then from the separate
    failed-connection log: per failure type, per SSID and VLAN, the ``top``
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

    lines = [
        f"# Connection failures — {net.get('name')} (last {hours}h)",
        f"- Overall (connection stats): {summary}{_trend(net, hours, stats)}",
    ]
    if not rows:
        lines.append("- No failed connections recorded in this window.")
        return "\n".join(lines)
    lines.append(
        f"- Failed-connection log: {len(rows):,} entries from {len({r.get('clientMac') for r in rows}):,} distinct clients"
        " (a separate source: its count can differ a little from the overall line; the breakdowns below come from it)"
    )
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


def _fold_repeats(event_lines: list[str]) -> list[tuple[str, str, str, int]]:
    """Group consecutive lines that differ only in time: (newest time, oldest time, rest, count)."""
    groups: list[list] = []
    for line in event_lines:
        date, clock, rest = (line[2:].split(" ", 2) + ["", ""])[:3]
        if groups and groups[-1][2] == rest:
            groups[-1][1] = f"{date} {clock}"
            groups[-1][3] += 1
        else:
            groups.append([f"{date} {clock}", f"{date} {clock}", rest, 1])
    return [tuple(g) for g in groups]


def _newest(lines: list[str], events: list[dict], top: int, tz, ssids) -> None:
    """The newest events, ``top`` lines at most, with identical neighbours folded into one line."""
    newest = sorted(events, key=lambda e: e.get("occurredAt") or "", reverse=True)
    groups = _fold_repeats([_event_line(e, tz, ssids) for e in newest])[:top]
    shown = sum(g[3] for g in groups)
    lines.append(f"\n## Newest {shown} of {len(newest)}")
    for first, last, rest, count in groups:
        when = first if first == last else f"{first} back to {last}"
        lines.append(f"- {when} {rest}" + (f" (x{count})" if count > 1 else ""))
    if len(newest) > shown:
        lines.append(f"- capped: {len(newest) - shown} more not shown (raise top= or shorten hours=)")


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
    lines = [
        f"# Security events — {net.get('name')} (last {hours}h)",
        f"- Total: {len(collected):,}{_capped_note(capped)}",
        f"- By type: {_type_summary(collected)}",
    ]
    if note := _unknown_types_note(net, event_types, collected):
        lines.append(note)
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
    (events_dropped2: an access point dropped ``n`` events of a high-volume
    type such as association, so the log is incomplete for that type).
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
    if note := _unknown_types_note(net, event_types, collected):
        lines.append(note)
    for group in [*OPERATIONAL_EVENT_GROUPS, "other"]:
        if groups.get(group):
            lines.append(f"- {group}: {_top(groups[group], 10)}")
    dropped = _dropped_summary(collected)
    if dropped:
        lines.append(
            f"- Dropped by the access points (events_dropped2, events per type): {dropped}. "
            "These are high-volume types; the log is incomplete for them."
        )
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
    previous page) and ``complete``. The endpoint offers an older page even
    past the oldest event, a month at a time, so an empty page counts as the
    end; pass ``older_cursor`` anyway to look further back.

    Args:
        product_type: wireless, switch, appliance, camera, cellularGateway or sensor.
        network: Network name or ID; may be omitted when only one is in scope.
        event_types: Only these event types (names from the Dashboard's event type list).
        per_page: Events per page, 3-100 (default 50).
        cursor: ``older_cursor`` from a previous answer.
    """
    if product_type not in EVENT_PRODUCT_TYPES:
        raise ToolError(f"product_type must be one of {', '.join(EVENT_PRODUCT_TYPES)}")
    net = _one_network(network)
    per_page = _bound(per_page, 3, 100)  # the events endpoint refuses perPage below 3
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
    if note := _unknown_types_note(net, event_types, events):
        lines.append(note)
    lines.extend(_event_line(e, tz, ssids) for e in sorted(events, key=lambda e: e.get("occurredAt") or "", reverse=True))
    lines.append(f"\nolder_cursor: {older or '-'}")
    if older and not events:
        lines.append("no events on this page; treated as the end of the log")
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
    stamped = [(ts, c) for c in changes if (ts := _parse_ts(c.get("ts"))) is not None]
    stamped.sort(key=lambda pair: pair[0])
    # A capped history lost its oldest changes: count down time only from the oldest one read.
    floor = max(stamped[0][0], start) if capped and stamped else start
    per: dict[str, dict] = {}
    for ts, change in stamped:
        device = change.get("device") or {}
        key = device.get("serial") or device.get("name") or "?"
        old, new = _status_of(change, "old"), _status_of(change, "new")
        if key not in per:
            per[key] = {
                "name": device.get("name") or key,
                "product": device.get("productType") or "",
                "downs": 0,
                "seconds": 0.0,
                # Not online before its first change read: down since the window (or the read) began.
                "down_since": floor if old not in ("online", "?") else None,
                "from_start": old not in ("online", "?"),
                "last": None,
            }
        row = per[key]
        row["last"] = change.get("ts")
        if new == "online":
            if row["down_since"] is not None:
                row["seconds"] += (ts - max(row["down_since"], floor)).total_seconds()
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
            row["seconds"] += (now - max(row["down_since"], floor)).total_seconds()
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
    minutes = f"at least {row['minutes']}" if row["start_unknown"] else str(row["minutes"])
    return f"{row['name']} {row['downs']}x {minutes} min ({', '.join(notes)})"


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
# wireless quality
# --------------------------------------------------------------------------


def _require_wireless(net: dict) -> None:
    if "wireless" not in (net.get("productTypes") or []):
        raise ToolError(f"{net.get('name')} has no wireless devices")


def _packet_loss(net: dict, hours: int) -> tuple[list[dict], bool]:
    """Per access point packet loss, upstream (client to AP) and downstream."""
    return _get_client().get_all(
        f"/organizations/{net['organizationId']}/wireless/devices/packetLoss/byDevice",
        {"networkIds[]": [net["id"]], "timespan": hours * 3600, "perPage": 1000},
        10,
    )


def _channel_use(net: dict, hours: int) -> tuple[list[dict], bool]:
    """Per access point channel utilization per band, averaged over the window."""
    return _get_client().get_all(
        f"/organizations/{net['organizationId']}/wireless/devices/channelUtilization/byDevice",
        {"networkIds[]": [net["id"]], "timespan": hours * 3600, "interval": 3600, "perPage": 100},
        20,
    )


def _pct(part: int, total: int) -> str:
    """Percentage to one decimal; "<0.1%" rather than a misleading 0.0% when anything was lost."""
    if not total:
        return "n/a"
    value = part / total * 100
    return "<0.1%" if part and value < 0.05 else f"{value:.1f}%"


def _loss_ranking(rows: list[dict], side: str, min_packets: int) -> list[tuple[str, dict]]:
    """Access points with loss on ``side``, worst first, ignoring those under ``min_packets``."""
    ranked = []
    for r in rows:
        d = r.get(side) or {}
        total, lost = int(d.get("total") or 0), int(d.get("lost") or 0)
        if total >= min_packets and lost:
            ranked.append(((r.get("device") or {}).get("name") or (r.get("device") or {}).get("serial") or "?", d))
    ranked.sort(key=lambda kv: -int(kv[1].get("lost") or 0) / int(kv[1].get("total") or 1))
    return ranked


def _loss_totals(rows: list[dict]) -> str:
    sums = {}
    for side in ("upstream", "downstream"):
        total = sum(int((r.get(side) or {}).get("total") or 0) for r in rows)
        lost = sum(int((r.get(side) or {}).get("lost") or 0) for r in rows)
        sums[side] = f"{_pct(lost, total)} of {total:,}"
    return f"client to AP (upstream) {sums['upstream']}, AP to client (downstream) {sums['downstream']}"


def _idle(rows: list[dict]) -> list[str]:
    """Access points that carried no packets at all in the window."""
    return sorted(
        (r.get("device") or {}).get("name") or (r.get("device") or {}).get("serial") or "?"
        for r in rows
        if not int((r.get("upstream") or {}).get("total") or 0) and not int((r.get("downstream") or {}).get("total") or 0)
    )


def _band_rows(rows: list[dict], names: dict[str, str]) -> list[tuple[str, str, dict]]:
    """(access point, band, {wifi, nonWifi, total}) for every band reported."""
    out = []
    for r in rows:
        name = names.get(r.get("serial"), r.get("serial") or "?")
        for b in r.get("byBand") or []:
            out.append((name, str(b.get("band")), {k: float((b.get(k) or {}).get("percentage") or 0) for k in ("wifi", "nonWifi", "total")}))
    return out


def _band_label(band: str) -> str:
    return f"{band} GHz"


@mcp.tool()
def wireless_quality(network: Optional[str] = None, hours: int = 24, top: int = 10, min_packets: int = MIN_LOSS_PACKETS) -> str:
    """Summarize wireless quality per access point: packet loss, channel use, latency.

    For "the Wi-Fi is slow or drops" questions. Over the window it reports
    packet loss for the whole network and the ``top`` access points by loss in
    each direction (upstream is client to AP, downstream is AP to client;
    access points that carried fewer than ``min_packets`` packets are not
    ranked, as a handful of packets gives a meaningless percentage), access
    points that carried no traffic at all, channel utilization averaged over
    the window per band (Wi-Fi and non-Wi-Fi interference), and the access
    points with the highest average best-effort latency.

    Args:
        network: Network name or ID; may be omitted when only one is in scope.
        hours: Look-back window, 1-168 (default 24).
        top: How many access points to list per section (1-50, default 10).
        min_packets: Packets an access point must carry to be ranked by loss (1-1000000, default 1000).
    """
    net = _one_network(network)
    _require_wireless(net)
    hours = _bound(hours, 1, MAX_HOURS)
    top = _bound(top, 1, 50)
    min_packets = _bound(min_packets, 1, 1_000_000)
    names, names_capped = _device_names(net["organizationId"])
    lines = [f"# Wireless quality — {net.get('name')} (last {hours}h)"]
    if names_capped:
        lines.append(f"- {NAMES_CAPPED}")

    loss, loss_capped = _packet_loss(net, hours)
    lines.append(f"- Packet loss, whole network: {_loss_totals(loss)}{' (capped: more access points not read)' if loss_capped else ''}")
    idle = _idle(loss)
    lines.append(
        f"- Access points reported: {len(loss)}; carried no traffic: {len(idle)}"
        + (f" ({', '.join(idle[:top])}{f' … capped: {len(idle) - top} more' if len(idle) > top else ''})" if idle else "")
    )
    for side, title in (("upstream", "Upstream loss (client to AP)"), ("downstream", "Downstream loss (AP to client)")):
        ranked = _loss_ranking(loss, side, min_packets)
        lines.append(f"\n## {title}, worst {min(top, len(ranked))} of {len(ranked)} with any loss and at least {min_packets:,} packets")
        for name, d in ranked[:top]:
            lost, total = int(d.get("lost") or 0), int(d.get("total") or 0)
            lines.append(f"- {name}: {_pct(lost, total)} ({lost:,} of {total:,})")
        if len(ranked) > top:
            lines.append(f"- capped: {len(ranked) - top} more access points not listed (raise top=)")

    use, use_capped = _channel_use(net, hours)
    bands = _band_rows(use, names)
    lines.append(f"\n## Channel utilization, average over the window{' (capped: more access points not read)' if use_capped else ''}")
    for band in sorted({b for _, b, _ in bands}, key=lambda b: float(b) if b.replace('.', '', 1).isdigit() else 99):
        vals = [v for _, b, v in bands if b == band]
        avg = sum(v["total"] for v in vals) / len(vals)
        lines.append(f"- {_band_label(band)}: {len(vals)} radios, average {avg:.1f}%, highest {max(v['total'] for v in vals):.1f}%")
    busiest = sorted(bands, key=lambda x: -x[2]["total"])
    for name, band, v in busiest[:top]:
        lines.append(f"- {name} {_band_label(band)}: {v['total']:.1f}% (Wi-Fi {v['wifi']:.1f}%, non-Wi-Fi {v['nonWifi']:.1f}%)")
    if len(busiest) > top:
        lines.append(f"- capped: {len(busiest) - top} more radios not listed (raise top=)")
    if bands:
        name, band, v = max(bands, key=lambda x: x[2]["nonWifi"])
        lines.append(f"- Most non-Wi-Fi interference: {name} {_band_label(band)} {v['nonWifi']:.1f}%")

    latency = _get_client().get(f"/networks/{net['id']}/wireless/devices/latencyStats", {"timespan": hours * 3600}) or []
    slow = []
    for r in latency:
        be = (r.get("latencyStats") or {}).get("bestEffortTraffic") or {}
        samples = sum(int(n or 0) for n in (be.get("rawDistribution") or {}).values())
        if samples >= MIN_LATENCY_SAMPLES and be.get("avg") is not None:
            slow.append((names.get(r.get("serial"), r.get("serial") or "?"), float(be["avg"]), samples))
    slow.sort(key=lambda x: -x[1])
    lines.append(f"\n## Best-effort latency, highest average {min(top, len(slow))} of {len(slow)} with at least {MIN_LATENCY_SAMPLES} samples")
    lines.extend(f"- {name}: {avg:.1f} ms ({samples:,} samples)" for name, avg, samples in slow[:top])
    if len(slow) > top:
        lines.append(f"- capped: {len(slow) - top} more access points not listed (raise top=)")
    return "\n".join(lines)


# --------------------------------------------------------------------------
# names to IDs, and clients
# --------------------------------------------------------------------------

_MAC_RE = re.compile(r"^[0-9a-f]{2}([:-]?)[0-9a-f]{2}(\1[0-9a-f]{2}){4}$|^[0-9a-f]{4}\.[0-9a-f]{4}\.[0-9a-f]{4}$", re.I)
CLIENT_SCAN_PAGES = 5


def _norm_mac(text: str) -> str:
    raw = re.sub(r"[^0-9a-f]", "", text.lower())
    return ":".join(raw[i : i + 2] for i in range(0, 12, 2))


@mcp.tool()
def resolve_entity(query: str, top: int = 10) -> str:
    """Turn a name, ID, serial, MAC or IP into the Meraki IDs other tools and api_get need.

    Matches (case-insensitive, whole or part) organizations by ID and name,
    networks by ID and name, and devices (access points, switches...) by
    serial, name, MAC and LAN IP, from the inventory in scope. A client
    (a laptop or phone) is not a device here: use find_client for those.

    Args:
        query: A name or part of one, an ID, a serial, a MAC or an IP address.
        top: How many matches to list per kind (1-50, default 10).
    """
    top = _bound(top, 1, 50)
    q = (query or "").strip().lower()
    if not q:
        raise ToolError("query is empty")
    mac = _norm_mac(q) if _MAC_RE.match(q) else None
    orgs = [o for o in _organizations() if q in str(o.get("id")).lower() or q in (o.get("name") or "").lower()]
    nets_all = _networks()
    net_names = {n["id"]: n.get("name") or n["id"] for n in nets_all}
    nets = [n for n in nets_all if q in n["id"].lower() or q in (n.get("name") or "").lower()]
    devices, capped = [], False
    for org in _organizations():
        inv, more = _devices(str(org["id"]))
        capped = capped or more
        for d in inv:
            if d.get("networkId") not in net_names:
                continue
            fields = [d.get("serial"), d.get("name"), d.get("lanIp"), d.get("mac")]
            if (mac and (d.get("mac") or "").lower() == mac) or any(q in str(f).lower() for f in fields if f):
                devices.append(d)
    lines = [f"# Matches for {query!r}"]
    for title, rows, render in (
        ("Organizations", orgs, lambda o: f"- {o.get('name')}: organizationId {o.get('id')}"),
        ("Networks", nets, lambda n: f"- {n.get('name')}: networkId {n['id']} ({', '.join(n.get('productTypes') or [])})"),
        (
            "Devices",
            devices,
            lambda d: f"- {d.get('name') or d.get('serial')}: serial {d.get('serial')}, {d.get('model')}, MAC {d.get('mac')}, "
            f"LAN IP {d.get('lanIp') or '-'}, network {net_names.get(d.get('networkId'))} ({d.get('networkId')})",
        ),
    ):
        if rows:
            lines.append(f"\n## {title} ({min(top, len(rows))} of {len(rows)})")
            lines.extend(render(r) for r in rows[:top])
            if len(rows) > top:
                lines.append(f"- capped: {len(rows) - top} more not listed (be more specific or raise top=)")
    if capped:
        lines.append(f"- {NAMES_CAPPED}")
    if len(lines) == 1:
        lines.append("- Nothing in scope matched." + (" A client (laptop, phone) is looked up with find_client." if mac or _is_ip(q) else ""))
    return "\n".join(lines)


def _is_ip(text: str) -> bool:
    try:
        ipaddress.ip_address(text)
        return True
    except ValueError:
        return False


def _client_matches(net: dict, query: str, hours: int) -> tuple[list[dict], str, bool]:
    """Clients of a network matching ``query``: (clients, how they were looked up, capped)."""
    q = query.strip()
    if _MAC_RE.match(q):
        mac = _norm_mac(q)
        found = _get_client().get(f"/organizations/{net['organizationId']}/clients/search", {"mac": mac}) or {}
        cid = found.get("clientId")
        rows = [r for r in found.get("records") or [] if (r.get("network") or {}).get("id") == net["id"]]
        return ([{**r, "id": cid, "mac": found.get("mac") or mac, "manufacturer": found.get("manufacturer")} for r in rows][:1], "MAC", False)
    if _is_ip(q):
        key = "ip" if ipaddress.ip_address(q).version == 4 else "ip6"
        rows, capped = _get_client().get_all(
            f"/networks/{net['id']}/clients", {key: q, "timespan": hours * 3600, "perPage": 1000}, CLIENT_SCAN_PAGES
        )
        wanted = ipaddress.ip_address(q)
        exact = []
        for r in rows:  # the API matches a prefix: 10.0.0.9 also returns 10.0.0.95
            try:
                if r.get(key) and ipaddress.ip_address(r[key]) == wanted:
                    exact.append(r)
            except ValueError:
                continue
        return exact, f"IP over the last {hours}h", capped and not exact
    needle = q.lower()
    rows, capped = _get_client().get_all(
        f"/networks/{net['id']}/clients", {"timespan": hours * 3600, "perPage": 1000}, CLIENT_SCAN_PAGES
    )
    hits = [r for r in rows if any(needle in str(r.get(k) or "").lower() for k in ("user", "description", "notes"))]
    return hits, f"user / description among {len(rows):,} clients of the last {hours}h", capped


@mcp.tool()
def find_client(query: str, network: Optional[str] = None, hours: int = 1, top: int = 5) -> str:
    """Find a client (laptop, phone...) and show where it connects and how it fares.

    ``query`` is a MAC address, an IP address (IPv4 or IPv6), or part of a
    user name or device description. A MAC is looked up directly; an IP or a
    name searches the clients seen in the last ``hours`` (an IP over a day
    takes about 25 seconds at a busy site; a name scans at most 5,000
    clients and says capped when there were more). For the best match it
    shows the client record (IP, VLAN, SSID, user, OS, last access point or
    switch port) and, for wireless clients over the last ``hours``, its
    connection stats per step, connectivity events by type and access point
    with signal strength, the latest problems, and latency.

    Args:
        query: MAC, IP, or part of a user name or description.
        network: Network name or ID; may be omitted when only one is in scope.
        hours: Look-back window for the search and the history, 1-24 (default 1).
        top: How many other matches and events to list (1-20, default 5).
    """
    net = _one_network(network)
    hours = _bound(hours, 1, 24)
    top = _bound(top, 1, 20)
    if not (query or "").strip():
        raise ToolError("query is empty")
    tz = _tz(net)
    names, _ = _device_names(net["organizationId"])
    try:
        rows, how, capped = _client_matches(net, query, hours)
    except httpx.TimeoutException:
        raise ToolError(f"the Dashboard took too long to search the clients of the last {hours}h; ask with a smaller hours=") from None
    lines = [f"# Client {query!r} — {net.get('name')} (matched by {how})"]
    if capped:
        lines.append("- capped: more clients were seen than were scanned; give a MAC or IP, or a smaller hours=")
    if not rows:
        lines.append("- No client matched.")
        return "\n".join(lines)
    rows.sort(key=lambda r: str(r.get("lastSeen") or ""), reverse=True)
    if len(rows) > 1:
        lines.append(f"- {len(rows)} clients matched; showing the most recently seen. Others: " + ", ".join(
            f"{r.get('description') or r.get('user') or r.get('mac')} ({r.get('mac')}, {r.get('ip') or '-'})" for r in rows[1 : 1 + top]
        ) + (f" … capped: {len(rows) - 1 - top} more" if len(rows) - 1 > top else ""))
    hit = rows[0]
    cid = hit.get("id")
    detail = _get_client().get(f"/networks/{net['id']}/clients/{cid}") if cid else hit
    detail = _redact(detail or hit, [0])
    where = detail.get("recentDeviceName") or names.get(detail.get("recentDeviceSerial"), detail.get("recentDeviceSerial"))
    lines += [
        f"- MAC {detail.get('mac')}, IP {detail.get('ip') or '-'}, IPv6 {detail.get('ip6') or '-'}, VLAN {detail.get('vlan') or detail.get('namedVlan') or '-'}",
        f"- User {detail.get('user') or '-'}, description {detail.get('description') or '-'}, OS {detail.get('os') or '-'}, maker {detail.get('manufacturer') or '-'}",
        f"- Status {detail.get('status') or '-'}, SSID {detail.get('ssid') or '-'}, last seen {_local(detail.get('lastSeen'), tz)}, first seen {_local(detail.get('firstSeen'), tz)}",
        f"- Last connected to {where or '-'}" + (f" port {detail.get('switchport')}" if detail.get("switchport") else ""),
    ]
    if not cid or "wireless" not in (net.get("productTypes") or []) or not detail.get("ssid"):
        return "\n".join(lines)

    base = f"/networks/{net['id']}/wireless/clients/{cid}"
    window = {"timespan": hours * 3600}
    stats = (_get_client().get(f"{base}/connectionStats", window) or {}).get("connectionStats") or {}
    summary, _ = _success_line(stats)
    lines.append(f"\n## Wireless, last {hours}h")
    lines.append(f"- Connections: {summary}")
    page = _get_client().page(f"{base}/connectivityEvents", {**window, "perPage": 1000})
    events = page.data or []
    if events:
        lines.append(f"- Connectivity events: {len(events):,}{' (capped: more than one page; shorten hours=)' if page.links.get('next') else ''}")
        lines.append(f"- By type: {_top(collections.Counter(e.get('type') for e in events), 10)}")
        per_ap: dict[str, list[int]] = collections.defaultdict(list)
        for e in events:
            ap = names.get(e.get("deviceSerial"), e.get("deviceSerial") or "?")
            rssi = e.get("rssi")
            per_ap[ap].append(int(rssi) if isinstance(rssi, (int, float)) and rssi > 0 else 0)  # -1 means unknown
        ranked = sorted(per_ap.items(), key=lambda kv: -len(kv[1]))
        lines.append(
            "- By access point: "
            + ", ".join(
                f"{ap} {len(v)} (RSSI {min(x for x in v if x) if any(v) else '-'}..{max(x for x in v if x) if any(v) else '-'} dB)"
                for ap, v in ranked[:top]
            )
            + (f" … capped: {len(ranked) - top} more" if len(ranked) > top else "")
        )
        bad = [e for e in events if (e.get("severity") or "").lower() not in ("", "info", "good")]
        if bad:
            lines.append(f"\n## Latest problems ({min(top, len(bad))} of {len(bad)})")
            for e in sorted(bad, key=lambda e: str(e.get("occurredAt")), reverse=True)[:top]:
                lines.append(
                    f"- {_local(e.get('occurredAt'), tz)} {e.get('type')}/{e.get('subtype')} ({e.get('severity')}) at "
                    f"{names.get(e.get('deviceSerial'), e.get('deviceSerial'))}, band {e.get('band')} ch {e.get('channel')}, RSSI {e.get('rssi')}"
                )
    else:
        lines.append("- No connectivity events in this window.")
    lat = ((_get_client().get(f"{base}/latencyStats", window) or {}).get("latencyStats") or {}).get("bestEffortTraffic") or {}
    if lat.get("avg") is not None:
        lines.append(f"- Best-effort latency: average {float(lat['avg']):.1f} ms")
    return "\n".join(lines)


# --------------------------------------------------------------------------
# configuration changes, firmware, licensing
# --------------------------------------------------------------------------

MAX_CHANGE_HOURS = 744  # 31 days
_CHANGES_CAPPED = " (capped: older entries in the window not read; shorten hours=)"


def _org_changes(org_id: str, hours: int) -> tuple[list[dict], bool]:
    """Change-log entries of the organization in the window, secrets masked, newest first."""

    def load():
        # The endpoint keeps offering a next page past the last entry, and that page repeats
        # the newest entry: stop when a page adds nothing new.
        query: dict[str, Any] = {"timespan": hours * 3600, "perPage": 1000}
        rows: list[dict] = []
        seen: set[str] = set()
        capped = False
        for index in range(10):
            page = _get_client().page(f"/organizations/{org_id}/configurationChanges", query)
            fresh = []
            for r in page.data or []:
                key = json.dumps(r, sort_keys=True, default=str)
                if key not in seen:
                    seen.add(key)
                    fresh.append(r)
            rows.extend(fresh)
            nxt = page.links.get("next")
            if not fresh or not nxt:
                break
            query = {"timespan": hours * 3600, "perPage": 1000, **nxt}
            capped = index == 9
        rows = _redact(rows, [0])
        rows.sort(key=lambda r: str(r.get("ts") or ""), reverse=True)
        return rows, capped

    return _cached(f"changes:{org_id}:{hours}", load)


def _changes_for(net: dict, rows: list[dict]) -> list[dict]:
    """Entries of this network, plus organization-wide ones (no network)."""
    return [r for r in rows if r.get("networkId") in (None, "", net["id"])]


def _short(value: Any, limit: int = 100) -> str:
    text = value if isinstance(value, str) else json.dumps(value, ensure_ascii=False)
    text = " ".join(text.split())
    return text if len(text) <= limit else text[:limit] + f"… ({len(text)} chars)"


@mcp.tool()
def config_changes(network: Optional[str] = None, hours: int = 168, top: int = 30) -> str:
    """Who changed what in the Dashboard, and when.

    Reads the organization's change log for the window: entries of the
    network and organization-wide ones (administrators, licensing...). Shows
    counts by administrator and by page, then the newest ``top`` entries with
    the old and new value, shortened. Values of entries whose label names a
    secret (PSK, RADIUS secret, SNMP community...) are "[redacted]".

    Args:
        network: Network name or ID; may be omitted when only one is in scope.
        hours: Look-back window, 1-744 (31 days; default 168).
        top: How many entries to list (1-100, default 30).
    """
    net = _one_network(network)
    hours = _bound(hours, 1, MAX_CHANGE_HOURS)
    top = _bound(top, 1, 100)
    tz = _tz(net)
    rows, capped = _org_changes(net["organizationId"], hours)
    rows = _changes_for(net, rows)
    lines = [f"# Configuration changes — {net.get('name')} (last {hours}h)"]
    lines.append(f"- Entries: {len(rows):,} ({sum(1 for r in rows if not r.get('networkId')):,} organization-wide){_CHANGES_CAPPED if capped else ''}")
    if not rows:
        return "\n".join(lines)
    lines.append(f"- By administrator: {_top(collections.Counter(r.get('adminName') or r.get('adminId') or '?' for r in rows), 10)}")
    lines.append(f"- By page: {_top(collections.Counter(r.get('page') or '?' for r in rows), 10)}")
    lines.append(f"\n## Newest {min(top, len(rows))} of {len(rows)}")
    for r in rows[:top]:
        where = r.get("networkName") or "organization"
        if r.get("ssidName"):
            where += f" / SSID {r['ssidName']}"
        lines.append(
            f"- {_local(r.get('ts'), tz)} {r.get('adminName') or '?'} — {where} — {r.get('page')}: {r.get('label')}: "
            f"{_short(r.get('oldValue'))} → {_short(r.get('newValue'))}"
        )
    if len(rows) > top:
        lines.append(f"- capped: {len(rows) - top} more entries not listed (raise top= or shorten hours=)")
    return "\n".join(lines)


def _changes_line(net: dict, hours: int, top: int) -> str:
    try:
        rows, capped = _org_changes(net["organizationId"], hours)
    except MerakiAPIError as exc:
        return f"- [CHANGES] not read: {exc}"
    rows = _changes_for(net, rows)
    if not rows:
        return f"- [CHANGES] none{_CHANGES_CAPPED if capped else ''}"
    org_wide = sum(1 for r in rows if not r.get("networkId"))
    return (
        f"- [CHANGES] {len(rows):,} ({org_wide:,} organization-wide) by "
        + _top(collections.Counter(r.get("adminName") or "?" for r in rows), top)
        + "; pages: "
        + _top(collections.Counter(r.get("page") or "?" for r in rows), top)
        + f"{_CHANGES_CAPPED if capped else ''} — see config_changes"
    )


def _firmware_line(net: dict, tz: datetime.tzinfo) -> str:
    try:
        products = (_get_client().get(f"/networks/{net['id']}/firmwareUpgrades") or {}).get("products") or {}
    except MerakiAPIError as exc:
        return f"- [FIRMWARE] not read: {exc}"
    parts = []
    for product, info in sorted(products.items()):
        current = (info.get("currentVersion") or {}).get("shortName") or "?"
        nxt = info.get("nextUpgrade") or {}
        when = nxt.get("time")
        target = (nxt.get("toVersion") or {}).get("shortName")
        parts.append(f"{product} {current}" + (f", upgrade to {target or '?'} at {_local(when, tz)}" if when else ""))
    return "- [FIRMWARE] " + ("; ".join(parts) if parts else "no product reported")


def _license_line(org: dict, warn_days: int = 30) -> tuple[str, bool]:
    """(the [LICENSE] line, whether it warrants a WARNING)."""
    now = datetime.datetime.now(datetime.timezone.utc)
    try:
        if ((org.get("licensing") or {}).get("model")) == "subscription":
            subs = _get_client().get(
                "/administered/licensing/subscription/subscriptions", {"organizationIds[]": [str(org["id"])]}
            ) or []
            if not subs:
                return "- [LICENSE] no subscription found", False
            parts, warn = [], False
            for sub in subs:
                end = _parse_ts(sub.get("endDate"))
                days = (end - now).days if end else None
                seats = ((sub.get("counts") or {}).get("seats")) or {}
                bad = sub.get("status") != "active" or (days is not None and days <= warn_days)
                warn = warn or bad
                parts.append(
                    f"{sub.get('name') or sub.get('subscriptionId')} {sub.get('status')}"
                    + (f" until {end:%Y-%m-%d} ({days} days)" if end else "")
                    + (f", seats {seats.get('assigned')}/{seats.get('limit')}" if seats else "")
                )
            return f"- [LICENSE{'-EXPIRING' if warn else ''}] " + "; ".join(parts), warn
        overview = _get_client().get(f"/organizations/{org['id']}/licenses/overview") or {}
        end = _parse_ts(overview.get("expirationDate"))
        days = (end - now).days if end else None
        warn = overview.get("status") not in (None, "OK") or (days is not None and days <= warn_days)
        return (
            f"- [LICENSE{'-EXPIRING' if warn else ''}] {overview.get('status')}"
            + (f" until {end:%Y-%m-%d} ({days} days)" if end else ""),
            warn,
        )
    except MerakiAPIError as exc:
        return f"- [LICENSE] not read: {exc}", False


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
# any GET operation: find_api / api_get
# --------------------------------------------------------------------------

API_ROOTS = ("organizations", "networks", "devices", "administered")
_SEGMENT_RE = re.compile(r"^[A-Za-z0-9_.:~-]{1,128}$")
_PARAM_KEY_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_]{0,63}(\[\])?$")
API_INDEX_SECONDS = 6 * 3600
API_MAX_CHARS = 20_000
API_MAX_PAGES = 5
_SERIAL_KEY = re.compile(r"(^serial|Serial)$")
API_PAGES_SECONDS = 20.0  # no further page is started after this; a page itself may take up to the client timeout
NOTE_CAPPED = "part of the answer was left out: use fields=, offset=/limit= or narrower params"
REDACTED = "[redacted]"
_CHANGE_VALUE_KEYS = ("oldValue", "newValue")
#: A change-log label or page naming a secret: its old and new values are masked.
_SECRET_LABEL = re.compile(r"(?i)psk|secret|passw|passphrase|communit|token|credential|key")
#: A key is secret when its lower-cased name contains one of these. Booleans stay.
_SECRET_KEY = re.compile(
    r"psk|secret|passw|passphrase|communit|token|credential|licensekey|apikey|privatekey|presharedkey"
    r"|sharedkey|authkey|eapolkey|md5authenticationkey|pass$|key$"
)


def _index_file(org_id: str) -> Optional[pathlib.Path]:
    """Where the operation index is kept between processes, or None when there is no cache directory."""
    root = os.environ.get("XDG_CACHE_HOME") or (os.path.join(os.path.expanduser("~"), ".cache") if os.path.expanduser("~") != "~" else "")
    if not root:
        return None
    base = os.environ.get("MERAKI_BASE_URL", "") or DEFAULT_BASE_URL
    tag = hashlib.sha256(f"{base}|{org_id}".encode()).hexdigest()[:16]
    return pathlib.Path(root) / "merakiadm-mcp" / f"api-index-{tag}.json"


def _compile_ops(ops: list[dict]) -> list[dict]:
    for op in ops:
        op["regex"] = re.compile("^" + re.sub(r"\\\{[^/]+?\\\}", "[^/]+", re.escape(op["path"])) + "$")
    return ops


def _api_index(cached_only: bool = False) -> Optional[list[dict]]:
    """GET operations of the Dashboard API, from the organization's own OpenAPI spec.

    Kept in memory and in a cache file for API_INDEX_SECONDS, so a server
    started per call (as an agent bridge does) reads the 4 MB spec only once
    in a while. The cache file is best effort: when it cannot be read or
    written the spec is fetched again. ``cached_only`` returns None instead
    of fetching.
    """
    hit = _cache.get("api-index")
    if hit and time.monotonic() - hit[0] < API_INDEX_SECONDS:
        return hit[1]
    orgs = _organizations()
    if not orgs:
        if cached_only:
            return None
        raise ToolError("no organization is visible to this API key, so there is no OpenAPI spec to search")
    org_id = str(orgs[0]["id"])
    path = _index_file(org_id)
    try:
        if path and time.time() - path.stat().st_mtime < API_INDEX_SECONDS:
            ops = _compile_ops(json.loads(path.read_text(encoding="utf-8")))
            _cache["api-index"] = (time.monotonic(), ops)
            return ops
    except (OSError, ValueError, KeyError, TypeError):
        pass
    if cached_only:
        return None
    ops = _load_api_index(org_id)
    _cache["api-index"] = (time.monotonic(), ops)
    if path:
        try:
            path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            tmp = path.with_suffix(f".{os.getpid()}.tmp")
            tmp.write_text(json.dumps([{k: v for k, v in op.items() if k != "regex"} for op in ops]), encoding="utf-8")
            os.replace(tmp, path)
        except OSError:
            pass
    return ops


def _load_api_index(org_id: str) -> list[dict]:
    """Read the GET operations out of the organization's OpenAPI spec (about 4 MB)."""
    spec = _get_client().get(f"/organizations/{org_id}/openapiSpec", {"version": 3}) or {}
    ops = []
    for path, methods in (spec.get("paths") or {}).items():
        op = (methods or {}).get("get")
        if not isinstance(op, dict):
            continue
        params = []
        for prm in op.get("parameters") or []:
            if not isinstance(prm, dict) or "name" not in prm:
                continue
            schema = prm.get("schema") or {}
            kind = schema.get("type") or ""
            if kind == "array":
                kind = f"array of {(schema.get('items') or {}).get('type') or 'value'}"
            params.append(
                {
                    "name": prm["name"],
                    "in": prm.get("in"),
                    "required": bool(prm.get("required")),
                    "type": kind,
                    "enum": schema.get("enum") or (schema.get("items") or {}).get("enum"),
                    "description": " ".join(str(prm.get("description") or "").split())[:200],
                }
            )
        ops.append(
            {
                "id": op.get("operationId") or "",
                "path": path,
                "summary": " ".join(str(op.get("summary") or "").split()),
                "description": " ".join(str(op.get("description") or "").split())[:600],
                "tags": [str(t) for t in op.get("tags") or []],
                "params": params,
            }
        )
    if not ops:
        raise ToolError("the Dashboard returned no OpenAPI operations")
    return _compile_ops(ops)


def _words(text: str) -> set[str]:
    """Lower-case words of a text, splitting camelCase and punctuation."""
    text = re.sub(r"([a-z0-9])([A-Z])", r"\1 \2", text)
    return {w for w in re.split(r"[^A-Za-z0-9]+", text.lower()) if w}


def _match_operation(path: str) -> Optional[dict]:
    """The GET operation whose template matches a concrete path, preferring the most literal one."""
    hits = [op for op in _api_index() if op["regex"].match(path)]
    return max(hits, key=lambda op: op["path"].count("/") - op["path"].count("{")) if hits else None


def _describe_operation(op: dict) -> str:
    lines = [f"# {op['id']} — GET {op['path']}", f"- {op['summary']}"]
    if op["description"] and op["description"] != op["summary"]:
        lines.append(f"- {op['description']}")
    if op["tags"]:
        lines.append(f"- tags: {', '.join(op['tags'])}")
    for prm in op["params"]:
        name = prm["name"] + ("[]" if prm["in"] == "query" and prm["type"].startswith("array") else "")
        enum = f"; one of {', '.join(map(str, prm['enum']))}" if prm["enum"] else ""
        lines.append(
            f"- {prm['in']} `{name}` ({prm['type'] or 'value'}{', required' if prm['required'] else ''}{enum})"
            + (f": {prm['description']}" if prm["description"] else "")
        )
    lines.append("Call it with api_get(path=<the path with its {placeholders} filled in>, params={...}).")
    return "\n".join(lines)


@mcp.tool()
def find_api(query: str, top: int = 10) -> str:
    """Find a Dashboard API read (GET) operation to call with api_get.

    For anything the other tools do not cover. Searches the operation IDs,
    paths, summaries and tags of this organization's own OpenAPI spec (read
    once and cached) with English keywords, e.g. "switch dhcp server policy"
    or "wireless packet loss by device". Pass an exact operation ID (e.g.
    getNetworkWirelessSsids) or a concrete path to see its parameters.

    Args:
        query: English keywords, an operation ID, or an API path.
        top: How many operations to list (1-50, default 10).
    """
    top = _bound(top, 1, 50)
    query = (query or "").strip()
    if not query:
        raise ToolError("query is empty; give English keywords such as 'switch port statuses'")
    ops = _api_index()
    exact = [op for op in ops if op["id"].lower() == query.lower() or op["path"] == query]
    if not exact and query.startswith("/"):
        hit = _match_operation(query.split("?", 1)[0])
        exact = [hit] if hit else []
    if exact:
        return _describe_operation(exact[0])
    wanted = _words(query)
    scored = []
    for op in ops:
        literal = _words(re.sub(r"\{[^}]*\}", " ", op["path"]))
        score = sum(
            3 * (w in _words(op["id"])) + 2 * (w in literal) + (w in _words(op["summary"])) + (w in {t.lower() for t in op["tags"]})
            for w in wanted
        )
        if score:
            scored.append((score, len(op["path"]), op))
    scored.sort(key=lambda x: (-x[0], x[1]))
    lines = [f"# API operations matching {query!r} ({min(top, len(scored))} of {len(scored)} of {len(ops)} GET operations)"]
    for _, _, op in scored[:top]:
        query_params = [p["name"] for p in op["params"] if p["in"] == "query"]
        lines.append(f"- {op['id']} — GET {op['path']} — {op['summary']}" + (f" (query: {', '.join(query_params)})" if query_params else ""))
    if len(scored) > top:
        lines.append(f"- capped: {len(scored) - top} more operations matched (add keywords or raise top=)")
    if not scored:
        lines.append("- No operation matched; try other English keywords (e.g. 'clients', 'firmware', 'switch ports').")
    else:
        lines.append("Pass an operation ID to find_api to see its parameters.")
    return "\n".join(lines)


def _redact(node: Any, counter: list[int]) -> Any:
    """Replace the values of secret-looking keys, also inside JSON carried in strings.

    A change-log entry keeps its values under generic keys (``oldValue`` /
    ``newValue``); those are masked when the entry's label or page names a
    secret (e.g. label "Ssid psk").
    """
    if isinstance(node, dict):
        out = {}
        secret_entry = any(k in node for k in _CHANGE_VALUE_KEYS) and any(
            isinstance(node.get(k), str) and _SECRET_LABEL.search(node[k]) for k in ("label", "page", "name")
        )
        for k, v in node.items():
            if secret_entry and k in _CHANGE_VALUE_KEYS and v not in (None, "") and not isinstance(v, bool):
                counter[0] += 1
                out[k] = REDACTED
            elif _SECRET_KEY.search(str(k).lower()) and v not in (None, "") and not isinstance(v, bool):
                counter[0] += 1
                out[k] = REDACTED
            else:
                out[k] = _redact(v, counter)
        return out
    if isinstance(node, list):
        return [_redact(v, counter) for v in node]
    if isinstance(node, str) and node.lstrip()[:1] in ("{", "["):
        try:
            inner = json.loads(node)
        except ValueError:
            return node
        return json.dumps(_redact(inner, counter), ensure_ascii=False)
    return node


def _api_segments(path: str) -> list[str]:
    """Validate an API path and split it; only relative Dashboard paths are accepted."""
    usage = "path must be a Dashboard API path such as /networks/N_123/wireless/ssids: no host, no query string"
    if not isinstance(path, str) or not path.startswith("/") or path.startswith("//") or len(path) > 512:
        raise ToolError(usage)
    if "{" in path or "}" in path:
        raise ToolError("fill in the {placeholders} of the path (e.g. {networkId} with a network ID from health_check)")
    segments = path[1:].removesuffix("/").split("/")
    if segments[0] not in API_ROOTS:
        raise ToolError(f"{usage}; it must start with /{', /'.join(API_ROOTS)}")
    for seg in segments:
        if seg in ("", ".", "..") or not _SEGMENT_RE.match(seg):
            raise ToolError(f"{usage}; segment {seg!r} is not allowed")
    return segments


def _scoped_serials() -> set[str]:
    nets = {n["id"] for n in _networks()}
    serials = set()
    for org in _organizations():
        devices, _ = _devices(org["id"])
        serials.update(d["serial"] for d in devices if d.get("serial") and d.get("networkId") in nets)
    return serials


def _api_scope(segments: list[str], path: str, params: dict[str, Any]) -> None:
    """Refuse paths outside MERAKI_ORG_ID / MERAKI_NETWORK_IDS; narrow organization-wide reads."""
    root = segments[0]
    if root == "organizations" and len(segments) > 1:
        if segments[1] not in {str(o["id"]) for o in _organizations()}:
            raise ToolError(f"organization {segments[1]} is not in scope (MERAKI_ORG_ID)")
        scope = _env_list("MERAKI_NETWORK_IDS")
        if scope and len(segments) > 2 and segments[2:] != ["networks"]:
            op = _match_operation(path)
            if op is None or not any(p["name"] == "networkIds" and p["in"] == "query" for p in op["params"]):
                raise ToolError("MERAKI_NETWORK_IDS limits the scope, and this organization-wide read cannot be narrowed to those networks")
            asked: Any = []
            for key in ("networkIds", "networkIds[]"):
                value = params.pop(key, None)
                asked += value if isinstance(value, list) else [] if value is None else [value]
            if not all(isinstance(n, str) for n in asked):
                raise ToolError("networkIds must be network ID strings")
            outside = [n for n in asked if n not in scope]
            if outside:
                raise ToolError(f"network {outside[0]} is not in scope (MERAKI_NETWORK_IDS)")
            params["networkIds[]"] = asked or scope
    elif root == "networks" and len(segments) > 1:
        if segments[1] not in {n["id"] for n in _networks()}:
            raise ToolError(f"network {segments[1]} is not in scope (see health_check for the networks)")
    elif root == "devices" and len(segments) > 1:
        if segments[1] not in _scoped_serials():
            raise ToolError(f"device {segments[1]} is not in a network in scope")
    elif root == "administered" and segments != ["administered", "identities", "me"]:
        if _env_list("MERAKI_ORG_ID") or _env_list("MERAKI_NETWORK_IDS"):
            raise ToolError("MERAKI_ORG_ID / MERAKI_NETWORK_IDS limit the scope, and /administered reads cannot be narrowed to it")


def _api_params(params: Optional[dict]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for key, value in (params or {}).items():
        if not isinstance(key, str) or not _PARAM_KEY_RE.match(key):
            raise ToolError(f"query parameter {key!r} is not allowed")
        values = value if isinstance(value, list) else [value]
        if not all(isinstance(v, (str, int, float, bool)) for v in values) or len(values) > 100:
            raise ToolError(f"query parameter {key!r} must be a value or a list of at most 100 values")
        if isinstance(value, list) and not key.endswith("[]"):
            key += "[]"
        out[key] = [str(v).lower() if isinstance(v, bool) else v for v in values] if isinstance(value, list) else (str(value).lower() if isinstance(value, bool) else value)
    return out


def _project(node: Any, fields: list[str]) -> Any:
    """Keep only ``fields`` (top-level keys, or dotted paths) of a dict or of each dict in a list."""
    if isinstance(node, list):
        return [_project(v, fields) for v in node]
    if not isinstance(node, dict):
        return node
    nested: dict[str, list[str]] = {}
    for f in fields:
        head, _, rest = str(f).partition(".")
        nested.setdefault(head, [])
        if rest:
            nested[head].append(rest)
    out: dict[str, Any] = {}
    for head, rests in nested.items():
        if head in node:
            whole = not rests or len(rests) < sum(1 for f in fields if str(f).partition(".")[0] == head)
            out[head] = node[head] if whole else _project(node[head], rests)
    return out


def _shrink(node: Any, list_max: int, str_max: int, state: dict) -> Any:
    if isinstance(node, dict):
        return {k: _shrink(v, list_max, str_max, state) for k, v in node.items()}
    if isinstance(node, list):
        kept = [_shrink(v, list_max, str_max, state) for v in node[:list_max]]
        if len(node) > list_max:
            state["cut"] = True
            kept.append(f"… {len(node) - list_max} more items")
        return kept
    if isinstance(node, str) and len(node) > str_max:
        state["cut"] = True
        return node[:str_max] + f"… ({len(node)} chars)"
    return node


def _json_arg(value: Any, kind: type, name: str) -> Any:
    """Accept an argument sent as a JSON-encoded string as well (some clients do that)."""
    if isinstance(value, str):
        text = value.strip()
        if not text:
            return None
        try:
            value = json.loads(text)
        except ValueError:
            if kind is list:
                return [f.strip() for f in text.split(",") if f.strip()]
            raise ToolError(f"{name} must be a JSON object") from None
    if value is not None and not isinstance(value, kind):
        raise ToolError(f"{name} must be a JSON {'object' if kind is dict else 'array'}")
    return value


def _merge_pages(data: Any, more: Any) -> Any:
    """Append the list of a following page to the first; None when the pages do not line up."""
    if isinstance(data, list) and isinstance(more, list):
        return data + more
    if isinstance(data, dict) and isinstance(more, dict):
        keys = [k for k, v in data.items() if isinstance(v, list)]
        key = "items" if "items" in keys else (keys[0] if len(keys) == 1 else None)
        if key and isinstance(more.get(key), list):
            return {**data, key: data[key] + more[key]}
    return None


def _name_serials(node: Any) -> Any:
    """Add a device name next to every serial of a device in scope.

    ``serial`` gets ``deviceName``; another key ending in ``Serial`` (e.g.
    ``recentDeviceSerial``) gets the same key ending in ``Name``.
    """
    serials: set[str] = set()

    def collect(n: Any) -> None:
        if isinstance(n, dict):
            for k, v in n.items():
                if _SERIAL_KEY.search(str(k)) and isinstance(v, str):
                    serials.add(v)
            for v in n.values():
                collect(v)
        elif isinstance(n, list):
            for v in n:
                collect(v)

    collect(node)
    if not serials:
        return node
    names: dict[str, str] = {}
    in_scope = {n["id"] for n in _networks()}
    for org in _organizations():
        try:
            devices, _ = _devices(str(org["id"]))
        except MerakiAPIError:
            continue
        names.update({d["serial"]: d.get("name") or d["serial"] for d in devices if d.get("serial") and d.get("networkId") in in_scope})

    def add(n: Any) -> Any:
        if isinstance(n, dict):
            out = {k: add(v) for k, v in n.items()}
            for k, v in n.items():
                if not (_SERIAL_KEY.search(str(k)) and isinstance(v, str)):
                    continue
                name = names.get(v)
                label = "deviceName" if k == "serial" else str(k)[:-6] + "Name"
                if name and name != v and label not in out and out.get("name") != name:
                    out[label] = name
            return out
        if isinstance(n, list):
            return [add(v) for v in n]
        return n

    return add(node)


def _size(node: Any) -> int:
    return len(json.dumps(node, ensure_ascii=False, default=str))


@mcp.tool()
def api_get(
    path: str,
    params: Optional[dict[str, Any] | str] = None,
    fields: Optional[list[str] | str] = None,
    offset: int = 0,
    limit: int = 20,
    max_chars: int = API_MAX_CHARS,
    max_pages: int = 1,
) -> dict:
    """Read any Dashboard API GET operation, bounded and with secrets masked.

    For what the other tools do not cover; find the operation with find_api
    first. Reads one page only. A list answer (or the one list inside an
    object, named by ``list_key``, e.g. "events") is cut to ``limit`` items from
    ``offset`` (``total_items`` says how many came back), ``fields`` keeps only
    the named keys of each item (dotted paths reach inside, e.g.
    "device.name"), and the whole answer is shrunk to ``max_chars``: long
    nested lists and strings are cut and ``capped`` is set. Values of
    secret-looking keys (PSKs, RADIUS secrets, SNMP communities, passwords,
    tokens, keys) are replaced with "[redacted]". Every item that carries a
    device ``serial`` also gets that device's ``deviceName``. ``next_params`` /
    ``prev_params`` are the paging parameters to add for the next page;
    ``max_pages`` reads up to 5 pages in one call and ``has_next_page`` says
    whether more remain. ``observed_at`` (UTC) and ``operation`` say when and
    what was read.

    Args:
        path: API path with its IDs filled in, e.g. /networks/N_123/wireless/ssids
            (IDs and serials from health_check or other tools; must be in scope).
        params: Query parameters, e.g. {"timespan": 3600, "perPage": 100}; a list value is sent as key[].
        fields: Keys to keep in each item, e.g. ["name", "serial", "status"].
        offset: First list item to return (default 0).
        limit: List items to return, 1-200 (default 20).
        max_chars: Size limit of the answer, 2000-60000 characters (default 20000).
        max_pages: Pages to read by following next links, 1-5 (default 1).
    """
    params = _json_arg(params, dict, "params")
    fields = _json_arg(fields, list, "fields")
    if isinstance(fields, list) and not all(isinstance(f, str) for f in fields):
        raise ToolError("fields must be a list of key names")
    segments = _api_segments(path)
    query = _api_params(params)
    path = "/" + "/".join(segments)
    _api_scope(segments, path, query)
    limit = _bound(limit, 1, 200)
    offset = max(0, int(offset or 0))
    max_chars = _bound(max_chars, 2000, 60000)
    max_pages = _bound(max_pages, 1, API_MAX_PAGES)
    observed_at = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    pages_read = 1
    page_error = ""
    if segments == ["organizations"]:
        data: Any = _organizations()
        page_links: dict = {}
    else:
        page = _get_client().page(path, query or None)
        data, page_links = page.data, page.links
        started = time.monotonic()
        while pages_read < max_pages and page_links.get("next") and time.monotonic() - started < API_PAGES_SECONDS:
            nxt = page_links["next"]
            follow = {k: v for k, v in query.items() if k not in CURSOR_PARAMS}
            follow.update(nxt)
            if "t0" in nxt or "t1" in nxt:
                follow.pop("timespan", None)
            try:
                more = _get_client().page(path, follow)
            except (MerakiAPIError, httpx.HTTPError) as exc:
                page_error = f"page {pages_read + 1} could not be read ({exc}); the pages before it are returned"
                break
            merged = _merge_pages(data, more.data)
            if merged is None:
                break
            data, page_links, pages_read = merged, more.links, pages_read + 1
        if segments[0] == "organizations" and segments[2:] == ["networks"] and _env_list("MERAKI_NETWORK_IDS"):
            scope = set(_env_list("MERAKI_NETWORK_IDS"))
            data = [n for n in data or [] if isinstance(n, dict) and n.get("id") in scope]
    redacted = [0]
    data = _redact(data, redacted)

    result: dict[str, Any] = {"path": path, "observed_at": observed_at}
    index = _api_index(cached_only=True) if segments != ["organizations"] else None
    op = next((o for o in index or [] if o["regex"].match(path)), None) if index else None
    if op:
        result["operation"] = op["id"]
    if query:
        result["params"] = _shrink(query, 20, 200, {})
    if pages_read > 1 or max_pages > 1:
        result["pages_read"] = pages_read
    result["has_next_page"] = bool(page_links.get("next"))
    if page_error:
        result["page_error"] = page_error
    if redacted[0]:
        result["redacted"] = redacted[0]
    for rel in ("next", "prev"):
        if page_links.get(rel):
            result[f"{rel}_params"] = _shrink(page_links[rel], 5, 300, {})

    list_key, rest, items = None, None, data
    if isinstance(data, dict):
        lists = [k for k, v in data.items() if isinstance(v, list)]
        list_key = "items" if "items" in lists else (lists[0] if len(lists) == 1 else None)
        if list_key:
            rest, items = {k: v for k, v in data.items() if k != list_key}, data[list_key]
    window = None
    if isinstance(items, list):
        result["total_items"] = len(items)
        if list_key:
            result["list_key"] = list_key
        result["offset"] = offset
        window = items[offset : offset + limit]
        if fields:
            window = _project(window, fields)
        window = _name_serials(window)
    else:
        if fields:
            data = _project(data, fields)
        data = _name_serials(data)

    def build(rows: Any, extra: Any, list_max: int, str_max: int, state: dict) -> Any:
        if rows is None:
            return _shrink(data, list_max, str_max, state)
        shrunk = [_shrink(r, list_max, str_max, state) for r in rows]
        if extra is None:
            return shrunk
        return {**_shrink(extra, list_max, str_max, state), list_key: shrunk}

    def fits(shaped: Any) -> bool:
        return _size({**result, "capped": True, "note": NOTE_CAPPED, "data": shaped}) <= max_chars

    state: dict[str, Any] = {}
    shaped = build(window, rest, 10**9, 10**9, state)
    for list_max, str_max in ((50, 2000), (20, 500), (10, 200), (5, 100), (2, 60), (1, 40)):
        if fits(shaped):
            break
        state = {}  # each pass starts from the unshrunk answer, so its state is the whole story
        shaped = build(window, rest, list_max, str_max, state)
    capped = bool(state.get("cut"))
    if window is not None:
        rows = list(window)
        while rows and not fits(shaped):
            rows = rows[: len(rows) // 2] if len(rows) > 1 else []
            shaped = build(rows, rest, list_max, str_max, state)
        result["returned"] = len(rows)
        capped = capped or offset + len(rows) < len(items) or len(rows) < len(window)
    if not fits(shaped):
        source = window if window is not None else data
        keys = sorted({k for v in (source if isinstance(source, list) else [source]) if isinstance(v, dict) for k in v})
        shaped = {"keys": keys[:100]}
        while keys and not fits(shaped):
            keys = keys[: len(keys) // 2]
            shaped = {"keys": keys}
        if window is not None:
            result["returned"] = 0
        capped = True
        result["note"] = "the answer is too large even when shrunk; only its keys are shown: pass fields= to pick some"
    result["capped"] = capped
    if capped and "note" not in result:
        result["note"] = NOTE_CAPPED
    if _size({**result, "data": shaped}) > max_chars:
        result.pop("params", None)
        shaped = None
        result["note"] = "the answer cannot fit max_chars; raise max_chars or narrow the request"
    result["data"] = shaped
    return result


# --------------------------------------------------------------------------
# morning brief
# --------------------------------------------------------------------------


def _wireless_line(net: dict, hours: int, top: int) -> str:
    """The [WIRELESS] line of daily_brief; an API error here is reported, not raised."""
    try:
        loss, loss_capped = _packet_loss(net, hours)
        use, use_capped = _channel_use(net, hours)
        names, _ = _device_names(net["organizationId"])
    except MerakiAPIError as exc:
        return f"- [WIRELESS] not read: {exc}"
    parts = [f"packet loss {_loss_totals(loss)}"]
    worst = _loss_ranking(loss, "upstream", MIN_LOSS_PACKETS)[:top]
    if worst:
        parts.append("worst upstream: " + ", ".join(f"{n} {_pct(int(d.get('lost') or 0), int(d.get('total') or 0))}" for n, d in worst))
    bands = _band_rows(use, names)
    if bands:
        name, band, v = max(bands, key=lambda x: x[2]["total"])
        parts.append(f"busiest channel: {name} {_band_label(band)} {v['total']:.1f}%")
    idle = _idle(loss)
    if idle:
        parts.append(f"no traffic: {', '.join(idle[:top])}{f' … capped: {len(idle) - top} more' if len(idle) > top else ''}")
    if loss_capped or use_capped:
        parts.append("capped: more access points not read")
    return "- [WIRELESS] " + "; ".join(parts) + " — see wireless_quality"


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
    - [WIRELESS] packet loss, the worst access points by upstream loss,
      the busiest channel and access points with no traffic (see
      wireless_quality); informational, it does not change the tier
    - [SECURITY] security event counts (see security_events)
    - [OPERATIONS] rare operational events: reboots, RADIUS/DHCP trouble,
      radar, attacks, switch faults, dropped log entries (see operational_events)
    - [UPLINK] switch ports flagged as uplinks that are not connected
    - [CHANGES] configuration changes by administrator and page, without
      values (see config_changes); [FIRMWARE] current versions and any
      scheduled upgrade; [LICENSE] subscription or license end date, with
      the organization's first network

    At most 25 networks, and only those started within 40 seconds, are
    checked per call; the rest are counted as capped. A network still
    running at 50 seconds stops between steps and says so.

    Output tiers:
    - CRITICAL — the API could not be read for that network
    - WARNING  — a device offline or alerting now or during the window,
                 connection failures above ``failure_threshold`` percent,
                 any security event, a warning-level operational event
                 (reboot, RADIUS timeout, DHCP pool exhausted, attack,
                 hardware or port fault), an uplink down, or a license
                 that is not active or ends within 30 days
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
    licensed: set[str] = set()  # the [LICENSE] line is per organization: shown with its first network
    started = time.monotonic()
    for index, net in enumerate(nets):
        if index and time.monotonic() - started > BRIEF_TIME_BUDGET:
            skipped = nets[index:] + skipped
            break
        tier, body = "OK", []
        org_id = net["organizationId"]
        products = net.get("productTypes") or []

        def step() -> None:
            if time.monotonic() - started > BRIEF_STEP_LIMIT:
                raise _BriefTimeUp

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

            step()
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

            step()
            alerts = _get_client().get(f"/networks/{net['id']}/health/alerts") or []
            if alerts:
                body.append(
                    f"- [HEALTH] {len(alerts)} alert(s): "
                    + "; ".join(f"{a.get('category')}: {a.get('type')} ({a.get('severity')})" for a in alerts[:top])
                    + (f" … capped: {len(alerts) - top} more" if len(alerts) > top else "")
                )

            step()
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

            step()
            if "wireless" in products:
                body.append(_wireless_line(net, hours, top))

            step()
            events, capped = _collect_events(net, list(SECURITY_EVENT_TYPES), hours)
            counts = collections.Counter(e.get("type") for e in _split_clat(events)[0])
            if counts:
                tier = "WARNING"
                body.append(f"- [SECURITY] {_type_summary(_split_clat(events)[0])}{_capped_note(capped)} — see security_events")
            else:
                body.append(f"- [SECURITY] none{_capped_note(capped)}")

            step()
            events, capped = _collect_events(net, list(OPERATIONAL_EVENT_TYPES), hours)
            ops = collections.Counter(e.get("type") for e in events if e.get("type") != "events_dropped2")
            warn = collections.Counter({t: n for t, n in ops.items() if t in OPERATIONAL_WARN_TYPES})
            info = collections.Counter({t: n for t, n in ops.items() if t not in OPERATIONAL_WARN_TYPES})
            if warn:
                tier = "WARNING"
                body.append(f"- [OPERATIONS-WARN] {_top(warn, 20)}{_capped_note(capped)} — see operational_events")
            if info or not warn:
                body.append(f"- [OPERATIONS] {_top(info, 20)}{'' if warn else _capped_note(capped)}")
            dropped = _dropped_summary(events)
            if dropped:
                body.append(f"- [LOG-DROPPED] access points dropped high-volume events: {dropped}")

            step()
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

            step()
            body.append(_changes_line(net, hours, top))
            step()
            body.append(_firmware_line(net, _tz(net)))
            step()
            if org_id not in licensed:
                licensed.add(org_id)
                org = next((o for o in _organizations() if str(o.get("id")) == str(org_id)), {"id": org_id})
                line, warn = _license_line(org)
                body.append(line)
                if warn and tier == "OK":
                    tier = "WARNING"
        except _BriefTimeUp:
            body.append(f"- capped: the brief reached {BRIEF_STEP_LIMIT:.0f} s; the rest of this network was not checked")
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
            f"capped: {len(skipped)} more networks not checked (at most {MAX_BRIEF_NETWORKS} networks and "
            f"{BRIEF_TIME_BUDGET:.0f} s per brief; set MERAKI_NETWORK_IDS or call the per-network tools)"
        )
    return "\n".join(lines).rstrip()


if __name__ == "__main__":
    mcp.run(transport="stdio")
