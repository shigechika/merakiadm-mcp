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

#: Event types worth an administrator's attention: rogue or duplicate DHCP
#: servers, spoofed or rogue access points, address conflicts, IPv6 RA guard,
#: loops and spanning-tree guards. Read from GET /networks/{id}/events/eventTypes.
NOTABLE_EVENT_TYPES = (
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
EVENT_PRODUCT_TYPES = ("wireless", "switch", "appliance", "camera", "cellularGateway", "sensor")
FAILURE_STEPS = ("assoc", "auth", "dhcp", "dns")
MAX_HOURS = 168  # the failed-connection and connection-stats endpoints look back at most 7 days
CACHE_SECONDS = 300
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


def _device_names(org_id: str) -> dict[str, str]:
    """serial -> device name (the serial itself when a device has no name)."""

    def load():
        devices = _get_client().get(f"/organizations/{org_id}/devices", {"perPage": 1000}) or []
        return {d["serial"]: d.get("name") or d["serial"] for d in devices if d.get("serial")}

    return _cached(f"devices:{org_id}", load)


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
    return ", ".join(f"{k} {v:,}" for k, v in counter.most_common(n)) or "none"


def _iso_ago(hours: int) -> str:
    moment = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(hours=hours)
    return moment.strftime("%Y-%m-%dT%H:%M:%SZ")


def _event_types(event_types: Optional[list[str]]) -> list[str]:
    if not event_types:
        return list(NOTABLE_EVENT_TYPES)
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
    (counts by status: online / alerting / offline / dormant). A degraded or
    error result adds ``detail``.
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
        for org in orgs:
            overview = _get_client().get(f"/organizations/{org['id']}/devices/statuses/overview") or {}
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


def _connection_stats(net: dict, hours: int) -> dict:
    return _get_client().get(f"/networks/{net['id']}/wireless/connectionStats", {"timespan": hours * 3600}) or {}


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
    names = _device_names(net["organizationId"])
    ssids = _ssid_names(net)
    stats = _connection_stats(net, hours)
    rows = _failed_connections(net, hours)
    summary, _ = _success_line(stats)

    lines = [f"# Connection failures — {net.get('name')} (last {hours}h)", f"- Overall: {summary}"]
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
    types = _event_types(event_types)
    tz = _tz(net)
    ssids = _ssid_names(net)
    collected: list[dict] = []
    capped: list[str] = []
    for product in [p for p in EVENT_PRODUCT_TYPES if p in (net.get("productTypes") or [])]:
        events, more = _read_events(net, product, types, hours)
        collected.extend(events)
        if more:
            capped.append(product)
    collected, clat = _split_clat(collected)
    counts = collections.Counter(e.get("type") for e in collected)
    lines = [
        f"# Security events — {net.get('name')} (last {hours}h)",
        f"- Total: {len(collected):,}{' (capped: more exist for ' + ', '.join(capped) + ')' if capped else ''}",
        f"- By type: {_top(counts, 20)}",
    ]
    if clat:
        lines.append(f"- Not counted: {clat:,} client_ip_conflict on {CLAT_PREFIX} (464XLAT/CLAT clients share 192.0.0.2 by design)")
    if collected:
        newest = sorted(collected, key=lambda e: e.get("occurredAt") or "", reverse=True)
        lines.append(f"\n## Newest {min(top, len(newest))} of {len(newest)}")
        lines.extend(_event_line(e, tz, ssids) for e in newest[:top])
        if len(newest) > top:
            lines.append(f"- capped: {len(newest) - top} more not shown (raise top= or shorten hours=)")
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
# switch uplinks
# --------------------------------------------------------------------------


def _switch_ports(org_id: str, net_ids: list[str], max_pages: int = 10):
    """Port statuses per switch for the networks. Returns (switches, capped)."""
    switches: list[dict] = []
    params: dict[str, Any] = {"networkIds[]": net_ids, "perPage": 20}
    for _ in range(max_pages):
        page = _get_client().page(f"/organizations/{org_id}/switch/ports/statuses/bySwitch", params)
        data = page.data
        items = (data.get("items") or []) if isinstance(data, dict) else (data or [])
        switches.extend(items)
        nxt = page.links.get("next")
        if not nxt:
            return switches, False
        params = {"networkIds[]": net_ids, "perPage": 20, **nxt}
    return switches, True


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

    Per network: device status (offline / alerting / dormant, by name), the
    network's health alerts, the wireless connection success rate with
    failures per step and the access points with the most failures,
    security-relevant events (see security_events), and switch uplink ports
    that are not connected.

    Output tiers:
    - CRITICAL — the API could not be read for that network
    - WARNING  — a device offline or alerting, connection failures above
                 ``failure_threshold`` percent, any security event, or an
                 uplink down
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

    sections: list[tuple[str, list[str]]] = []
    for net in nets:
        tier, body = "OK", []
        org_id = net["organizationId"]
        products = net.get("productTypes") or []
        try:
            names = _device_names(org_id)
            avail = _get_client().get(
                f"/organizations/{org_id}/devices/availabilities", {"networkIds[]": [net["id"]], "perPage": 1000}
            ) or []
            status = collections.Counter(d.get("status") for d in avail)
            body.append("- [DEVICES] " + ", ".join(f"{s} {status.get(s, 0)}" for s in ("online", "alerting", "offline", "dormant")))
            down = [d for d in avail if d.get("status") in ("offline", "alerting")]
            if down:
                tier = "WARNING"
                listed = ", ".join(f"{d.get('name') or d.get('serial')} ({d.get('status')})" for d in down[:top])
                more = f" … capped: {len(down) - top} more" if len(down) > top else ""
                body.append(f"- [DEVICES-DOWN] {listed}{more}")

            alerts = _get_client().get(f"/networks/{net['id']}/health/alerts") or []
            if alerts:
                body.append(
                    f"- [HEALTH] {len(alerts)} alert(s): "
                    + "; ".join(f"{a.get('category')}: {a.get('type')} ({a.get('severity')})" for a in alerts[:top])
                    + (f" … capped: {len(alerts) - top} more" if len(alerts) > top else "")
                )

            if "wireless" in products:
                summary, pct = _success_line(_connection_stats(net, hours))
                flag = pct > failure_threshold
                tier = "WARNING" if flag else tier
                body.append(f"- [CONNECT{'-HIGH-FAILURE' if flag else ''}] {summary}")
                if flag:
                    per_ap = collections.Counter(names.get(r.get("serial"), r.get("serial")) for r in _failed_connections(net, hours))
                    body.append(f"- [CONNECT-TOP-AP] {_top(per_ap, top)}")

            types = list(NOTABLE_EVENT_TYPES)
            counts: collections.Counter = collections.Counter()
            capped = []
            for product in [p for p in EVENT_PRODUCT_TYPES if p in products]:
                events, more = _read_events(net, product, types, hours)
                counts.update(e.get("type") for e in _split_clat(events)[0])
                if more:
                    capped.append(product)
            if counts:
                tier = "WARNING"
                body.append(f"- [SECURITY] {_top(counts, 20)}{' (capped)' if capped else ''} — see security_events")
            else:
                body.append("- [SECURITY] none")

            if "switch" in products:
                switches, more = _switch_ports(org_id, [net["id"]])
                uplinks, problems = _uplink_problems(switches)
                if problems:
                    tier = "WARNING"
                    body.append(
                        f"- [UPLINK-DOWN] {'; '.join(problems[:top])}"
                        + (f" … capped: {len(problems) - top} more" if len(problems) > top else "")
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
    return "\n".join(lines).rstrip()


if __name__ == "__main__":
    mcp.run(transport="stdio")
