"""Tools against a mocked Dashboard: aggregation, bounds, capped markers."""

from __future__ import annotations

import asyncio
import json

import httpx
import pytest
import respx

from mcp.server.mcpserver.exceptions import ToolError

from merakiadm_mcp import server


def _recent(minutes_ago):
    import datetime

    moment = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(minutes=minutes_ago)
    return moment.strftime("%Y-%m-%dT%H:%M:%SZ")

BASE = "https://api.meraki.com/api/v1"
ORG = {"id": "100", "name": "Example Org"}
NET = {
    "id": "N_1",
    "organizationId": "100",
    "name": "Example Net",
    "productTypes": ["switch", "wireless"],
    "timeZone": "Asia/Tokyo",
}
DEVICES = [
    {"serial": "Q-AP1", "name": "ap-1", "productType": "wireless", "networkId": "N_1"},
    {"serial": "Q-AP2", "name": "ap-2", "productType": "wireless", "networkId": "N_1"},
    {"serial": "Q-SW1", "name": "sw-1", "productType": "switch", "networkId": "N_1"},
]
SSIDS = [
    {"number": 0, "name": "CorpNet", "enabled": True},
    {"number": 1, "name": "Guest", "enabled": True},
    {"number": 2, "name": "Unused", "enabled": False},
]


@pytest.fixture(autouse=True)
def fresh(monkeypatch, tmp_path):
    monkeypatch.setenv("XDG_CACHE_HOME", str(tmp_path / "cache"))
    monkeypatch.setenv("MERAKI_DASHBOARD_API_KEY", "test-key")
    monkeypatch.delenv("MERAKI_ORG_ID", raising=False)
    monkeypatch.delenv("MERAKI_NETWORK_IDS", raising=False)
    monkeypatch.delenv("MERAKI_BASE_URL", raising=False)
    server._client = None
    server._cache.clear()
    yield
    server._client = None
    server._cache.clear()


def base_routes(nets=(NET,)):
    respx.get(f"{BASE}/organizations").mock(return_value=httpx.Response(200, json=[ORG]))
    respx.get(f"{BASE}/organizations/100/networks").mock(return_value=httpx.Response(200, json=list(nets)))
    respx.get(f"{BASE}/organizations/100/devices").mock(return_value=httpx.Response(200, json=DEVICES))
    respx.get(f"{BASE}/networks/N_1/wireless/ssids").mock(return_value=httpx.Response(200, json=SSIDS))


def failed_rows(n_dhcp=6, n_auth=2):
    rows = []
    for i in range(n_dhcp):
        rows.append({"serial": "Q-AP1", "clientMac": f"aa:{i:02x}", "failureStep": "dhcp", "type": "NO DHCP response", "ssidNumber": 0, "vlan": 10, "ts": "2026-11-25T01:15:00Z"})
    for i in range(n_auth):
        rows.append({"serial": "Q-AP2", "clientMac": f"bb:{i:02x}", "failureStep": "auth", "type": "802.1X auth fail", "ssidNumber": 1, "vlan": 20, "ts": "2026-11-25T02:15:00Z"})
    return rows


@respx.mock
def test_health_check_reports_counts():
    base_routes()
    respx.get(f"{BASE}/organizations/100/devices/statuses/overview").mock(
        return_value=httpx.Response(200, json={"counts": {"byStatus": {"online": 3, "alerting": 0, "offline": 0, "dormant": 0}}})
    )
    result = server.health_check()
    assert result["status"] == "healthy"
    assert result["auth"] == "ok"
    assert (result["organizations"], result["networks"]) == (1, 1)
    assert result["devices"]["online"] == 3


def test_health_check_without_key(monkeypatch):
    monkeypatch.delenv("MERAKI_DASHBOARD_API_KEY")
    result = server.health_check()
    assert result["status"] == "error"
    assert result["auth"] == "missing-env"


@respx.mock
def test_health_check_bad_key():
    respx.get(f"{BASE}/organizations").mock(return_value=httpx.Response(401, json={"errors": ["Invalid API key"]}))
    result = server.health_check()
    assert (result["status"], result["auth"]) == ("error", "error")


@respx.mock
def test_connection_failures_aggregates_without_client_macs():
    base_routes()
    respx.get(f"{BASE}/networks/N_1/wireless/connectionStats").mock(
        return_value=httpx.Response(200, json={"assoc": 0, "auth": 2, "dhcp": 6, "dns": 0, "success": 92})
    )
    respx.get(f"{BASE}/networks/N_1/wireless/failedConnections").mock(return_value=httpx.Response(200, json=failed_rows()))
    text = server.connection_failures(hours=24, top=1)
    assert text.startswith("# Connection failures — Example Net (last 24h)")
    assert "8.0% failed" in text
    assert "dhcp 6" in text and "CorpNet 6" in text and "Guest 2" in text
    assert "- ap-1: 6 (dhcp 6)" in text
    assert "capped: 1 more access points" in text
    assert "10h 6" in text  # 01:15Z is 10:15 in Asia/Tokyo
    assert "aa:00" not in text


@respx.mock
def test_hours_are_bounded():
    base_routes()
    stats = respx.get(f"{BASE}/networks/N_1/wireless/connectionStats").mock(return_value=httpx.Response(200, json={}))
    respx.get(f"{BASE}/networks/N_1/wireless/failedConnections").mock(return_value=httpx.Response(200, json=[]))
    server.connection_failures(hours=10_000, top=5)
    assert stats.calls[0].request.url.params["timespan"] == str(168 * 3600)


@respx.mock
def test_air_marshal_reports_rogues_and_twins_not_the_raw_list():
    base_routes()
    rows = [{"ssid": f"neighbour-{i}", "bssids": [{"bssid": f"x{i}"}], "wiredMacs": []} for i in range(500)]
    rows.append({"ssid": "Rogue", "bssids": [{"bssid": "r1"}], "wiredMacs": ["00:11"], "wiredVlans": [10], "lastSeen": 1764030000})
    rows.append({"ssid": "corpnet", "bssids": [{"bssid": "t1"}, {"bssid": "t2"}], "wiredMacs": [], "encryption": "WPA2"})
    rows.append({"ssid": "", "bssids": [], "wiredMacs": []})
    respx.get(f"{BASE}/networks/N_1/wireless/airMarshal").mock(return_value=httpx.Response(200, json=rows))
    text = server.air_marshal(hours=1, top=5)
    assert "- Seen: 503 SSIDs (1 hidden), 503 BSSIDs" in text
    assert "- On your wired LAN (rogue): 1" in text
    assert "- Using one of your SSID names: 1" in text
    assert "- Rogue: bssids=1" in text and "wiredMacs=1" in text and "wiredVlans=[10]" in text
    assert "- corpnet: bssids=2" in text
    assert "neighbour-1" not in text


@respx.mock
def test_security_events_counts_and_details():
    base_routes()
    when = _recent(90)
    event = {
        "occurredAt": when,
        "type": "multiple_dhcp_servers_detected",
        "deviceName": "ap-1",
        "deviceSerial": "Q-AP1",
        "ssidNumber": 0,
        "eventData": {"server_ip": "192.0.2.1"},
    }
    old = {**event, "occurredAt": _recent(60 * 30)}
    route = respx.get(f"{BASE}/networks/N_1/events").mock(return_value=httpx.Response(200, json={"events": [event, old]}))
    text = server.security_events(hours=24, top=5)
    assert "- Total: 2" in text  # one per product type queried; the 30-hour-old one is outside the window
    assert "multiple_dhcp_servers_detected 2 (1 devices)" in text
    local = server._local(when, server._tz(NET))
    assert f"{local} multiple_dhcp_servers_detected device=ap-1 ssid=CorpNet" in text
    assert "192.0.2.1" in text
    params = route.calls[0].request.url.params
    assert "ra_blocked" in params.get_list("includedEventTypes[]")
    assert {c.request.url.params["productType"] for c in route.calls} == {"switch", "wireless"}
    assert "startingAfter" not in params  # newest page first


@respx.mock
def test_security_events_marks_capped_pages():
    base_routes()
    events = [{"occurredAt": _recent(5), "type": "client_ip_conflict", "clientMac": f"aa:{i:04x}"} for i in range(1000)]
    respx.get(f"{BASE}/networks/N_1/events").mock(
        return_value=httpx.Response(200, json={"events": events}, headers={"Link": f"<{BASE}/networks/N_1/events?endingBefore=z>; rel=prev"})
    )
    text = server.security_events(hours=24, top=2)
    assert "capped: older wireless, switch events in the window not read" in text
    assert "capped: 1998 more not shown" in text


@respx.mock
def test_clat_conflicts_are_counted_apart():
    base_routes()
    clat = {"occurredAt": "2026-11-25T08:00:00Z", "type": "client_ip_conflict", "eventData": {"ip": "192.0.0.2"}}
    real = {"occurredAt": "2026-11-25T08:00:00Z", "type": "client_ip_conflict", "eventData": {"ip": "198.51.100.7"}}
    respx.get(f"{BASE}/networks/N_1/events").mock(return_value=httpx.Response(200, json={"events": [clat, clat, real]}))
    text = server.security_events(hours=24, top=5)
    assert "- Total: 2" in text  # one real conflict per product type queried
    assert "Not counted: 4 client_ip_conflict on 192.0.0.0/29" in text
    assert "192.0.0.2" not in text.split("## Newest", 1)[1]


def test_invalid_event_type_is_refused():
    with pytest.raises(ToolError):
        server._event_types(["ok_type", "bad&type=1"])


@respx.mock
def test_list_events_returns_an_older_cursor():
    base_routes()
    link = f"<{BASE}/networks/N_1/events?productType=wireless&endingBefore=2026-11-25T11%3A00%3A00Z>; rel=prev"
    route = respx.get(f"{BASE}/networks/N_1/events").mock(
        return_value=httpx.Response(
            200,
            json={"events": [{"occurredAt": "2026-11-25T11:10:00Z", "type": "association"}], "pageStartAt": "2026-11-25T11:00:00Z", "pageEndAt": "2026-11-25T11:20:00Z"},
            headers={"Link": link},
        )
    )
    text = server.list_events("wireless", per_page=500)
    assert "older_cursor: endingBefore=2026-11-25T11%3A00%3A00Z" in text
    assert "complete: false" in text
    assert route.calls[0].request.url.params["perPage"] == "100"
    server.list_events("wireless", per_page=5, cursor="endingBefore=2026-11-25T11%3A00%3A00Z&perPage=9999")
    params = route.calls[1].request.url.params
    assert params["endingBefore"] == "2026-11-25T11:00:00Z" and params["perPage"] == "5"


def test_list_events_rejects_unknown_product_type():
    with pytest.raises(ToolError):
        server.list_events("toaster")


@respx.mock
def test_several_networks_need_a_name():
    other = {**NET, "id": "N_2", "name": "Other Net"}
    base_routes(nets=(NET, other))
    with pytest.raises(ToolError, match="Several networks"):
        server._one_network(None)
    assert server._one_network("other net")["id"] == "N_2"
    with pytest.raises(ToolError, match="No network named"):
        server._one_network("nope")


def events_by_kind(security=(), operational=(), headers=None):
    """An events route answering by which default type list was asked for."""

    def answer(request):
        asked = request.url.params.get_list("includedEventTypes[]")
        body = list(operational) if "boot" in asked else list(security)
        return httpx.Response(200, json={"events": body}, headers=headers or {})

    return answer


def daily_routes(stats, events=(), ports=None, avail=None, changes=(), ops=(), prev=None):
    base_routes()
    respx.get(f"{BASE}/organizations/100/devices/availabilities/changeHistory").mock(
        return_value=httpx.Response(200, json=list(changes))
    )
    respx.get(f"{BASE}/organizations/100/devices/availabilities").mock(
        return_value=httpx.Response(200, json=avail if avail is not None else [{"name": d["name"], "serial": d["serial"], "status": "online"} for d in DEVICES])
    )
    respx.get(f"{BASE}/networks/N_1/health/alerts").mock(return_value=httpx.Response(200, json=[]))
    respx.get(f"{BASE}/networks/N_1/wireless/connectionStats").mock(
        side_effect=lambda request: httpx.Response(200, json=(prev or {}) if "t0" in request.url.params else stats)
    )
    respx.get(f"{BASE}/networks/N_1/wireless/failedConnections").mock(return_value=httpx.Response(200, json=failed_rows()))
    respx.get(f"{BASE}/networks/N_1/events").mock(side_effect=events_by_kind(events, ops))
    respx.get(f"{BASE}/organizations/100/switch/ports/statuses/bySwitch").mock(
        return_value=httpx.Response(200, json={"items": ports if ports is not None else [{"name": "sw-1", "ports": [{"portId": "49", "isUplink": True, "status": "Connected", "enabled": True}]}], "meta": {}})
    )
    wireless_routes()
    respx.get(f"{BASE}/organizations/100/configurationChanges").mock(return_value=httpx.Response(200, json=CHANGES))
    respx.get(f"{BASE}/networks/N_1/firmwareUpgrades").mock(return_value=httpx.Response(200, json={"products": {
        "wireless": {"currentVersion": {"shortName": "MR 31.1"}, "nextUpgrade": {"time": "2026-12-01T18:00:00Z", "toVersion": {"shortName": "MR 31.2"}}},
        "switch": {"currentVersion": {"shortName": "MS 18.1"}, "nextUpgrade": {"time": "", "toVersion": {}}},
    }}))
    respx.get(f"{BASE}/organizations/100/licenses/overview").mock(return_value=httpx.Response(200, json={"status": "OK", "expirationDate": "2099-01-01T00:00:00Z"}))


CHANGES = [
    {"ts": "2026-11-25T01:00:00Z", "adminName": "alice", "networkId": "N_1", "networkName": "Example Net", "ssidName": "CorpNet", "page": "Access control", "label": "Ssid psk", "oldValue": "s1", "newValue": "s2"},
    {"ts": "2026-11-25T02:00:00Z", "adminName": "bob", "networkId": None, "page": "Administrators", "label": "Create admin", "oldValue": "", "newValue": "x" * 300},
    {"ts": "2026-11-25T03:00:00Z", "adminName": "bob", "networkId": "N_9", "page": "Other", "label": "Elsewhere", "oldValue": "a", "newValue": "b"},
]


def loss_rows():
    def side(total, lost):
        return {"total": total, "lost": lost, "lossPercentage": round(lost / total * 100, 1) if total else None}

    return [
        {"device": {"serial": "Q-AP1", "name": "ap-1"}, "upstream": side(10_000, 2_000), "downstream": side(20_000, 20)},
        {"device": {"serial": "Q-AP2", "name": "ap-2"}, "upstream": side(50, 25), "downstream": side(40, 0)},
        {"device": {"serial": "Q-AP3", "name": "ap-3"}, "upstream": side(0, 0), "downstream": side(0, 0)},
    ]


def wireless_routes(loss=None, use=None, latency=None):
    respx.get(f"{BASE}/organizations/100/wireless/devices/packetLoss/byDevice").mock(
        return_value=httpx.Response(200, json=loss if loss is not None else loss_rows())
    )
    band = lambda b, w, n: {"band": b, "wifi": {"percentage": w}, "nonWifi": {"percentage": n}, "total": {"percentage": w + n}}  # noqa: E731
    respx.get(f"{BASE}/organizations/100/wireless/devices/channelUtilization/byDevice").mock(
        return_value=httpx.Response(200, json=use if use is not None else [
            {"serial": "Q-AP1", "byBand": [band("2.4", 40.0, 5.0), band("5", 10.0, 0.5)]},
            {"serial": "Q-AP2", "byBand": [band("2.4", 20.0, 15.0), band("5", 6.0, 0.0)]},
        ])
    )
    be = lambda avg, n: {"bestEffortTraffic": {"avg": avg, "rawDistribution": {"1": n}}}  # noqa: E731
    respx.get(f"{BASE}/networks/N_1/wireless/devices/latencyStats").mock(
        return_value=httpx.Response(200, json=latency if latency is not None else [
            {"serial": "Q-AP1", "latencyStats": be(3.5, 500)},
            {"serial": "Q-AP2", "latencyStats": be(90.0, 10)},
        ])
    )


@respx.mock
def test_daily_brief_ok():
    daily_routes({"assoc": 0, "auth": 1, "dhcp": 1, "dns": 0, "success": 98})
    text = server.daily_brief(hours=24, failure_threshold=10.0, top=3)
    assert text.startswith("## daily_brief — ")
    assert "1 networks: 1 OK, 0 WARNING, 0 CRITICAL" in text
    assert "[AVAILABILITY] every device stayed online (0 status changes)" in text
    assert "[SECURITY] none" in text
    assert "[OPERATIONS] none" in text
    assert "[UPLINK] 1 switches, 1 uplink ports, none down" in text
    assert "[WIRELESS] packet loss client to AP (upstream) 20.1% of 10,050" in text
    assert "worst upstream: ap-1 20.0%;" in text  # ap-2 carried too few packets to rank
    assert "busiest channel: ap-1 2.4 GHz 45.0%" in text and "no traffic: ap-3" in text
    assert "[CHANGES] 2 (1 organization-wide) by bob 1, alice 1; pages: Administrators 1, Access control 1" in text
    assert "[FIRMWARE] switch MS 18.1; wireless MR 31.1, upgrade to MR 31.2 at 12-02 03:00" in text
    assert "[LICENSE] OK until 2099-01-01" in text and "s2" not in text


@respx.mock
def test_daily_brief_reports_an_unreadable_wireless_line_without_raising_the_tier():
    daily_routes({"assoc": 0, "auth": 1, "dhcp": 1, "dns": 0, "success": 98})
    respx.get(f"{BASE}/organizations/100/wireless/devices/packetLoss/byDevice").mock(return_value=httpx.Response(404, json={"errors": ["Not found"]}))
    text = server.daily_brief(hours=24, failure_threshold=10.0, top=3)
    assert "1 OK, 0 WARNING, 0 CRITICAL" in text
    assert "[WIRELESS] not read:" in text


@respx.mock
def test_wireless_quality_ranks_loss_channels_and_latency():
    base_routes()
    wireless_routes()
    text = server.wireless_quality(hours=24, top=5, min_packets=1000)
    assert text.startswith("# Wireless quality — Example Net (last 24h)")
    assert "Access points reported: 3; carried no traffic: 1 (ap-3)" in text
    assert "Upstream loss (client to AP), worst 1 of 1 with any loss and at least 1,000 packets" in text
    assert "- ap-1: 20.0% (2,000 of 10,000)" in text
    assert "ap-2: 50.0%" not in text
    assert "- 2.4 GHz: 2 radios, average 40.0%, highest 45.0%" in text
    assert "- ap-1 2.4 GHz: 45.0% (Wi-Fi 40.0%, non-Wi-Fi 5.0%)" in text
    assert "Most non-Wi-Fi interference: ap-2 2.4 GHz 15.0%" in text
    assert "- ap-1: 3.5 ms (500 samples)" in text and "90.0 ms" not in text
    assert "- ap-1: <0.1% (20 of 20,000)" not in text  # 0.1% is shown as is
    assert "Downstream loss (AP to client), worst 1 of 1" in text and "- ap-1: 0.1% (20 of 20,000)" in text
    assert server._pct(1, 7_750) == "<0.1%" and server._pct(0, 10) == "0.0%" and server._pct(0, 0) == "n/a"
    assert "more radios not listed" not in text
    assert "- capped: 3 more radios not listed" in server.wireless_quality(hours=24, top=1)
    small = server.wireless_quality(hours=24, top=5, min_packets=10)
    assert "- ap-2: 50.0% (25 of 50)" in small


@respx.mock
def test_wireless_quality_needs_a_wireless_network():
    base_routes(nets=({**NET, "productTypes": ["switch"]},))
    with pytest.raises(ToolError, match="no wireless devices"):
        server.wireless_quality()


@respx.mock
def test_daily_brief_warns_on_failures_events_devices_and_uplinks():
    daily_routes(
        {"assoc": 0, "auth": 2, "dhcp": 6, "dns": 0, "success": 12},
        events=[{"type": "rogue_dhcp"}],
        ports=[{"name": "sw-1", "ports": [{"portId": "49", "isUplink": True, "status": "Disconnected", "enabled": True}]}],
        avail=[{"name": "ap-1", "serial": "Q-AP1", "status": "offline"}],
    )
    text = server.daily_brief(hours=24, failure_threshold=10.0, top=3)
    assert "0 OK, 1 WARNING" in text
    assert "[DEVICES-DOWN] ap-1 (offline)" in text
    assert "[CONNECT-HIGH-FAILURE]" in text and "[CONNECT-TOP-AP] ap-1 6, ap-2 2" in text
    assert "[SECURITY] rogue_dhcp 2" in text  # one per product type queried
    assert "[UPLINK-DOWN] sw-1 port 49 Disconnected" in text


@respx.mock
def test_daily_brief_reports_api_errors_per_network():
    daily_routes({})
    respx.get(f"{BASE}/networks/N_1/health/alerts").mock(return_value=httpx.Response(500, json={"errors": ["boom"]}))
    server._get_client()._max_retries = 0
    text = server.daily_brief(hours=24, failure_threshold=10.0, top=3)
    assert "0 OK, 0 WARNING, 1 CRITICAL" in text
    assert "[API-ERROR]" in text


def test_every_tool_is_read_only():
    tools = asyncio.run(server.mcp.list_tools())
    assert tools
    for tool in tools:
        assert tool.annotations and tool.annotations.read_only_hint, tool.name


def test_top_says_how_many_were_left_out():
    import collections

    assert server._top(collections.Counter({"a": 3, "b": 2, "c": 1}), 2) == "a 3, b 2, +1 more"


@respx.mock
def test_health_check_counts_only_the_configured_networks(monkeypatch):
    monkeypatch.setenv("MERAKI_NETWORK_IDS", "N_1")
    base_routes(nets=(NET, {**NET, "id": "N_2", "name": "Other"}))
    route = respx.get(f"{BASE}/organizations/100/devices/statuses/overview").mock(
        return_value=httpx.Response(200, json={"counts": {"byStatus": {"online": 3}}})
    )
    result = server.health_check()
    assert result["networks"] == 1
    assert route.calls[0].request.url.params.get_list("networkIds[]") == ["N_1"]


@respx.mock
def test_daily_brief_checks_at_most_the_network_budget(monkeypatch):
    monkeypatch.setattr(server, "MAX_BRIEF_NETWORKS", 1)
    other = {**NET, "id": "N_2", "name": "Other Net"}
    daily_routes({"success": 10})
    respx.get(f"{BASE}/organizations/100/networks").mock(return_value=httpx.Response(200, json=[NET, other]))
    text = server.daily_brief(hours=24, failure_threshold=10.0, top=3)
    assert "1 networks: 1 OK" in text
    assert "capped: 1 more networks not checked" in text


@respx.mock
def test_daily_brief_says_when_security_pages_were_left_unread():
    daily_routes({"success": 10})
    clat = {"occurredAt": _recent(5), "type": "client_ip_conflict", "eventData": {"ip": "192.0.0.2"}}
    respx.get(f"{BASE}/networks/N_1/events").mock(
        side_effect=events_by_kind([clat] * 1000, headers={"Link": f"<{BASE}/networks/N_1/events?endingBefore=z>; rel=prev"})
    )
    text = server.daily_brief(hours=24, failure_threshold=10.0, top=3)
    assert "[SECURITY] none (capped: older wireless, switch events in the window not read" in text


def change(serial, name, ts, old, new):
    return {
        "ts": ts,
        "device": {"serial": serial, "name": name, "productType": "wireless"},
        "details": {"old": [{"name": "status", "value": old}], "new": [{"name": "status", "value": new}]},
    }



@respx.mock
def test_availability_history_pairs_outages():
    base_routes()
    respx.get(f"{BASE}/organizations/100/devices/availabilities/changeHistory").mock(
        return_value=httpx.Response(
            200,
            json=[
                change("Q-AP1", "ap-1", _recent(120), "online", "offline"),
                change("Q-AP1", "ap-1", _recent(110), "offline", "online"),
                change("Q-AP1", "ap-1", _recent(60), "online", "offline"),
                change("Q-AP1", "ap-1", _recent(55), "offline", "online"),
                change("Q-AP2", "ap-2", _recent(30), "online", "offline"),
            ],
        )
    )
    text = server.availability_history(hours=24, top=5)
    assert "- Status changes: 5" in text
    assert "- Devices not online at some point: 2 (left online during the window: 2)" in text
    assert "- ap-1 2x 15 min" in text
    assert "ap-2 1x 30 min" in text and "still down" in text


@respx.mock
def test_operational_events_groups_and_flags_dropped_entries():
    base_routes()
    ops = [
        {"occurredAt": _recent(30), "type": "boot", "deviceName": "ap-1"},
        {"occurredAt": _recent(20), "type": "dfs_event", "deviceName": "ap-2"},
        {"occurredAt": _recent(10), "type": "events_dropped2", "eventData": {"n": "34", "type": "association"}},
    ]
    route = respx.get(f"{BASE}/networks/N_1/events").mock(side_effect=events_by_kind(operational=ops))
    text = server.operational_events(hours=24, top=5)
    assert "- reboot/firmware: boot 2" in text  # one per product type queried
    assert "- radio: dfs_event 2" in text
    assert "- event log: events_dropped2 2" in text
    assert "Dropped by the access points (events_dropped2, events per type): association 68" in text
    assert "events_dropped2" not in text.split("## Newest", 1)[1]
    assert "8021x_radius_timeout" in route.calls[0].request.url.params.get_list("includedEventTypes[]")


@respx.mock
def test_daily_brief_reports_outages_operations_and_trend():
    daily_routes(
        {"assoc": 0, "auth": 1, "dhcp": 9, "dns": 0, "success": 90},
        prev={"assoc": 0, "auth": 1, "dhcp": 2, "dns": 0, "success": 97},
        changes=[change("Q-AP1", "ap-1", _recent(30), "online", "offline"), change("Q-AP1", "ap-1", _recent(20), "offline", "online")],
        ops=[
            {"occurredAt": _recent(5), "type": "8021x_radius_timeout"},
            {"occurredAt": _recent(5), "type": "dfs_event"},
            {"occurredAt": _recent(5), "type": "events_dropped2", "eventData": {"n": "7", "type": "disassociation"}},
        ],
    )
    text = server.daily_brief(hours=24, failure_threshold=50.0, top=3)
    assert "0 OK, 1 WARNING" in text
    assert "[AVAILABILITY] 1 device(s) not online at some point: ap-1 1x 10 min" in text
    assert "(previous 24h: 3.0% failed; biggest change: dhcp +7)" in text
    assert "[OPERATIONS-WARN] 8021x_radius_timeout 2" in text
    assert "[OPERATIONS] dfs_event 2" in text
    assert "[LOG-DROPPED] access points dropped high-volume events: disassociation 14" in text


@respx.mock
def test_long_windows_skip_the_comparison():
    base_routes()
    stats = respx.get(f"{BASE}/networks/N_1/wireless/connectionStats").mock(return_value=httpx.Response(200, json={"success": 1}))
    respx.get(f"{BASE}/networks/N_1/wireless/failedConnections").mock(return_value=httpx.Response(200, json=[]))
    text = server.connection_failures(hours=100, top=3)
    assert "previous" not in text
    assert all("t0" not in c.request.url.params for c in stats.calls)


@respx.mock
def test_device_down_at_window_start_is_not_a_new_outage():
    base_routes()
    respx.get(f"{BASE}/organizations/100/devices/availabilities/changeHistory").mock(
        return_value=httpx.Response(
            200,
            json=[
                change("Q-AP1", "ap-1", _recent(50), "alerting", "offline"),
                change("Q-AP1", "ap-1", _recent(40), "offline", "online"),
            ],
        )
    )
    text = server.availability_history(hours=1, top=5)
    assert "- ap-1 0x 20 min (down at window start" in text
    assert "(left online during the window: 0)" in text


@respx.mock
def test_brief_says_when_availability_history_was_cut():
    daily_routes({"success": 10})
    nxt = f"<{BASE}/organizations/100/devices/availabilities/changeHistory?startingAfter=z>; rel=next"
    respx.get(f"{BASE}/organizations/100/devices/availabilities/changeHistory").mock(
        return_value=httpx.Response(200, json=[], headers={"Link": nxt})
    )
    text = server.daily_brief(hours=24, failure_threshold=10.0, top=3)
    assert "every device stayed online in the 0 status changes read (capped" in text


@respx.mock
def test_daily_brief_stops_starting_networks_after_the_time_budget(monkeypatch):
    monkeypatch.setattr(server, "BRIEF_TIME_BUDGET", -1.0)
    other = {**NET, "id": "N_2", "name": "Other Net"}
    daily_routes({"success": 10})
    respx.get(f"{BASE}/organizations/100/networks").mock(return_value=httpx.Response(200, json=[NET, other]))
    text = server.daily_brief(hours=24, failure_threshold=10.0, top=3)
    assert "1 networks: 1 OK" in text
    assert "capped: 1 more networks not checked" in text


@respx.mock
def test_event_reads_are_capped_by_the_page_start():
    base_routes()
    prev = {"Link": f"<{BASE}/networks/N_1/events?endingBefore=z>; rel=prev"}
    pages = {
        # Not full, but the page starts an hour ago: older events of a 24 h window are unread.
        "wireless": {"events": [{"occurredAt": _recent(5), "type": "rogue_dhcp"}], "pageStartAt": _recent(60)},
        # Not full and reaching back a month: the whole window was read.
        "switch": {"events": [], "pageStartAt": _recent(60 * 24 * 31)},
    }
    respx.get(f"{BASE}/networks/N_1/events").mock(
        side_effect=lambda request: httpx.Response(200, json=pages[request.url.params["productType"]], headers=prev)
    )
    text = server.security_events(hours=24, top=2)
    assert "capped: older wireless events in the window not read" in text


@respx.mock
def test_list_events_treats_an_empty_page_as_the_end():
    base_routes()
    link = f"<{BASE}/networks/N_1/events?productType=switch&endingBefore=2026-10-25T00%3A00%3A00Z>; rel=prev"
    respx.get(f"{BASE}/networks/N_1/events").mock(
        return_value=httpx.Response(200, json={"events": [], "pageStartAt": "2026-10-25T00:00:00Z", "pageEndAt": "2026-11-25T00:00:00Z"}, headers={"Link": link})
    )
    text = server.list_events("switch")
    assert "treated as the end of the log" in text
    assert "complete: true" in text
    assert "older_cursor: endingBefore=" in text


def test_dropped_entries_with_no_count_are_skipped():
    events = [
        {"type": "events_dropped2", "eventData": {"type": "association", "n": 0}},
        {"type": "events_dropped2", "eventData": {"type": "roam"}},
    ]
    assert server._dropped_summary(events) == "roam 1"


@respx.mock
def test_capped_history_counts_down_time_from_the_oldest_change_read():
    base_routes()
    nxt = f"<{BASE}/organizations/100/devices/availabilities/changeHistory?startingAfter=z>; rel=next"
    respx.get(f"{BASE}/organizations/100/devices/availabilities/changeHistory").mock(
        return_value=httpx.Response(
            200,
            json=[change("Q-AP1", "ap-1", _recent(60), "online", "offline"), change("Q-AP2", "ap-2", _recent(30), "offline", "online")],
            headers={"Link": nxt},
        )
    )
    text = server.availability_history(hours=168, top=5)
    assert "ap-2 0x at least 30 min (state at window start unknown" in text


@respx.mock
def test_change_times_without_an_offset_are_read_as_utc():
    base_routes()
    naive = _recent(30).rstrip("Z")
    respx.get(f"{BASE}/organizations/100/devices/availabilities/changeHistory").mock(
        return_value=httpx.Response(200, json=[change("Q-AP2", "ap-2", naive, "online", "offline")])
    )
    text = server.availability_history(hours=24, top=5)
    assert "ap-2 1x 30 min" in text


@respx.mock
def test_daily_brief_stops_a_network_between_steps_after_the_limit(monkeypatch):
    monkeypatch.setattr(server, "BRIEF_STEP_LIMIT", -1.0)
    daily_routes({"success": 10})
    text = server.daily_brief(hours=24, failure_threshold=10.0, top=3)
    assert "[DEVICES]" in text
    assert "the rest of this network was not checked" in text
    assert "[SECURITY]" not in text


@respx.mock
def test_repeated_events_are_folded_into_one_line():
    base_routes()
    same = {"type": "client_ip6_lla_conflict", "deviceName": "ap-1", "clientMac": "aa:01"}
    events = [{**same, "occurredAt": _recent(m)} for m in (1, 2, 3)] + [{"type": "rogue_dhcp", "occurredAt": _recent(4)}]
    respx.get(f"{BASE}/networks/N_1/events").mock(
        side_effect=lambda request: httpx.Response(200, json={"events": events if request.url.params["productType"] == "wireless" else []})
    )
    text = server.security_events(hours=24, top=2)
    assert "## Newest 4 of 4" in text
    assert "back to" in text and "client_ip6_lla_conflict device=ap-1 client=aa:01 (x3)" in text
    assert "rogue_dhcp" in text.split("## Newest", 1)[1]


@respx.mock
def test_unknown_event_types_get_a_hint():
    base_routes()
    respx.get(f"{BASE}/networks/N_1/events/eventTypes").mock(
        return_value=httpx.Response(200, json=[{"category": "DHCP", "type": "rogue_dhcp", "description": "Rogue DHCP server"}])
    )
    respx.get(f"{BASE}/networks/N_1/events").mock(return_value=httpx.Response(200, json={"events": []}))
    text = server.security_events(hours=24, event_types=["rogue_dhpc"])
    assert "Not in this network's event type list, may match nothing: rogue_dhpc (did you mean rogue_dhcp?)" in text
    assert "Not in this network" not in server.security_events(hours=24, event_types=["rogue_dhcp"])


SPEC = {
    "openapi": "3.0.1",
    "paths": {
        "/networks/{networkId}/wireless/ssids": {"get": {"operationId": "getNetworkWirelessSsids", "summary": "List the MR SSIDs in a network", "tags": ["wireless"], "parameters": [{"name": "networkId", "in": "path", "required": True, "schema": {"type": "string"}}]}},
        "/organizations/{organizationId}/devices/statuses": {"get": {"operationId": "getOrganizationDevicesStatuses", "summary": "List the status of every device", "tags": ["organizations"], "parameters": [{"name": "networkIds", "in": "query", "schema": {"type": "array", "items": {"type": "string"}}, "description": "Filter by network"}, {"name": "perPage", "in": "query", "schema": {"type": "integer"}}]}},
        "/organizations/{organizationId}/admins": {"get": {"operationId": "getOrganizationAdmins", "summary": "List the dashboard administrators", "tags": ["organizations"], "parameters": []}},
        "/networks/{networkId}/snmp": {"get": {"operationId": "getNetworkSnmp", "summary": "Return the SNMP settings for a network", "tags": ["networks"]}, "put": {"operationId": "updateNetworkSnmp"}},
    },
}


def spec_route():
    return respx.get(f"{BASE}/organizations/100/openapiSpec").mock(return_value=httpx.Response(200, json=SPEC))


@respx.mock
def test_find_api_searches_and_describes_get_operations():
    base_routes()
    spec_route()
    text = server.find_api("wireless ssids")
    assert text.splitlines()[1].startswith("- getNetworkWirelessSsids — GET /networks/{networkId}/wireless/ssids")
    assert "updateNetworkSnmp" not in server.find_api("snmp")
    detail = server.find_api("getOrganizationDevicesStatuses")
    assert "query `networkIds[]` (array of string)" in detail and "Filter by network" in detail
    assert server.find_api("/networks/N_1/wireless/ssids").startswith("# getNetworkWirelessSsids")


@pytest.mark.parametrize(
    "path",
    [
        "https://evil.example/api",
        "http://evil.example/api",
        "//evil.example/api",
        "evil.example/api",
        "/networks/N_1/../../x",
        "/networks/N_1/%2e%2e/x",
        "/networks/N_1/ssids?x=1",
        "/networks/N_1#frag",
        "/networks/N_1/a b",
        "/networks/user@evil.example",
        "/other/thing",
        "/networks/{networkId}/wireless/ssids",
    ],
)
@respx.mock
def test_api_get_refuses_paths_that_could_leave_the_api(path):
    base_routes()
    with pytest.raises(ToolError):
        server.api_get(path)
    assert not [c for c in respx.calls if "evil" in str(c.request.url) or "/other" in str(c.request.url)]


@respx.mock
def test_api_get_stays_in_scope(monkeypatch):
    other = {**NET, "id": "N_2", "name": "other net"}
    base_routes(nets=(NET, other))
    monkeypatch.setenv("MERAKI_NETWORK_IDS", "N_1")
    respx.get(f"{BASE}/organizations/100/devices").mock(return_value=httpx.Response(200, json=[{**d, "networkId": "N_1"} for d in DEVICES] + [{"serial": "Q-X", "networkId": "N_2"}]))
    spec_route()
    with pytest.raises(ToolError, match="network N_2 is not in scope"):
        server.api_get("/networks/N_2/wireless/ssids")
    with pytest.raises(ToolError, match="organization 999 is not in scope"):
        server.api_get("/organizations/999/admins")
    with pytest.raises(ToolError, match="device Q-X is not in a network in scope"):
        server.api_get("/devices/Q-X")
    with pytest.raises(ToolError, match="cannot be narrowed"):
        server.api_get("/organizations/100/admins")
    with pytest.raises(ToolError, match="network N_2 is not in scope"):
        server.api_get("/organizations/100/devices/statuses", params={"networkIds": ["N_2"]})
    with pytest.raises(ToolError, match="network N_2 is not in scope"):
        server.api_get("/organizations/100/devices/statuses", params={"networkIds": "N_2"})
    statuses = respx.get(f"{BASE}/organizations/100/devices/statuses").mock(return_value=httpx.Response(200, json=[]))
    server.api_get("/organizations/100/devices/statuses")
    assert statuses.calls[0].request.url.params.get_list("networkIds[]") == ["N_1"]
    server.api_get("/organizations/100/devices/statuses", params={"networkIds": "N_1"})
    assert "networkIds" not in statuses.calls[1].request.url.params
    device = respx.get(f"{BASE}/devices/Q-AP1").mock(return_value=httpx.Response(200, json={"serial": "Q-AP1"}))
    assert server.api_get("/devices/Q-AP1")["data"] == {"serial": "Q-AP1", "deviceName": "ap-1"} and device.called


@respx.mock
def test_api_get_masks_secrets_before_shaping():
    base_routes()
    ssids = [
        {"number": 0, "name": "CorpNet", "psk": "hunter2", "authMode": "psk", "radiusServers": [{"host": "10.0.0.1", "secret": "s3"}], "radiusEnabled": True, "encryptionMode": None},
        {"number": 1, "name": "Guest", "notes": '{"wpaPassphrase": "p4"}', "snmpCommunity": ""},
    ]
    respx.get(f"{BASE}/networks/N_1/wireless/ssids").mock(return_value=httpx.Response(200, json=ssids))
    result = server.api_get("/networks/N_1/wireless/ssids", fields=["name", "psk", "radiusServers.secret", "radiusServers.host", "notes"])
    text = str(result)
    assert "hunter2" not in text and "s3" not in text and "p4" not in text
    assert result["redacted"] == 3
    assert result["data"][0] == {"name": "CorpNet", "psk": "[redacted]", "radiusServers": [{"host": "10.0.0.1", "secret": "[redacted]"}]}


@respx.mock
def test_api_get_bounds_a_huge_list_and_returns_paging_params():
    base_routes()
    rows = [{"mac": f"aa:{i:04x}", "ssid": "x" * 400, "bssids": [{"bssid": f"b{j}"} for j in range(30)]} for i in range(500)]
    link = f'<{BASE}/networks/N_1/wireless/airMarshal?startingAfter=abc&perPage=500>; rel=next'
    respx.get(f"{BASE}/networks/N_1/wireless/airMarshal").mock(return_value=httpx.Response(200, json=rows, headers={"Link": link}))
    result = server.api_get("/networks/N_1/wireless/airMarshal", params={"timespan": 3600}, limit=200, max_chars=8000)
    assert result["total_items"] == 500 and result["capped"] is True
    assert len(json.dumps(result)) <= 8000
    assert result["next_params"] == {"startingAfter": "abc"}
    assert result["data"][0]["bssids"][-1].endswith("more items")
    assert result["returned"] == len(result["data"]) < 200


@respx.mock
def test_api_get_keeps_the_whole_answer_within_max_chars():
    base_routes()
    respx.get(f"{BASE}/networks/N_1/clients").mock(return_value=httpx.Response(200, json=[{"k" + str(i): "v" * 50 for i in range(400)}] * 3))
    result = server.api_get("/networks/N_1/clients", params={"description": "x" * 5000, "mac": ["y" * 300] * 50}, max_chars=2000)
    assert len(json.dumps(result, ensure_ascii=False)) <= 2000 and result["capped"] is True


@respx.mock
def test_api_get_refuses_administered_reads_under_a_scope(monkeypatch):
    base_routes()
    monkeypatch.setenv("MERAKI_ORG_ID", "100")
    with pytest.raises(ToolError, match="/administered reads cannot be narrowed"):
        server.api_get("/administered/licensing/subscription/subscriptions")
    me = respx.get(f"{BASE}/administered/identities/me").mock(return_value=httpx.Response(200, json={"name": "x"}))
    server.api_get("/administered/identities/me")
    assert me.called


@respx.mock
def test_api_get_wants_network_id_strings(monkeypatch):
    base_routes()
    spec_route()
    monkeypatch.setenv("MERAKI_NETWORK_IDS", "N_1")
    with pytest.raises(ToolError, match="network ID strings"):
        server.api_get("/organizations/100/devices/statuses", params={"networkIds": 5})


@respx.mock
def test_api_get_lists_only_organizations_in_scope(monkeypatch):
    respx.get(f"{BASE}/organizations").mock(return_value=httpx.Response(200, json=[ORG, {"id": "200", "name": "Other"}]))
    monkeypatch.setenv("MERAKI_ORG_ID", "100")
    result = server.api_get("/organizations", fields=["id"])
    assert result["data"] == [{"id": "100"}] and result["total_items"] == 1


@respx.mock
def test_api_get_windows_the_list_inside_an_object():
    base_routes()
    body = {"message": None, "pageStartAt": "x", "events": [{"type": "boot", "n": i} for i in range(30)]}
    respx.get(f"{BASE}/networks/N_1/events").mock(return_value=httpx.Response(200, json=body))
    result = server.api_get("/networks/N_1/events", fields=["n"], offset=5, limit=3)
    assert result["list_key"] == "events" and result["total_items"] == 30 and result["capped"] is True
    assert result["data"] == {"message": None, "pageStartAt": "x", "events": [{"n": 5}, {"n": 6}, {"n": 7}]}


@respx.mock
def test_api_get_takes_json_strings_pages_and_names_serials():
    base_routes()
    first = [{"serial": "Q-AP1", "x": 1}, {"serial": "Q-AP2", "x": 2}]
    link = f'<{BASE}/organizations/100/devices/statuses?startingAfter=Q-AP2>; rel=next'
    route = respx.get(f"{BASE}/organizations/100/devices/statuses").mock(
        side_effect=lambda r: httpx.Response(200, json=[{"serial": "Q-SW1", "x": 3}])
        if r.url.params.get("startingAfter")
        else httpx.Response(200, json=first, headers={"Link": link})
    )
    result = server.api_get("/organizations/100/devices/statuses", params='{"perPage": 2}', fields='["serial"]', max_pages=3)
    assert route.call_count == 2 and result["pages_read"] == 2 and result["has_next_page"] is False
    assert result["total_items"] == 3 and result["observed_at"].endswith("Z")
    assert result["data"] == [{"serial": "Q-AP1", "deviceName": "ap-1"}, {"serial": "Q-AP2", "deviceName": "ap-2"}, {"serial": "Q-SW1", "deviceName": "sw-1"}]
    with pytest.raises(ToolError, match="params must be a JSON object"):
        server.api_get("/networks/N_1/clients", params="perPage=2")


@respx.mock
def test_find_api_keeps_its_index_between_processes():
    base_routes()
    spec = spec_route()
    server.find_api("wireless ssids")
    server._cache.clear()  # a new process
    assert server.find_api("snmp").splitlines()[1].startswith("- getNetworkSnmp")
    assert spec.call_count == 1
    respx.get(f"{BASE}/networks/N_1/wireless/ssids").mock(return_value=httpx.Response(200, json=[]))
    assert server.api_get("/networks/N_1/wireless/ssids")["operation"] == "getNetworkWirelessSsids"


@respx.mock
def test_health_check_lists_ids_for_api_get():
    base_routes()
    respx.get(f"{BASE}/organizations/100/devices/statuses/overview").mock(return_value=httpx.Response(200, json={"counts": {"byStatus": {"online": 3}}}))
    result = server.health_check()
    assert result["organization_list"] == [{"id": "100", "name": "Example Org"}]
    assert result["network_list"] == [{"id": "N_1", "name": "Example Net", "products": ["switch", "wireless"]}]


@respx.mock
def test_resolve_entity_finds_networks_and_devices():
    base_routes()
    respx.get(f"{BASE}/organizations/100/devices").mock(return_value=httpx.Response(200, json=[
        {"serial": "Q-AP1", "name": "ap-1", "model": "CW9174I", "mac": "aa:bb:cc:00:00:01", "lanIp": "10.0.0.11", "networkId": "N_1"},
        {"serial": "Q-ZZ", "name": "ap-out", "mac": "aa:bb:cc:00:00:09", "networkId": "N_9"},
    ]))
    text = server.resolve_entity("AABB.CC00.0001")
    assert "- ap-1: serial Q-AP1, CW9174I, MAC aa:bb:cc:00:00:01, LAN IP 10.0.0.11, network Example Net (N_1)" in text
    assert "ap-out" not in server.resolve_entity("ap")
    assert "networkId N_1" in server.resolve_entity("example")
    assert "find_client" in server.resolve_entity("10.9.9.9")


@respx.mock
def test_find_client_by_mac_shows_record_and_wireless_history():
    base_routes()
    respx.get(f"{BASE}/organizations/100/clients/search").mock(return_value=httpx.Response(200, json={
        "clientId": "k1", "mac": "11:22:33:44:55:66", "manufacturer": "Acme",
        "records": [{"network": {"id": "N_1"}, "ip": "10.1.1.5", "ssid": "CorpNet", "lastSeen": 1795600000}],
    }))
    respx.get(f"{BASE}/networks/N_1/clients/k1").mock(return_value=httpx.Response(200, json={
        "id": "k1", "mac": "11:22:33:44:55:66", "ip": "10.1.1.5", "vlan": 10, "ssid": "CorpNet", "user": "u1",
        "recentDeviceSerial": "Q-AP1", "status": "Online", "lastSeen": 1795600000, "notes": '{"psk": "x"}',
    }))
    respx.get(f"{BASE}/networks/N_1/wireless/clients/k1/connectionStats").mock(return_value=httpx.Response(200, json={"connectionStats": {"assoc": 0, "auth": 0, "dhcp": 2, "dns": 0, "success": 8}}))
    respx.get(f"{BASE}/networks/N_1/wireless/clients/k1/connectivityEvents").mock(return_value=httpx.Response(200, json=[
        {"type": "association", "severity": "info", "deviceSerial": "Q-AP1", "rssi": 40, "occurredAt": "2026-11-25T01:00:00Z"},
        {"type": "dhcp", "subtype": "dhcp_timeout", "severity": "bad", "deviceSerial": "Q-AP2", "rssi": 12, "occurredAt": "2026-11-25T02:00:00Z", "band": "5", "channel": 36},
    ]))
    respx.get(f"{BASE}/networks/N_1/wireless/clients/k1/latencyStats").mock(return_value=httpx.Response(200, json={"latencyStats": {"bestEffortTraffic": {"avg": 4.25}}}))
    text = server.find_client("11-22-33-44-55-66", hours=24)
    assert "matched by MAC" in text and "VLAN 10" in text and "User u1" in text and "Last connected to ap-1" in text
    assert "20.0% failed" in text and "By access point: ap-1 1 (RSSI 40..40 dB), ap-2 1" in text
    assert "11:00 dhcp/dhcp_timeout (bad) at ap-2" in text or "dhcp/dhcp_timeout (bad) at ap-2" in text
    assert "average 4.2 ms" in text or "average 4.3 ms" in text


@respx.mock
def test_find_client_by_name_scans_a_bounded_list():
    base_routes()
    rows = [{"id": f"k{i}", "mac": f"00:00:00:00:00:{i:02x}", "user": "alice" if i == 3 else "bob", "lastSeen": i} for i in range(10)]
    respx.get(f"{BASE}/networks/N_1/clients").mock(return_value=httpx.Response(200, json=rows))
    respx.get(f"{BASE}/networks/N_1/clients/k3").mock(return_value=httpx.Response(200, json={**rows[3], "ssid": None}))
    text = server.find_client("ALICE")
    assert "among 10 clients of the last 1h" in text and "User alice" in text


@respx.mock
def test_find_client_by_ip_keeps_only_the_exact_address():
    base_routes()
    rows = [{"id": "k1", "mac": "m1", "ip": "10.0.0.95", "lastSeen": 2}, {"id": "k2", "mac": "m2", "ip": "10.0.0.9", "lastSeen": 1}]
    respx.get(f"{BASE}/networks/N_1/clients").mock(return_value=httpx.Response(200, json=rows))
    respx.get(f"{BASE}/networks/N_1/clients/k2").mock(return_value=httpx.Response(200, json={**rows[1], "recentDeviceSerial": "Q-AP2"}))
    text = server.find_client("10.0.0.9")
    assert "clients matched" not in text and "IP 10.0.0.9," in text and "Last connected to ap-2" in text


def test_other_serial_keys_get_a_name(monkeypatch):
    monkeypatch.setattr(server, "_organizations", lambda: [ORG])
    monkeypatch.setattr(server, "_networks", lambda: [NET])
    monkeypatch.setattr(server, "_devices", lambda org: ([{"serial": "Q-AP1", "name": "ap-1", "networkId": "N_1"}], False))
    assert server._name_serials([{"recentDeviceSerial": "Q-AP1"}, {"deviceSerial": "Q-AP1"}]) == [
        {"recentDeviceSerial": "Q-AP1", "recentDeviceName": "ap-1"}, {"deviceSerial": "Q-AP1", "deviceName": "ap-1"}]


def test_device_names_stay_in_the_network_scope(monkeypatch):
    monkeypatch.setattr(server, "_organizations", lambda: [ORG])
    monkeypatch.setattr(server, "_networks", lambda: [NET])
    monkeypatch.setattr(server, "_devices", lambda org: ([{"serial": "Q-IN", "name": "in", "networkId": "N_1"}, {"serial": "Q-OUT", "name": "out", "networkId": "N_9"}], False))
    assert server._name_serials([{"serial": "Q-IN"}, {"serial": "Q-OUT"}]) == [{"serial": "Q-IN", "deviceName": "in"}, {"serial": "Q-OUT"}]


@respx.mock
def test_api_get_follows_pages_with_the_next_cursor_only_and_keeps_pages_read_before_an_error():
    base_routes()
    calls = []

    def answer(request):
        calls.append(dict(request.url.params))
        if "startingAfter" in request.url.params:
            return httpx.Response(400, json={"errors": ["bad page"]})
        return httpx.Response(200, json=[{"x": 1}], headers={"Link": f'<{BASE}/networks/N_1/clients?startingAfter=z>; rel=next'})

    respx.get(f"{BASE}/networks/N_1/clients").mock(side_effect=answer)
    result = server.api_get("/networks/N_1/clients", params={"endingBefore": "a", "timespan": 60}, max_pages=3)
    assert calls[1] == {"timespan": "60", "startingAfter": "z"}
    assert result["data"] == [{"x": 1}] and "page_error" in result and result["pages_read"] == 1


@respx.mock
def test_api_get_answers_without_an_index_when_no_organization_is_visible():
    respx.get(f"{BASE}/organizations").mock(return_value=httpx.Response(200, json=[]))
    respx.get(f"{BASE}/networks").mock(return_value=httpx.Response(200, json=[]))
    respx.get(f"{BASE}/administered/identities/me").mock(return_value=httpx.Response(200, json={"name": "me"}))
    assert server.api_get("/administered/identities/me")["data"] == {"name": "me"}


@respx.mock
def test_find_client_by_ip_reads_further_pages_for_the_exact_address():
    base_routes()
    link = f'<{BASE}/networks/N_1/clients?startingAfter=p2>; rel=next'
    respx.get(f"{BASE}/networks/N_1/clients").mock(side_effect=lambda r: httpx.Response(200, json=[{"id": "k2", "mac": "m2", "ip": "10.0.0.9", "lastSeen": 1}])
        if r.url.params.get("startingAfter") else httpx.Response(200, json=[{"id": "k1", "mac": "m1", "ip": "10.0.0.95"}], headers={"Link": link}))
    respx.get(f"{BASE}/networks/N_1/clients/k2").mock(return_value=httpx.Response(200, json={"id": "k2", "mac": "m2", "ip": "10.0.0.9"}))
    assert "IP 10.0.0.9," in server.find_client("10.0.0.9")


def test_change_log_values_are_masked_when_the_label_names_a_secret():
    rows = [
        {"page": "Access control", "label": "Ssid psk", "oldValue": "old-secret", "newValue": "new-secret"},
        {"page": "SNMP", "label": "Community string", "oldValue": "c1", "newValue": "c2"},
        {"page": "Access Points", "label": "Device address", "oldValue": "a", "newValue": "b"},
    ]
    counter = [0]
    out = server._redact(rows, counter)
    assert out[0]["oldValue"] == out[0]["newValue"] == out[1]["newValue"] == "[redacted]"
    assert out[2]["newValue"] == "b" and counter[0] == 4


@respx.mock
def test_config_changes_lists_entries_with_secrets_masked():
    daily_routes({})
    text = server.config_changes(hours=48, top=5)
    assert "Entries: 2 (1 organization-wide)" in text and "Elsewhere" not in text
    assert "alice — Example Net / SSID CorpNet — Access control: Ssid psk: [redacted] → [redacted]" in text
    assert "… (300 chars)" in text


@respx.mock
def test_daily_brief_warns_on_a_subscription_ending_soon():
    daily_routes({"assoc": 0, "auth": 0, "dhcp": 0, "dns": 0, "success": 10})
    respx.get(f"{BASE}/organizations").mock(return_value=httpx.Response(200, json=[{**ORG, "licensing": {"model": "subscription"}}]))
    soon = _recent(-60 * 24 * 10)
    respx.get(f"{BASE}/administered/licensing/subscription/subscriptions").mock(return_value=httpx.Response(200, json=[
        {"name": "SUB1", "status": "active", "endDate": soon, "counts": {"seats": {"assigned": 3, "limit": 5}}}]))
    text = server.daily_brief(hours=24, failure_threshold=10.0, top=3)
    assert "[LICENSE-EXPIRING] SUB1 active until" in text and "seats 3/5" in text and "1 WARNING" in text


def test_config_changes_says_capped(monkeypatch):
    monkeypatch.setattr(server, "_one_network", lambda n: NET)
    monkeypatch.setattr(server, "_org_changes", lambda org, h: ([dict(CHANGES[0])], True))
    assert "capped: older entries in the window not read" in server.config_changes()


@respx.mock
def test_change_log_paging_stops_when_a_page_only_repeats():
    base_routes()
    link = {"Link": f'<{BASE}/organizations/100/configurationChanges?startingAfter=z>; rel=next'}
    respx.get(f"{BASE}/organizations/100/configurationChanges").mock(side_effect=lambda r: httpx.Response(200, json=CHANGES[1:2], headers=link)
        if r.url.params.get("startingAfter") else httpx.Response(200, json=CHANGES, headers=link))
    rows, capped = server._org_changes("100", 24)
    assert len(rows) == 3 and capped is False
