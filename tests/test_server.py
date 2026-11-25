"""Tools against a mocked Dashboard: aggregation, bounds, capped markers."""

from __future__ import annotations

import asyncio

import httpx
import pytest
import respx

from mcp.server.mcpserver.exceptions import ToolError

from merakiadm_mcp import server

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
    {"serial": "Q-AP1", "name": "ap-1", "productType": "wireless"},
    {"serial": "Q-AP2", "name": "ap-2", "productType": "wireless"},
    {"serial": "Q-SW1", "name": "sw-1", "productType": "switch"},
]
SSIDS = [
    {"number": 0, "name": "CorpNet", "enabled": True},
    {"number": 1, "name": "Guest", "enabled": True},
    {"number": 2, "name": "Unused", "enabled": False},
]


@pytest.fixture(autouse=True)
def fresh(monkeypatch):
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
    event = {
        "occurredAt": "2026-11-13T14:49:22Z",
        "type": "multiple_dhcp_servers_detected",
        "deviceName": "ap-1",
        "ssidNumber": 0,
        "eventData": {"server_ip": "192.0.2.1"},
    }
    route = respx.get(f"{BASE}/networks/N_1/events").mock(return_value=httpx.Response(200, json={"events": [event]}))
    text = server.security_events(hours=24, top=5)
    assert "- Total: 2" in text  # the mock answers once per product type queried
    assert "multiple_dhcp_servers_detected 2" in text
    assert "11-13 23:49 multiple_dhcp_servers_detected device=ap-1 ssid=CorpNet" in text
    assert "192.0.2.1" in text
    params = route.calls[0].request.url.params
    assert "ra_blocked" in params.get_list("includedEventTypes[]")
    assert {c.request.url.params["productType"] for c in route.calls} == {"switch", "wireless"}


@respx.mock
def test_security_events_marks_capped_pages():
    base_routes()
    events = [{"occurredAt": "2026-11-13T14:49:22Z", "type": "client_ip_conflict"}] * 1000
    respx.get(f"{BASE}/networks/N_1/events").mock(
        return_value=httpx.Response(200, json={"events": events}, headers={"Link": f"<{BASE}/networks/N_1/events?startingAfter=z>; rel=next"})
    )
    text = server.security_events(hours=24, top=2)
    assert "capped: more exist for wireless, switch" in text
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


def daily_routes(stats, events=(), ports=None, avail=None):
    base_routes()
    respx.get(f"{BASE}/organizations/100/devices/availabilities").mock(
        return_value=httpx.Response(200, json=avail if avail is not None else [{"name": d["name"], "serial": d["serial"], "status": "online"} for d in DEVICES])
    )
    respx.get(f"{BASE}/networks/N_1/health/alerts").mock(return_value=httpx.Response(200, json=[]))
    respx.get(f"{BASE}/networks/N_1/wireless/connectionStats").mock(return_value=httpx.Response(200, json=stats))
    respx.get(f"{BASE}/networks/N_1/wireless/failedConnections").mock(return_value=httpx.Response(200, json=failed_rows()))
    respx.get(f"{BASE}/networks/N_1/events").mock(return_value=httpx.Response(200, json={"events": list(events)}))
    respx.get(f"{BASE}/organizations/100/switch/ports/statuses/bySwitch").mock(
        return_value=httpx.Response(200, json={"items": ports if ports is not None else [{"name": "sw-1", "ports": [{"portId": "49", "isUplink": True, "status": "Connected", "enabled": True}]}], "meta": {}})
    )


@respx.mock
def test_daily_brief_ok():
    daily_routes({"assoc": 0, "auth": 1, "dhcp": 1, "dns": 0, "success": 98})
    text = server.daily_brief(hours=24, failure_threshold=10.0, top=3)
    assert text.startswith("## daily_brief — ")
    assert "1 networks: 1 OK, 0 WARNING, 0 CRITICAL" in text
    assert "[SECURITY] none" in text
    assert "[UPLINK] 1 switches, 1 uplink ports, none down" in text


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
    clat = {"type": "client_ip_conflict", "eventData": {"ip": "192.0.0.2"}}
    respx.get(f"{BASE}/networks/N_1/events").mock(
        return_value=httpx.Response(200, json={"events": [clat] * 1000}, headers={"Link": f"<{BASE}/networks/N_1/events?startingAfter=z>; rel=next"})
    )
    text = server.daily_brief(hours=24, failure_threshold=10.0, top=3)
    assert "[SECURITY] none (capped: more wireless, switch events not read)" in text
