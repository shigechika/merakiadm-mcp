"""MerakiClient: auth header, Link parsing, redirects, retries, errors."""

from __future__ import annotations

import httpx
import pytest
import respx

from merakiadm_mcp.client import MerakiAPIError, MerakiClient, MerakiClientError, parse_cursor

BASE = "https://api.meraki.com/api/v1"


def make(**kw) -> MerakiClient:
    return MerakiClient("test-key", **kw)


def test_missing_key_is_a_configuration_error():
    with pytest.raises(MerakiClientError):
        MerakiClient("")


@respx.mock
def test_get_sends_bearer_and_returns_body():
    route = respx.get(f"{BASE}/organizations").mock(return_value=httpx.Response(200, json=[{"id": "1"}]))
    assert make().get("/organizations") == [{"id": "1"}]
    assert route.calls[0].request.headers["Authorization"] == "Bearer test-key"


@respx.mock
def test_link_header_becomes_cursors_with_only_paging_params():
    link = (
        f'<{BASE}/networks/N/events?productType=wireless&perPage=5&endingBefore=2026-01-01T00%3A00%3A00Z>; rel=prev, '
        f'<{BASE}/networks/N/events?productType=wireless&startingAfter=abc&evil=1>; rel=next'
    )
    respx.get(f"{BASE}/networks/N/events").mock(return_value=httpx.Response(200, json={"events": []}, headers={"Link": link}))
    page = make().page("/networks/N/events")
    assert page.links["prev"] == {"endingBefore": "2026-01-01T00:00:00Z"}
    assert page.links["next"] == {"startingAfter": "abc"}
    assert parse_cursor(page.cursor("prev")) == {"endingBefore": "2026-01-01T00:00:00Z"}


def test_parse_cursor_drops_unknown_params():
    assert parse_cursor("startingAfter=x&productType=switch&perPage=999") == {"startingAfter": "x"}
    assert parse_cursor(None) == {}


@respx.mock
def test_redirect_to_meraki_host_keeps_auth():
    respx.get(f"{BASE}/organizations").mock(
        return_value=httpx.Response(307, headers={"Location": "https://n1.meraki.com/api/v1/organizations"})
    )
    shard = respx.get("https://n1.meraki.com/api/v1/organizations").mock(return_value=httpx.Response(200, json=[]))
    assert make().get("/organizations") == []
    assert shard.calls[0].request.headers["Authorization"] == "Bearer test-key"


@respx.mock
def test_redirect_to_other_host_is_refused():
    respx.get(f"{BASE}/organizations").mock(
        return_value=httpx.Response(302, headers={"Location": "https://attacker.example/steal"})
    )
    with pytest.raises(MerakiAPIError, match="refused redirect"):
        make().get("/organizations")


@respx.mock
def test_rate_limit_is_retried_after_retry_after(monkeypatch):
    sleeps = []
    monkeypatch.setattr("merakiadm_mcp.client.time.sleep", sleeps.append)
    respx.get(f"{BASE}/organizations").mock(
        side_effect=[httpx.Response(429, headers={"Retry-After": "1"}), httpx.Response(200, json=[])]
    )
    assert make().get("/organizations") == []
    assert sleeps == [1.0]


@respx.mock
def test_rate_limit_gives_up_within_budget(monkeypatch):
    monkeypatch.setattr("merakiadm_mcp.client.time.sleep", lambda s: None)
    respx.get(f"{BASE}/organizations").mock(return_value=httpx.Response(429, headers={"Retry-After": "1"}))
    with pytest.raises(MerakiAPIError) as exc:
        make(max_retries=2).get("/organizations")
    assert exc.value.status == 429


@respx.mock
def test_error_body_is_reported_without_the_key():
    respx.get(f"{BASE}/organizations").mock(return_value=httpx.Response(401, json={"errors": ["Invalid API key"]}))
    with pytest.raises(MerakiAPIError) as exc:
        make().get("/organizations")
    assert "Invalid API key" in str(exc.value)
    assert "test-key" not in str(exc.value)


@respx.mock
def test_plain_http_redirect_is_refused_even_to_meraki():
    respx.get(f"{BASE}/organizations").mock(
        return_value=httpx.Response(302, headers={"Location": "http://n1.meraki.com/api/v1/organizations"})
    )
    with pytest.raises(MerakiAPIError, match="refused redirect to http://"):
        make().get("/organizations")


@respx.mock
def test_get_all_follows_next_within_budget():
    nxt = f'<{BASE}/organizations/1/devices?startingAfter=b>; rel=next'
    respx.get(f"{BASE}/organizations/1/devices").mock(
        side_effect=[
            httpx.Response(200, json=[{"serial": "a"}], headers={"Link": nxt}),
            httpx.Response(200, json=[{"serial": "b"}], headers={"Link": nxt}),
        ]
    )
    items, capped = make().get_all("/organizations/1/devices", {"perPage": 1}, max_pages=2)
    assert [i["serial"] for i in items] == ["a", "b"]
    assert capped is True


@respx.mock
def test_redirect_without_location_is_refused():
    respx.get(f"{BASE}/organizations").mock(return_value=httpx.Response(302))
    with pytest.raises(MerakiAPIError, match="without a Location"):
        make().get("/organizations")
