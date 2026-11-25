"""Probe specs for this server's tools — the Meraki-specific half of the smoke test.

Every registered tool needs an entry here (the harness fails on a tool with no
spec), so adding a tool forces a decision: how would we know it works?

**Read-only.** Every tool here reads; nothing in the Dashboard is changed.

**No deployment-specific values in this file.** This repository is public, so a
probe may not name a network, a device or an SSID. Tools that need one network
get none: with a single network in scope they pick it themselves, and with
several the probe is skipped by ``_single_network`` rather than guessing.

**Bounded.** Every tool takes a window and a count; each probe passes small
explicit ones (an hour of Air Marshal is already hundreds of KB at a busy site).

Assertions pin the header line each tool renders. ``daily_brief`` catches its
own failures and reports them in the text, so its probe also refuses the
error markers.
"""

from __future__ import annotations

from typing import Any

from smoke_harness import Caller, Probe, SkipProbe

#: Tools registered only with extra configuration. None today.
OPT_IN_TOOLS: frozenset[str] = frozenset()

NO_ERROR = (r"^(Error|Failed|Invalid)", r"\[API-ERROR\]")


async def _single_network(call: Caller) -> dict[str, Any]:
    """Skip the per-network tools when several networks are in scope."""
    health = await call("health_check", {})
    if isinstance(health, dict) and int(health.get("networks") or 0) != 1:
        raise SkipProbe("several networks in scope; set MERAKI_NETWORK_IDS to one network to probe these tools")
    return {}


PROBES: dict[str, Probe] = {
    "health_check": Probe(
        require_keys=("status", "service", "devices"),
        must_match=(r'"status": "(healthy|degraded)"',),
        allow_empty=True,
    ),
    "daily_brief": Probe(
        args={"hours": 24, "top": 3, "failure_threshold": 10.0},
        must_match=(r"^## daily_brief — ",),
        must_not_match=(*NO_ERROR, r"^## CRITICAL — API error:"),
        timeout=300,
    ),
    "connection_failures": Probe(
        args_factory=_single_network,
        args={"hours": 1, "top": 3},
        must_match=(r"^# Connection failures — ",),
        must_not_match=NO_ERROR,
        timeout=120,
    ),
    "wireless_quality": Probe(
        args_factory=_single_network,
        args={"hours": 1, "top": 3},
        must_match=(r"^# Wireless quality — ",),
        must_not_match=NO_ERROR,
        timeout=120,
    ),
    "find_api": Probe(
        args={"query": "wireless ssids", "top": 3},
        must_match=(r"^# API operations matching ",),
        must_not_match=NO_ERROR,
        timeout=120,
    ),
    "api_get": Probe(
        args={"path": "/organizations", "fields": ["id", "name"], "limit": 3, "max_chars": 4000},
        require_keys=("path", "total_items", "capped", "data"),
        must_not_match=NO_ERROR,
        timeout=60,
    ),
    "air_marshal": Probe(
        args_factory=_single_network,
        args={"hours": 1, "top": 3},
        must_match=(r"^# Air Marshal — ",),
        must_not_match=NO_ERROR,
        timeout=120,
    ),
    "security_events": Probe(
        args_factory=_single_network,
        args={"hours": 24, "top": 3},
        must_match=(r"^# Security events — ",),
        must_not_match=NO_ERROR,
        timeout=120,
    ),
    "operational_events": Probe(
        args_factory=_single_network,
        args={"hours": 24, "top": 3},
        must_match=(r"^# Operational events — ",),
        must_not_match=NO_ERROR,
        timeout=120,
    ),
    "availability_history": Probe(
        args_factory=_single_network,
        args={"hours": 24, "top": 3},
        must_match=(r"^# Availability history — ",),
        must_not_match=NO_ERROR,
    ),
    "list_events": Probe(
        args_factory=_single_network,
        args={"product_type": "wireless", "per_page": 5},
        must_match=(r"^# Events — ",),
        must_not_match=NO_ERROR,
    ),
}
