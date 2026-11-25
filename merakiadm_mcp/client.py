"""Read-only HTTP client for the Cisco Meraki Dashboard API v1.

Only GET is implemented. Pagination metadata (the ``Link`` header) is kept and
returned to the caller instead of being followed automatically, so every tool
decides how much it reads and can say when it stopped early.
"""

from __future__ import annotations

import logging
import time
import urllib.parse
from dataclasses import dataclass, field
from typing import Any

import httpx

DEFAULT_BASE_URL = "https://api.meraki.com/api/v1"

#: Query parameters a continuation cursor may carry. Anything else in a
#: cursor is dropped, so a cursor cannot smuggle other parameters into a call.
CURSOR_PARAMS = ("startingAfter", "endingBefore", "t0", "t1")

# The API key travels in a header; keep httpx's own request logging quiet so a
# debug configuration cannot print URLs and headers.
logging.getLogger("httpx").setLevel(logging.WARNING)
logging.getLogger("httpcore").setLevel(logging.WARNING)


class MerakiClientError(Exception):
    """Configuration or transport problem (no API answer to report)."""


class MerakiAPIError(Exception):
    """The Dashboard API answered with an error status."""

    def __init__(self, status: int, message: str, path: str):
        self.status = status
        self.path = path
        super().__init__(f"Meraki API {status} on {path}: {message}")


@dataclass
class Page:
    """One API answer plus the paging links that came with it."""

    data: Any
    #: rel -> query parameters of that link, restricted to CURSOR_PARAMS.
    links: dict[str, dict[str, str]] = field(default_factory=dict)
    size: int = 0

    def cursor(self, rel: str) -> str | None:
        """An opaque continuation cursor for ``rel`` ("next" / "prev"), or None."""
        params = self.links.get(rel)
        return urllib.parse.urlencode(params) if params else None


def parse_cursor(cursor: str | None) -> dict[str, str]:
    """Turn a cursor made by Page.cursor back into query parameters."""
    if not cursor:
        return {}
    parsed = urllib.parse.parse_qs(cursor, keep_blank_values=False)
    return {k: v[0] for k, v in parsed.items() if k in CURSOR_PARAMS and v}


def _parse_links(header: str) -> dict[str, dict[str, str]]:
    links: dict[str, dict[str, str]] = {}
    for part in header.split(","):
        if ";" not in part:
            continue
        url_part, *attrs = part.split(";")
        url = url_part.strip().strip("<>")
        rel = ""
        for attr in attrs:
            key, _, value = attr.strip().partition("=")
            if key == "rel":
                rel = value.strip('"')
        if not rel:
            continue
        query = urllib.parse.parse_qs(urllib.parse.urlsplit(url).query)
        links[rel] = {k: v[0] for k, v in query.items() if k in CURSOR_PARAMS and v}
    return links


def _error_message(response: httpx.Response) -> str:
    try:
        body = response.json()
    except ValueError:
        return (response.text or "").strip()[:300] or response.reason_phrase
    if isinstance(body, dict) and isinstance(body.get("errors"), list):
        return "; ".join(str(e) for e in body["errors"])[:300]
    return str(body)[:300]


class MerakiClient:
    """GET-only Dashboard API client with rate-limit backoff.

    Redirects are followed by hand and only to Meraki hosts: httpx drops the
    Authorization header on a cross-host redirect, and the Dashboard API may
    redirect an organization to its shard.
    """

    def __init__(
        self,
        api_key: str,
        base_url: str = DEFAULT_BASE_URL,
        timeout: float = 30.0,
        max_retries: int = 4,
        retry_budget: float = 30.0,
    ):
        if not api_key:
            raise MerakiClientError("MERAKI_DASHBOARD_API_KEY is not set")
        self.base_url = base_url.rstrip("/")
        self._max_retries = max_retries
        self._retry_budget = retry_budget
        self._http = httpx.Client(
            timeout=timeout,
            follow_redirects=False,
            headers={
                "Authorization": f"Bearer {api_key}",
                "Accept": "application/json",
                "User-Agent": "merakiadm-mcp",
            },
        )

    def close(self) -> None:
        self._http.close()

    def page(self, path: str, params: dict[str, Any] | None = None) -> Page:
        """GET one page of ``path``; never follows pagination links."""
        url = path if path.startswith("http") else f"{self.base_url}{path}"
        started = time.monotonic()
        attempt = 0
        redirects = 0
        while True:
            response = self._http.get(url, params=params)
            if response.status_code in (301, 302, 303, 307, 308):
                location = urllib.parse.urljoin(url, response.headers.get("Location", ""))
                target = urllib.parse.urlsplit(location)
                host = target.hostname or ""
                trusted = target.scheme == "https" and (host == "meraki.com" or host.endswith(".meraki.com"))
                if redirects >= 3 or not trusted:
                    raise MerakiAPIError(response.status_code, f"refused redirect to {target.scheme}://{host or '?'}", path)
                url, params, redirects = location, None, redirects + 1
                continue
            if response.status_code == 429 or response.status_code >= 500:
                attempt += 1
                wait = _retry_after(response, attempt)
                if attempt > self._max_retries or time.monotonic() - started + wait > self._retry_budget:
                    raise MerakiAPIError(response.status_code, _error_message(response), path)
                time.sleep(wait)
                continue
            if response.status_code >= 400:
                raise MerakiAPIError(response.status_code, _error_message(response), path)
            content = response.content
            data = response.json() if content else None
            return Page(data=data, links=_parse_links(response.headers.get("Link", "")), size=len(content))

    def get(self, path: str, params: dict[str, Any] | None = None) -> Any:
        """GET one page of ``path`` and return only its body."""
        return self.page(path, params).data

    def get_all(self, path: str, params: dict[str, Any] | None = None, max_pages: int = 10) -> tuple[list, bool]:
        """Follow ``rel=next`` for at most ``max_pages`` pages of a list endpoint.

        Returns (items, capped); capped is True when a next page was left unread.
        """
        items: list = []
        query = dict(params or {})
        for _ in range(max_pages):
            page = self.page(path, query)
            data = page.data
            items.extend((data.get("items") or []) if isinstance(data, dict) else (data or []))
            nxt = page.links.get("next")
            if not nxt:
                return items, False
            query = {**(params or {}), **nxt}
        return items, True


def _retry_after(response: httpx.Response, attempt: int) -> float:
    try:
        return max(0.5, float(response.headers.get("Retry-After", "")))
    except ValueError:
        return min(8.0, 0.5 * 2 ** attempt)
