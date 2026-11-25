"""Allow running as: python -m merakiadm_mcp"""

from __future__ import annotations

import argparse
import os
import sys

from merakiadm_mcp import __version__
from merakiadm_mcp.client import MerakiAPIError, MerakiClientError
from merakiadm_mcp.server import _networks, _organizations, mcp


def _check_config() -> int:
    """Verify the API key and list what it can see."""
    try:
        orgs = _organizations()
        nets = _networks()
    except MerakiClientError as e:
        print(f"Configuration error: {e}", file=sys.stderr)
        return 1
    except MerakiAPIError as e:
        print(f"API error: {e}", file=sys.stderr)
        return 2
    print(f"OK: {len(orgs)} organization(s), {len(nets)} network(s) in scope")
    return 0


def main() -> None:
    """Entry point for console_scripts."""
    parser = argparse.ArgumentParser(
        prog="merakiadm-mcp",
        description=(
            "Read-only MCP server for Cisco Meraki Dashboard administrators. "
            "Runs a STDIO JSON-RPC server exposing bounded device, connection, "
            "Air Marshal and event summaries to AI assistants."
        ),
        epilog=(
            "Required environment variable: MERAKI_DASHBOARD_API_KEY. "
            "Optional: MERAKI_ORG_ID, MERAKI_NETWORK_IDS, MERAKI_BASE_URL."
        ),
    )
    parser.add_argument("-V", "--version", action="version", version=f"%(prog)s {__version__}")
    parser.add_argument(
        "--check",
        action="store_true",
        help="Verify the API key and print how many organizations and networks it can read, then exit.",
    )
    args = parser.parse_args()

    if args.check:
        sys.exit(_check_config())

    try:
        mcp.run(transport="stdio")
    except KeyboardInterrupt:
        # Bypass normal interpreter shutdown: the stdio reader runs in a daemon
        # thread blocked on sys.stdin, and joining it at shutdown can crash with
        # "_enter_buffered_busy" on Python 3.14.
        os._exit(0)


if __name__ == "__main__":
    main()
