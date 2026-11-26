"""Release metadata the registries check only at publish time."""

from __future__ import annotations

import json
import pathlib

ROOT = pathlib.Path(__file__).resolve().parent.parent


def test_server_json_fits_the_registry_schema_limits():
    server = json.loads((ROOT / "server.json").read_text(encoding="utf-8"))
    assert 1 <= len(server["description"]) <= 100  # MCP Registry: ServerDetail.description maxLength
    assert 1 <= len(server["title"]) <= 100
    assert server["name"] == "io.github.shigechika/merakiadm-mcp"
    assert server["packages"][0]["identifier"] == "merakiadm-mcp"


def test_readme_carries_the_registry_ownership_marker():
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    assert "<!-- mcp-name: io.github.shigechika/merakiadm-mcp -->" in readme
