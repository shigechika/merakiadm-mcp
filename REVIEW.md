# Review rules for this repository

On top of the reviewer's default focus. The reasoning lives in
`.github/copilot-instructions.md` and `CLAUDE.md`.

## Always blocking

- Anything reaching **stdout** from code that runs while the stdio server is
  serving (`server.py`, `client.py`, `__main__.py` after `mcp.run()`).
  `--check` and `scripts/smoke_test.py` print to stdout on purpose.
- The API key reaching a log line, an exception message or a tool response —
  the `Authorization` header or `MERAKI_DASHBOARD_API_KEY` — at any level.
- Any request other than GET, or a tool not marked read-only.
- A tool that returns a raw API list, or a window / count parameter that is
  not clamped. Several endpoints return hundreds of KB to MB per call; an
  unbounded answer makes the caller's next model request fail.
- Following a redirect to a non-Meraki host with the Authorization header.
- A cursor that lets parameters other than `CURSOR_PARAMS` into a request.
- A deployment-specific literal (network, device or SSID name, ID, address)
  anywhere, `scripts/smoke_probes.py` especially. This repository is public.
- Replacing `__main__.py`'s `os._exit(0)` with `sys.exit(0)`.

## Report even though the default focus would not

- Tool name and docstring accuracy: a model picks a tool by its docstring, so
  a docstring that promises a field or a bound the code does not deliver is a
  bug.
- A `capped` case that is not reported in the answer.

## Noise

- `ruff format` style (formatting is not gated).
- Suggestions to wrap tool returns in MCP content envelopes: `MCPServer` does it.
