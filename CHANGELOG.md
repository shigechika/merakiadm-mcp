# Changelog

## 0.0.1 (2026-11-26)


### Features

* add config_changes and [CHANGES]/[FIRMWARE]/[LICENSE] brief lines; mask change-log values whose label names a secret ([d64078f](https://github.com/shigechika/merakiadm-mcp/commit/d64078fda1025d815f702453dba9477c36ae099c))
* add find_api and api_get so one server covers any Dashboard read ([ba472ac](https://github.com/shigechika/merakiadm-mcp/commit/ba472acfc631aaa5894bb54dd717ea5c28182068))
* add resolve_entity and find_client; api_get reads up to five pages, takes JSON strings, names serials and says when and what it read ([0cdee30](https://github.com/shigechika/merakiadm-mcp/commit/0cdee30e697b5b137e9ed6d40689a76f57cd246c))
* add wireless_quality and a [WIRELESS] brief line; name the two sources in connection_failures ([9e2e08f](https://github.com/shigechika/merakiadm-mcp/commit/9e2e08f337ac40376f34ed47a81b0a305b885a4d))
* availability history, operational events and a previous-window comparison in daily_brief ([e33ff18](https://github.com/shigechika/merakiadm-mcp/commit/e33ff183b1b9c70819b98e28aa3845ea84b0c4f9))
* fold repeated event lines and hint at misspelt event types ([16e2fcb](https://github.com/shigechika/merakiadm-mcp/commit/16e2fcb5e842c9b2358be9aca027bfa803e2be49))
* read-only Meraki Dashboard MCP with bounded health, connection, Air Marshal and event summaries ([9a3d7ac](https://github.com/shigechika/merakiadm-mcp/commit/9a3d7ac11e2dd884684c9e9cafa4dc9b8d81bcdd))


### Bug Fixes

* bound the whole api_get answer, keep returned accurate, scope administered reads and every networkIds form ([634a711](https://github.com/shigechika/merakiadm-mcp/commit/634a71105e5c79408059431701b5e141251c5f98))
* count outages only on leaving online, report capped history, note undetailed dropped entries ([4ba5f15](https://github.com/shigechika/merakiadm-mcp/commit/4ba5f15881cfb205c79b8d98327dba68ad1a4f57))
* fit the registry description in 100 characters and stop tests from ageing out ([e4ec005](https://github.com/shigechika/merakiadm-mcp/commit/e4ec00528e4af5adcef2a2d3d02212da4db7f21b))
* judge event caps by page start, end list_events on an empty page, bound each network's time ([71ed21f](https://github.com/shigechika/merakiadm-mcp/commit/71ed21ff1b9ad46076ae3a359d0addf023771d08))
* judge licenses by active subscriptions, keep organization-wide data out of a network scope, report slow brief lines, bound change-log pages to the window ([597dcac](https://github.com/shigechika/merakiadm-mcp/commit/597dcacd68a921a51c853f180a7ef4b0120f506b))
* keep device names in the network scope, page through IP matches, follow next links with their own cursor and keep earlier pages on a later failure ([ce48308](https://github.com/shigechika/merakiadm-mcp/commit/ce483088fcaf1bbb651b805c64e2083f1e79b344))
* label devices with downtime accurately and mark the window-start state unknown when history is capped ([eed63ce](https://github.com/shigechika/merakiadm-mcp/commit/eed63ce44d9d9387218102641bf7bce8c10b3e47))
* name the list field of an api_get answer list_name, so key-name redaction downstream leaves it alone ([302f15a](https://github.com/shigechika/merakiadm-mcp/commit/302f15ae609a25ca9774e6e387ab7977b60e6adc))
* read co-term license dates, check the brief deadline before each new line, never lower a tier ([8cba043](https://github.com/shigechika/merakiadm-mcp/commit/8cba04328b3676454faf3f4718b319528d0bd48b))
* read events newest first, fix history paging, report dropped events per type, bound the brief by time ([d5ece5f](https://github.com/shigechika/merakiadm-mcp/commit/d5ece5f3e4a2ee05f3f05c9fd7898c5900c34f68))
* refuse plain-http redirects, page device lists, scope health counts, bound the brief ([fdf8ba7](https://github.com/shigechika/merakiadm-mcp/commit/fdf8ba72145c352c6a819a2764bf60bf69fa2daf))
* say when device names are incomplete, refuse redirects without Location ([762e609](https://github.com/shigechika/merakiadm-mcp/commit/762e609136e8ce6d3bc5b67471dd216ebf460b3f))


### Performance

* read the device inventory in daily_brief only when AP names are shown ([0b341eb](https://github.com/shigechika/merakiadm-mcp/commit/0b341eb18a89645a2f7f91d4d2407ceafb4f86ae))

## Changelog
