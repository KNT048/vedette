# Deferred: feat/inventory (WP-10)

- [ ] `feeds.vuln.new_kev` / `feeds.vuln.updated` re-match: inventory announces matches only when software is added; findings must re-match from software + `kev` keys itself (needs `inventory.Service.Device/Devices`) — WP-21 (findings)
- [ ] `FindingCounter`: findings implements `CountByAsset` and `Config.Findings` is set; until then `findings_count` is 0 — WP-21
- [ ] Wire `*inventory.Service` as `observe.Sink` / `observe.SoftwareSink` into sensor-passive, sensor-active, agent-intake, scan when those modules are wired — WP-11+
- [ ] Time window evaluation (`active.days/from/to` with the org timezone) belongs to the sensor-active scheduler; `ScanPolicy` does not check it — WP-sensor-active
