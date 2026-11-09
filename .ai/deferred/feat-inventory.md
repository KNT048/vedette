# Deferred: feat/inventory (WP-10)

- [ ] Wire the real event bus: `cmd/vedette/inventory.go` passes no `Config.Events`; after WP-04b add `inventory.PublisherFunc` over `events.Bus.Publish(ctx, events.Event{Name, Data})` — lead (WP-04b)
- [ ] Give feeds' data to inventory: implement `inventory.KEV` (`Products`, `CVEs` incl. vendor "Multiple Products" matching) in `modules/feeds` and set `Config.KEV`; until then `EmbeddedKEV` (content/catalog/kev-products.json) gives the catalog but no CVE ids, so `kev_cves` lists are empty and no `inventory.match.changed` is published; delete the embedded copy and `make fixtures` writing it when done — WP-20 (Emily)
- [ ] `feeds.vuln.new_kev` / `feeds.vuln.updated` re-match: inventory announces matches only when software is added; findings must re-match from software + `kev` keys itself (needs `inventory.Service.Device/Devices`) — WP-21 (findings)
- [ ] `basis="version"` on `inventory.match.changed` needs affected ranges from feeds (Vuln.Affected); today only `product` — WP-20/21
- [ ] Box packages: implement `inventory.BoxPackages` over `vedette-host` (dpkg, confidence 1.0) and the box IP/OS in `inventory.BoxInfo` (job `box` passes only the hostname) — WP-07
- [ ] `FindingCounter`: findings implements `CountByAsset` and `Config.Findings` is set; until then `findings_count` is 0 — WP-21
- [ ] Wire `*inventory.Service` as `observe.Sink` / `observe.SoftwareSink` into sensor-passive, sensor-active, agent-intake, scan when those modules are wired — WP-11+
- [ ] CSV downloads: ogen fixes `Content-Type: application/octet-stream` and sets no `Content-Disposition` for `/inventory/export.csv` and `/inventory/import-template.csv`; add `text/csv; charset=utf-8` + `filename=vedette-devices-YYYYMMDD.csv` + `Cache-Control: no-store` in `core/server` (API_CONVENTIONS §11) — Kiên (core)
- [ ] Time window evaluation (`active.days/from/to` with the org timezone) belongs to the sensor-active scheduler; `ScanPolicy` does not check it — WP-sensor-active
- [ ] Retention: `inv_service` rows not seen for 90 days and agent software not seen for 30 days (DATA_MODEL [ĐX]) are not pruned yet — job in a later milestone
