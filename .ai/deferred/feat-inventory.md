# Deferred: feat/inventory (WP-10)

- [ ] `FindingCounter`: findings implements `CountByAsset` and `Config.Findings` is set; until then `findings_count` is 0 — WP-21
- [ ] Wire `*inventory.Service` as `observe.Sink` / `observe.SoftwareSink` into sensor-passive, sensor-active, agent-intake, scan when those modules are wired — WP-11+
- [ ] CSV downloads: ogen fixes `Content-Type: application/octet-stream` and sets no `Content-Disposition` for `/inventory/export.csv` and `/inventory/import-template.csv`; add `text/csv; charset=utf-8` + `filename=vedette-devices-YYYYMMDD.csv` + `Cache-Control: no-store` in `core/server` (API_CONVENTIONS §11) — Kiên (core)
- [ ] Time window evaluation (`active.days/from/to` with the org timezone) belongs to the sensor-active scheduler; `ScanPolicy` does not check it — WP-sensor-active
