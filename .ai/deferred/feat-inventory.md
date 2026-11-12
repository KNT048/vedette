# Deferred: feat/inventory (WP-10)

- [ ] `feeds.vuln.new_kev` / `feeds.vuln.updated` re-match: inventory announces matches only when software is added; findings must re-match from software + `kev` keys itself (needs `inventory.Service.Device/Devices`) — WP-21 (findings)
- [ ] CSV downloads: ogen fixes `Content-Type: application/octet-stream` and sets no `Content-Disposition` for `/inventory/export.csv` and `/inventory/import-template.csv`; add `text/csv; charset=utf-8` + `filename=vedette-devices-YYYYMMDD.csv` + `Cache-Control: no-store` in `core/server` (API_CONVENTIONS §11) — Kiên (core)
