# Deferred: feat/inventory (WP-10)

- [ ] CSV downloads: ogen fixes `Content-Type: application/octet-stream` and sets no `Content-Disposition` for `/inventory/export.csv` and `/inventory/import-template.csv`; add `text/csv; charset=utf-8` + `filename=vedette-devices-YYYYMMDD.csv` + `Cache-Control: no-store` in `core/server` (API_CONVENTIONS §11) — Kiên (core)
