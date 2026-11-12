# Deferred from feat/e2e-real-specs-sal (WP-30 specs for logs, scan, ai; D-198)

- [ ] ai: `POST /ai/ask` and `GET /ai/asks`, `POST /ai/cve/{id}/news`, `/ai/memory`, `/ai/skills`, `/ai/knowledge` answer 501. `/assistant` is in KNOWN_501 (`GET /ai/asks`). fixme blocks in ai.global.spec.ts hold the real flows. A model answer needs a provider key: the specs never configure one (PRIVACY flow 3).
- [ ] scan: a run, Stop now, auto-stop and the rescan on a new KEV need the scan worker (sensor seam, WP-30 slice 7) and the scan image: four fixme blocks in scan.global.spec.ts, with `can_scan=false` and `503 scanner_unavailable` tested meanwhile.
