# fix/scan-first-run-tonight (W3-9) — deferred

- 2026-11-13 (Opus #670 L1): on a box with nothing scannable without a pick, `firstPending` stays true and every window tick re-reads scope/devices/policy (~420×/night). Record "extra slot looked at" (column or in-memory) without ending the first-run period.
- 2026-11-13 (Opus #670 L2): `firstPending` scans `scan_run` (no index on `trigger`) every minute and on every GET /scans/config until the first scheduled run; add a partial index `ON scan_run(trigger) WHERE trigger='schedule'` or cache the flip in Service.
- 2026-11-13 (Opus #670 L5): test gaps — assert the 18:39 tick leaves `sched_last` and the `missed` audit unchanged; cover an empty/missed weekday slot during the first-run period followed by silent extra nights.
