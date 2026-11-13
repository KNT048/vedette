# Deferred: fix/multi-products-old-rows-close (D-506)

- [ ] notify: alert when Vedette reopens a finding by itself (`findings.finding.status_changed` with `reason: matches_again`), so a D-506 or D-530 close that NVD later contradicts is not silent (today notify only alerts on `confirmed`, `modules/notify/events.go`). Needs a story criterion in S-ALERT-1 first; notify is Mlee's module.
- 2026-11-13 (Opus #674 L2): reconcile's `closed_multiple_products` under-counts when the backlog write commits and the recent write then fails (the device is skipped). Count per committed write.
- 2026-11-13 (Opus #674 L3): tests for the exact 365-day boundary, two unlisted same-vendor rows, and a confirmed/scan finding on the D-506 path (checked by the reviewer's overlay probe, not in the suite).
