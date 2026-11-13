# Deferred — feat/notify-logs-severity-raised-mlee (D-495, 2026-11-13)

- [ ] 2026-11-13 — A raise that follows a regrade down to the same level (raise, regrade, raise) is not told twice (notice id is unique per finding and level) — vì sao để sau: rare; an id with a counter needs the finding history — ở đâu: modules/notify/events.go.
- [ ] 2026-11-13 — The reopen goes to the SIEM as `finding.status_changed` with severity info; a SIEM rule on severity does not see a reopened critical finding — vì sao để sau: needs the finding severity in `StatusChangedEvent` or a new record — ở đâu: modules/logs/siem_run.go, modules/findings/ports.go.
