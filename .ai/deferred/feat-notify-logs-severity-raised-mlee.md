# Deferred — feat/notify-logs-severity-raised-mlee (D-495, 2026-11-13)

- [ ] 2026-11-13 — The "raised" notice says only "new information about how it is exploited" when basis is not version (ransomware / EPSS ≥ 0.5): the event carries no cause — vì sao để sau: needs findings to add a `cause` field (ransomware | epss | version) to `severity_raised` — ở đâu: modules/findings/ports.go SeverityRaisedEvent, modules/notify/events.go findingRaised.
- [ ] 2026-11-13 — A raise that follows a regrade down to the same level (raise, regrade, raise) is not told twice (notice id is unique per finding and level) — vì sao để sau: rare; an id with a counter needs the finding history — ở đâu: modules/notify/events.go.
