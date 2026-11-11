# Deferred: fix/feeds-before-v1

- [ ] 2026-11-11 — `feeds.vuln.updated` is published but nobody listens: a CVE whose vendor/product changed in the KEV list, or whose `has_template` changed, does not re-match devices (inventory CONTRACT, "Nhận"). KevInfo is read at display time so findings stay right; only the product-key change would be missed. Wire `RematchCVE` from `VulnUpdatedEvent` if a story needs it — why later: rare, no story — where: cmd/vedette/wiring.go `subscribe`.
