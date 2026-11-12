# Deferred: fix/v1-left-logs-a-mlee

- [ ] 2026-11-13 — a keyword that matches nothing over 7 days of a 5M-line box answers 503 `server_busy` after 5 s (D-432); an FTS5 index is the upgrade if a customer needs it — vì sao để sau: no customer asked, a migration doubling the largest table — ở đâu: `modules/logs/events.go` `search`.
