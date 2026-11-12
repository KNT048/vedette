# Deferred: fix/logs-deferred-v1-mlee

- [ ] 2026-11-12 — the SIEM `bad_conn` record does not carry `blocked` (D-384): add it (CEF `act=blocked`, syslog/json key `blocked`) with its test and the format docs — vì sao để sau: changes the SIEM record format (S-LOG-3 contract), out of the scope of the incident wording — ở đâu: `modules/logs/siem_run.go` `on(siemEventBadAddress, …)`.
- [ ] 2026-11-12 — response's `ioc_connection` trigger does not read `IocHit.blocked` (D-384): decide with the story whether a blocked attempt proposes the same actions as a completed connection — vì sao để sau: response is Kiên's module and the trigger semantics are a product call — ở đâu: `modules/response/events.go` `iocEvent`.
