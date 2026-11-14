# Deferred: feat/exposure-internetdb-mlee

- [ ] 2026-11-14 — F7 review r1 L2: the `exposure.outside_view` audit row is written after the Shodan GET (one row per request, detached from the person's request since M1), so a crash or OOM-kill between the GET and the commit leaves a request with no audit row — vì sao để sau: a second "sending" row per request doubles the audit lines for a window of at most 10 s that needs a process crash; nothing records that one request then — ở đâu: modules/exposure/outside.go CheckOutside, CONTRACT INV-21
