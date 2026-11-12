# Deferred — fix/ci-shard-timeout (2026-11-12)
- [ ] 2026-11-12 — Drop `-timeout 18m` from `test-go-shard` once `modules/response` runs fast under -race (branch fix/response-test-hang, session wp30-s3, target < 90 s) — vì sao để sau: stopgap so main is green again; the speed-up is its own work — ở đâu: Makefile test-go-shard
