# Việc để sau — nhánh fix/feeds-own-ports-ssrf (D-208)

- [x] Done in this branch (`e2eOffline` loopback-only transport, supervisor OK, D-65) — 2026-11-12 — `cmd/vedette/e2ebox_test.go` `e2eOffline` and `web/e2e-real/feeds.spec.ts` pull a custom feed from a node server on 127.0.0.1; D-208 now refuses loopback at connect, so the e2e-real feeds pull specs need a test seam (harness) — vì sao để sau: harness is not in this slice's scope — ở đâu: `cmd/vedette/e2ebox_test.go`
