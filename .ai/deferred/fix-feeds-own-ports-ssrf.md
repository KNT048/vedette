# Việc để sau — nhánh fix/feeds-own-ports-ssrf (D-208)

- [ ] 2026-11-12 — `cmd/vedette/e2ebox_test.go` `e2eOffline` and `web/e2e-real/feeds.spec.ts` pull a custom feed from a node server on 127.0.0.1; D-208 now refuses loopback at connect, so the e2e-real feeds pull specs need a test seam (harness) — vì sao để sau: harness is not in this slice's scope — ở đâu: `cmd/vedette/e2ebox_test.go`
- [ ] 2026-11-12 — Save-time check (INV-2) and the Settings hint (`web/src/locales/en/feeds.json` `urlHint`, `mirrorHint`) still say localhost/127.x are allowed for http; make the save check and text match the pull (GUI/mock change, kien) — vì sao để sau: web/src/lib and mocks are out of this slice — ở đâu: `modules/feeds/validate.go`, `web/src/mocks`
