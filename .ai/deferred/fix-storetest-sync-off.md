# Deferred — fix/storetest-sync-off

- [ ] 2026-11-12 — LOW (Opus review): response's `eventually` (links_test.go) polls a fixed 5 s of wall time; with the package now parallel under -race on a loaded runner the headroom is smaller. Watch CI; if it flakes, poll on the test's own signal or raise the bound — vì sao để sau: no failure seen — ở đâu: modules/response/links_test.go eventually
