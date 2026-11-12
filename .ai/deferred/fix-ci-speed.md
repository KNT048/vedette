# Deferred — fix/ci-speed

- [ ] 2026-11-12 — Measure the Go test cache's size per shard after a week of pushes (4 entries per push, keys per run): if the repo's 10 GB churns out the golangci-lint and setup-go caches, keep fewer entries (one key per shard per day) — vì sao để sau: needs real runs (Opus review LOW) — ở đâu: .github/workflows/ci.yml go-test, gh cache list
- [ ] 2026-11-12 — go-static and go-release still use setup-go's own cache, which a pull request saves when go.sum changes (as before D-365); consider restore-only there too — vì sao để sau: unchanged behaviour, not a regression (Opus review LOW) — ở đâu: .github/workflows/ci.yml
- [ ] 2026-11-12 — Refresh scripts/ci/testtime.tsv from the first daily (-count=2) run's log after the storetest speed-up merged (`go run ./scripts/ci times <log>`, halve the times) — vì sao để sau: needs that run — ở đâu: scripts/ci/testtime.tsv
- [ ] 2026-11-12 — LOW (Opus round 2): scripts/ci flaky.go lists only Test… functions, so a failed Example…/Fuzz… shows its package as "no test named"; the "Z " timestamp strip can cut a raw local line — vì sao để sau: CI logs only, round cap D-255 — ở đâu: scripts/ci/flaky.go
- [ ] 2026-11-12 — LOW (Opus round 2): the guard does not check a `GOTESTFLAGS ?=` default or GOFLAGS set in the Makefile (none today) — vì sao để sau: round cap — ở đâu: scripts/ci/guard_test.go
