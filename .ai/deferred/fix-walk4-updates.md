# Deferred: fix/walk4-updates (D-407)

- [ ] 2026-11-13 — `web/e2e-real/os-updates.global.spec.ts` "never checked" test now expects 200 with `os` null (D-407); not run here (e2e-real is outside check and CI, needs the real backend) — vì sao để sau: heavy, not for subagents — ở đâu: `make e2e-real` on the Mac, next real-box walk
- [ ] 2026-11-13 — the new Updates states (one status line with `update_not_published`, empty managed/advisories sentences, "Vedette <version>" under the account menu, OS never-checked 200) and Privacy flow 3 as a list were checked by vitest only: the browser pane could not run the mock service worker from this worktree — vì sao để sau: needs a visual pass (docs/QA.md) — ở đâu: Settings → Updates, Settings → Privacy, sidebar footer; next walk on 0.0.1-test.N
