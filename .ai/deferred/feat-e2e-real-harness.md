# Việc để sau — nhánh feat/e2e-real-harness (WP-30 lát 1, D-170, D-171)

Kế hoạch đầy đủ: `/Users/kien/Desktop/vedette-wt/wp30-plan.md` (§2 các lát, §4 rủi ro).

- [ ] 2026-11-11 — Lát 2: `users.spec`, `modules.global.spec`, `privacy.spec`, `logs-export.spec`, `bugreport.spec` (S-CORE-1/3/4/5/6, D-132, D-153) — vì sao để sau: một PR mỗi lát — ở đâu: `web/e2e-real/`
- [ ] 2026-11-11 — Lát 3: `twofa.spec` với SMTP sink + control endpoint (S-CORE-3, D-76, D-35) — vì sao để sau: cần fake trong tiến trình hộp — ở đâu: `cmd/vedette/e2ebox_test.go`
- [ ] 2026-11-11 — Lát 4: vedette-host giả + hộp trần (`os-updates.global`, `network.global`, `backup`, `bare-box`; S-CORE-7/8, D-55, D-100, D-118) — vì sao để sau: một PR mỗi lát — ở đâu: `web/e2e-real/`
- [ ] 2026-11-11 — Lát 5: `connections.spec` với fake conntest (D-93/D-94/D-127) — vì sao để sau: một PR mỗi lát — ở đâu: `web/e2e-real/`
- [ ] 2026-11-11 — Lát 6: `inventory.spec`, `scope.global.spec` (S-INV-2/3/5) — vì sao để sau: một PR mỗi lát — ở đâu: `web/e2e-real/`
- [ ] 2026-11-11 — Lát 7: sensor thật (passive replay pcap, active với nmap giả; S-INV-1/3, D-80, D-84) — vì sao để sau: cần `-sensor-listen` trong hộp — ở đâu: `cmd/vedette/e2ebox_test.go`
- [ ] 2026-11-11 — Lát 8a/8b: adapter host cho honeypot rồi `honeypot.spec` (S-HP-1/2, D-102) — vì sao để sau: 8a là backend (`notAnAppliance`) — ở đâu: `cmd/vedette/honeypot.go:77-90`
- [ ] 2026-11-11 — Lát 9a/9b: `response-actions`, `response-exec.global`, `response-chain` (S-RESP-3/4, INV-2/4/7/8/10/13/17/19), cần seam `BaseURL` (D-173) — vì sao để sau: một PR mỗi lát — ở đâu: `cmd/vedette/notify.go:95-98`
- [ ] 2026-11-11 — Lát 10: chạy đầy đủ, project `@mobile`, hàng `docs/QA.md`, completion log, đóng dòng deferred — vì sao để sau: cuối chuỗi — ở đâu: `docs/QA.md`
- [ ] 2026-11-11 — Gộp ý tưởng `clean.ts` của `origin/fix/e2e-baseline` (đợi `/$` sau "Skip and finish") vào suite mock; nhánh đó bỏ — vì sao để sau: không thuộc WP-30 — ở đâu: `web/e2e/qa/clean.ts`
- [x] 2026-11-11 — Dòng `feat-core-skeleton.md:5` và `feat-fast-checks.md:4` đã Moved to WP-30 (D-170) theo quyết định của supervisor
- [ ] 2026-11-11 — `KNOWN_501` (shrink-only): `GET /api/v1/core/updates` on `/settings/updates` (`feat-core-os-updates.md:3`); the role-lock loop of `auth.spec.ts` skips the Updates read-only note for the same reason (annotation `fixme`) — vì sao để sau: unbuilt backend — ở đâu: `web/e2e-real/gaps.spec.ts`, `web/e2e-real/auth.spec.ts`
- [ ] 2026-11-11 — `GET /api/v1/inventory/agents` answers 404 on the real box (agent-intake not wired; the GUI calls it on `/devices/setup`); `gaps.spec.ts` pins it in `KNOWN_404` (shrink-only, D-171) — vì sao để sau: agent-intake is not wired (`cmd/vedette/modules.go`) — ở đâu: `web/e2e-real/gaps.spec.ts`
- [ ] 2026-11-11 — The release GUI still shows "Use sample data" and the real box answers 400 `sample_unavailable` (covered by `setup.spec.ts`); decision with kien is in `feat-core-auth-api.md:7` — vì sao để sau: product decision — ở đâu: `web/src/features/core/SetupPage.tsx:150`
- [x] 2026-11-11 — Bug filed: issue #201 (owner:kien, wp:30), CSP violation report from the contract chunk (zod probe): fixed by #202; the four `test.fail()` markers were removed from `gaps.spec.ts` and those routes now must pass
- [ ] 2026-11-11 — `GET /api/v1/core/oidc` answers 404 on the real box (single sign-on is not wired; the GUI calls it on `/settings/users`); pinned in `KNOWN_404` — vì sao để sau: OIDC is not built (`cmd/vedette/modules.go`) — ở đâu: `web/e2e-real/gaps.spec.ts`
- [ ] 2026-11-11 — `GET /api/v1/core/mcp` answers 404 on the real box (MCP server is not wired; the GUI calls it on `/settings/mcp`); pinned in `KNOWN_404` — vì sao để sau: MCP is not built (`cmd/vedette/modules.go`) — ở đâu: `web/e2e-real/gaps.spec.ts`
