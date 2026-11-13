# Deferred: fix/setup-no-alerts-step (D-462)

- [ ] 2026-11-13 — QA.md §1/§3 (owner: lead): independent walk of the 3-step wizard and the Home "No alert channel yet" reminder, desktop + phone + dark, mock and real box — why later: the agent that built it may not accept its own screen, and agents do not run Playwright — where: `web/e2e/qa/core.spec.ts` (shot `setup-home-no-channel`), `web/e2e-real/setup.spec.ts`
- [ ] 2026-11-13 — Playwright specs edited but not run (owner: lead): `web/e2e/journey.spec.ts`, `web/e2e/qa/{clean.ts,core,findings,inventory,logs,scan}.spec.ts`, `web/e2e-real/setup.spec.ts` now click "Finish setup" on the Modules step — why later: agents run no Playwright (brief) — where: `make check` runs the specs of the touched module
