# Deferred — fix/e2e-mock-inventory

- [ ] 2026-11-12 — The inventory empty state ("No devices yet" + "Plug the box into your LAN…", `inventory.json` `empty.*`) is now unreachable in a real or mock install, because the box is always the first device (INV-3, S-INV-5); only vitest still covers the copy. Decide: keep for a list filtered to nothing, or delete the dead text — vì sao để sau: product decision, not a spec drift — ở đâu: web/src/features/inventory/DevicesPage (empty state), web/e2e/qa/inventory.spec.ts clean-install test
- [ ] 2026-11-12 — No Playwright spec drives Settings → Box network (choosing the card / SPAN), which replaced the old sensor dialog's interface select and SPAN switch; vitest covers the mock side only — vì sao để sau: new spec, own slice — ở đâu: web/e2e/qa/
