# Deferred: feat/exposure-runner-mlee

- [ ] 2026-11-13 — BLOCKS V1: `exposure.Runner` was never built (feat-scan-module.md:81 said "Moved → #115", but #115 closed 2026-11-11 without it): POST /exposure/…/scan answers 501, no snapshot of hosts/ports/admin pages/certs, so the exposure page and the response `new_port` trigger (#532) have no data on a real box. S-EXP-1 `[đạt]` promises them — vì sao để sau: in progress on this branch (AI-Mlee, 2026-11-13) — ở đâu: modules/exposure/ports.go Runner, Service.SetRunner; modules/scan registers it
