# Việc để sau — nhánh feat/e2e-real-honeypot (WP-30 slice 8b)

- [ ] 2026-11-11 — Optional GUI, not built: the decoy MAC is shown nowhere in the GUI or in GET /honeypot. S-HP-2 / D-102 already mark showing the MAC as optional and for later; the spec checks it on the host side only (GET /v1/state/net) — vì sao để sau: optional by the story — ở đâu: `web/e2e-real/honeypot.global.spec.ts`
- [ ] 2026-11-11 — Not covered: decoy personalities (S-HP-2 extra decoys, scan detection from several decoy IPs), viewer/operator role locks of the page, string-typed ports in the log (another branch changes `parse.go`) — vì sao để sau: one slice — ở đâu: `web/e2e-real/honeypot.global.spec.ts`
