# Deferred — feat/mcp-server (WP-27 mcp-server, Mac side session, 2026-11-11)

- [ ] 2026-11-11 — Quadlet/packaging: let the host's `127.0.0.1:8765` reach core's loopback-only MCP listener without listening off loopback (host network for this port, or another way), and pass `-mcp-listen` (D-234 (3)) — why later: packaging is WP-08 (AI-Trưởng); until then MCP works only on a container-less install — where: host/ops core unit, `cmd/vedette/main.go` newFlags
- [ ] 2026-11-11 — WP-30 e2e-real spec for Settings → MCP server on the real box (turn on, token once, revoke; a fake MCP client against 127.0.0.1:8765 from the runner) — why later: one PR per WP-30 slice; contract + wiring tests cover the backend here — where: `web/e2e-real/`
- [ ] 2026-11-11 — `.ai/deferred/feat-e2e-real-harness.md:21` (GET /core/mcp 404 pinned in KNOWN_404) is resolved by this branch (pin removed); that file belongs to another session: its owner ticks the line — where: `.ai/deferred/feat-e2e-real-harness.md`
