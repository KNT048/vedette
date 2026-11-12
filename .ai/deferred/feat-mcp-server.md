# Deferred — feat/mcp-server (WP-27 mcp-server, Mac side session, 2026-11-11)

- [x] 2026-11-11 — Quadlet/packaging: let the host's `127.0.0.1:8765` reach core's loopback-only MCP listener without listening off loopback (host network for this port, or another way), and pass `-mcp-listen` (D-234 (3)) — why later: packaging is WP-08 (AI-Trưởng); until then MCP works only on a container-less install — where: host/ops core unit, `cmd/vedette/main.go` newFlags — done: D-395, PR #585 (unit and compose publish 127.0.0.1:8765; core defaults -mcp-listen to 0.0.0.0:8765 only inside a container)
