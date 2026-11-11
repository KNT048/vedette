# Deferred — fix/response-never-touch-gateway

- [ ] 2026-11-12 — DNS servers a DHCP lease gives the management card are not in vedette-host's `state/net` (only the saved static `config.mgmt.dns`), so with DHCP only the default gateway is seeded as never-touch (D-325) — vì sao để sau: host change (AI-Trưởng's area): report the resolvers in use (systemd-resolved `resolvectl dns` / `/run/systemd/resolve/resolv.conf`) — ở đâu: host/api/net.go NetState, cmd/vedette/hostmacs.go hostInfraOf
