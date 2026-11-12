# Deferred — feat/agent-intake-wazuh (WP-26 slice 4)

- [ ] 2026-11-12 — [verify] One local run against a real pinned `wazuh/wazuh-manager` 4.9.x container with the read-only role of the GUI steps: login `?raw=true`, `select` with `lastKeepAlive` and `os.*`, `packages` `select=name,version,vendor,format,source` accepted, a Windows agent's `format=win` rows, the `ip` of an agent behind NAT — vì sao để sau: needs the container and a Windows agent; local only, never CI (plan §6) — ở đâu: modules/agent-intake/wazuh_client.go, D-306
