# Roadmap: verify the concept → GUI → modules

> The work to do lives in the repository's GitHub issues. This file now has historical value only.

Constraints: ship fast but keep to the concept; SMB/Mid/Enterprise can use it early; **a good GUI first, then the backend**, so the project does not drift; no imagined features. Durations are estimates for 1-2 people; re-measure after each milestone.

| Milestone | Duration | What is delivered | "Done" when | Not done |
|---|---|---|---|---|
| ~~M0 Verify the concept~~ (dropped) | n/a | A clickable prototype (real KEV data, fake inventory), 8-10 interviews with P1/P2/P3, a results table by story, a go/no-go decision per module | Every story in M0 has `[passed]`/`[failed]` with evidence; it says which modules go into M1 | Backend, DB, auth |
| **M1 GUI** | 4-6 weeks | A complete SPA for every `[passed]` module, running on a **mock API** (MSW + fixtures from real KEV/Nuclei); modules switched on/off in Settings; i18n vi/en; dark/light; a11y; a usability test with 5 people; design review against `FRONTEND.md` | `pnpm test` + `pnpm build` green; every screen traces to a story; no screen without a story; 5/5 testers complete the 3 main tasks without guidance | The real backend |
| **M2 Core + Feed + Notifications** | 4 weeks | The Go binary: core (local auth, configuration, module registry, jobs, audit, update client), `feeds` (pulls the signed index.json), `inventory` by hand, `notify` Zalo/Telegram/email; the **builder** + data repository + Pages; an anonymous-signal service that **does not record the source IP** (committed to `PRIVACY.md` in the same commit) | A new machine: `install.sh` → 10 minutes later it receives a real alert for a hand-declared product; the signed data update runs 24h without errors | Sensor, scan, AI |
| **M3 Inventory + Mitigation** | 6 weeks | `sensor-passive`, `sensor-active` (nmap from the OS repository, Recog), merging observations, a real "Do you have it?" column; `mitigation` with packs for ≥5 firewall vendors; the authoring tool + confirmation through PRs (S-MIT-4); sensor/server can be separated | Plug the box into a test LAN: ≥80% of devices have the right vendor, ≥50% have product/version; a new matching KEV → an alert + mitigation pack in ≤60 minutes | AI, scan |
| **M4 External surface + Scanning** | 4 weeks | `exposure` (ownership verification, subfinder/httpx), `scan` (Nuclei kev/vkev safe), rescans on a KEV event, evidence | Nuclei confirms correctly on a lab with the flaw; nothing unverified is scanned; "Stop now" stops within 5 seconds | Credentialed |
| **M5 Honeypot + Logs** | 4 weeks | `honeypot` (OpenCanary), `logs` (syslog from FortiGate/MikroTik/pfSense/Windows, a 7-day baseline, IOC) | A trap touched → an alert in ≤30 seconds with the source device; 7 days of logs aggregated to ≤ 1/100 of the raw lines | SIEM forward |
| **M6 BYOK AI** | 4 weeks | `ai`: provider adapter, skill runner, RAG FTS5, 3 levels, `explain-finding`, `cve-news`, `log-digest`, `mcp-server` | Skill fixtures reach ≥95% schema-correct; the token gauge is right to ±5%; no action button from the AI | Vector RAG, log-investigate (max) if no story has passed |
| **M7 Mid/Enterprise/MSP** | 6 weeks | `reports`, `fleet`, `auth-oidc` + RBAC + 2FA, `agent-intake`, `scan-credentialed`, SIEM forward, PostgreSQL | 1 server + 3 sensors + 2 tenants run stable for 7 days; OIDC with Keycloak/Entra | none |

After M2 it is **usable** for P1/P2 (alerts from hand declarations). After M3 it is a complete SMB product. After M7 it is Mid/Enterprise.

## Status 2026-11-10

The milestone table above does not record status; this is the situation by work area, measured from the main branch and the merged PRs (refreshed on the evening of 2026-11-10).

| Milestone | Status | Detail |
|---|---|---|
| M0 | dropped | none |
| M1 GUI | **xong** (2026-11-09, trên mock API) | WP-06 xong (#26) |
| M2 Core + Feed + Notifications | **nearly done, being connected** | The critical path is done (#58); `feeds` has a real backend and UI (#46, #80); `notify` has channels, Incidents, vulnerability notices (#60, #120); `inventory` is done. The host helper is **done** (#140, #148, #163); health check (#144), self-reissuing TLS certificate, fast CI (#147). Remaining: packaging/release not done yet (waiting for the release key and a lab VM) |
| M3 Inventory + Mitigation | **main backend done** | `sensor-passive`, `sensor-active` and the mTLS sensor protocol are done; `mitigation` + `findings` (#44) merged. Two further sensor-protocol steps are done (#151, #158); not done: the remaining sensor-protocol steps (one in progress) |
| M4 External surface + Scanning | **in progress** | `exposure` + the self-detected IP (#91) done; `scan` has finished four slices (#127, #131, #138, #154), the next is #164, open; on the sensor side the protocol step in #151 is done |
| M5 Honeypot + Logs | **honeypot done, logs not yet** | The honeypot is done (#72); `logs`: no merged PR yet; the log export of core is done (#137) |
| M6 BYOK AI | **in progress** | The AI library (#16) is done; the first slice of the AI module is done (#123); the core part: the read-only reader `core/conn/read` (#126) and the AI `Propose` proposals (#113) are done |
| M7 Mid/Enterprise/MSP | not started | no PR yet |

Response side: the first part is done (#74), the critical path is done (#105: pushing configuration to a device works when the AI is off), approval through chat is done. Phase 3: packaging and the other late-phase work are not done yet; packaging waits for the offline release key and a lab VM.

## Rules for moving between milestones
- Each milestone ends with: a record of what is done and a recorded demo.
- Do not pull work of a later milestone into an earlier one "while we are at it".
- M1 can run in parallel with the builder (M2) because the builder has no GUI.

## Known risks
| Risk | Mitigation |
|---|---|
| Devices that hide their version (Synology, Fortinet, MikroTik v7) → a wrong "Do you have it?" | 3 confidence levels, "suspected" shown clearly, Nuclei confirms, an optional agent |
| The free tier changes | A signed `channels.json`, a double mirror |
| An IOC false positive blocks something by mistake | Vedette does not block; it only alerts; a whitelist by domain |
| Prompt injection through logs/web | The guardrails in §5 of `AI_ASSISTANT.md`; the AI takes no actions |
| The open project gets forked commercially | Accepted (Apache-2.0); the advantage is deployment + Vietnamese data |
| Hard to recruit enough people for interviews at the end of the year | Invite 12-14; with too few P4, the P4 stories move to group D |
| The hand-written AI explanation in the prototype is better than the real AI → the explanation hypothesis is optimistic | A note when scoring; verify again at M6 with skill fixtures |
| Testers believe the fake inventory is real | Say so clearly at the start of the session; a "Sample data" label on the prototype |
| M2 coincides with Tet (6/2/2027) | A 1-week buffer |
