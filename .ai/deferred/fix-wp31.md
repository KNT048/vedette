# WP-31 security review: findings still open (session fix-wp31, 2026-11-11)

Full report: kien's Mac `vedette-wt/wp31-findings.md` (24 findings: 0 High, 7 Medium, 17 Low). One line per finding; a line goes when its PR merges.

- [ ] M1 response: template header values (API keys) visible to viewers and in the backup → slice R1 `fix/wp31-response-approver` (D-174).
- [ ] M2 response/notify: Telegram Approve shows line 1 of a multi-line call; chain log keeps line 1 → R1 (D-175). Open after R1: `DecideFromChat` still accepts a decision from a chat channel on a high-risk request if an old button (sent before D-175, nonce kept by notify) is pressed before the request ends; add a server-side refusal when Slack/Telegram buttons are built for real (R2 or the Slack slice).
- [ ] L6 response: approval messages and the email-link page lack the "AI-generated" label → R1.
- [ ] L16 PRIVACY flow 5: the `webhook_call` action posts request text to the notify webhook → R1. R1 `make check` note: web, generate-check, golangci-lint (0 issues) and the contract tests passed; the final `go test -race ./...` of `make verify` hit the 10 min cap on this machine (load), so the targeted Go tests of the touched packages were run instead.
- [ ] L1, L2, L3, L5 response execution path (re-check earlier approver, count unknown-state items, hash-check undo, emergency stop interrupts a running step) + L4 (latent SYS-8, MCP annotations) + L9 (BoxAddrs for decoy IPs) → slice R2, after R1.
- [ ] L7 response/notify: approver channel identity is typed by an admin, never proven by the user → needs a story criterion (link step in My account) first; slice R3.
- [ ] M3 core/sensorlink: one sensor can hold all 64 link slots (unread chunked body, no read deadline) → slice S (Mac).
- [ ] M5 inventory: one SSDP/LLDP frame makes a device a router on response's never-touch list → slice I (Mac).
- [ ] M6 inventory/cmd/vedette: "IP in use" and new-MAC budget read a list capped at 2000 → slice I.
- [ ] L8 sensor-active: `recordSweep` has no new-device budget → slice I.
- [ ] L12 inventory: `cleanText` lets C1, bidi, zero-width and tag characters through → slice I.
- [ ] L11 honeypot: failed teardown never retried while the module is off (SYS-5) → slice H (Mac).
- [ ] L13 honeypot: `clean()` keeps variation selectors → slice H.
- [ ] L14 honeypot: Viewer sees bait passwords in full (INV-10) → decide in slice H (D-xx).
- [ ] M4 host/ops: backup retention can drop the backup a revert/rollback needs; missing backup loops; `os.install` skips `coreFree()` → AI-Trưởng (host).
- [ ] L10 packaging (LAB): `RuntimeDirectory=vedette` without User/Group makes /run/vedette root:root → AI-Trưởng (WP-08).
- [ ] M7 inventory/honeypot (latent, LAB): devices on a decoy IP are invisible; filter on (decoy IP, decoy MAC) once vedette-host reports MACs → after the host adapter replaces `notAnAppliance`; WP-08 lab.
- [ ] L15 `/core/privacy` telemetry default on → already in `fix-privacy-accuracy.md` (D-153).
- [ ] L17 `/core/data/export` and `/core/data/purge` answer 501 while PRIVACY.md promises them → AI-Trưởng core purge work, or reword the footer before release.
- [ ] LAB list for WP-08 lab: SO_PEERPIDFD + core cgroup under Quadlet; NET_RAW ambient for non-root sensor/scan; L10 chown; process-group kill and Pdeathsig; nuclei egress; nmap overriding a passive kind (M5).
