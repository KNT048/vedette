# WP-31 security review: findings still open (session fix-wp31, 2026-11-11)

Full report: kien's Mac `vedette-wt/wp31-findings.md` (24 findings: 0 High, 7 Medium, 17 Low). One line per finding; a line goes when its PR merges.

- [ ] L7 response/notify: approver channel identity is typed by an admin, never proven by the user → needs a story criterion (link step in My account) first; slice R3.
- [ ] L11 honeypot: failed teardown never retried while the module is off (SYS-5) → slice H (Mac).
- [ ] L13 honeypot: `clean()` keeps variation selectors → slice H.
- [ ] L14 honeypot: Viewer sees bait passwords in full (INV-10) → decide in slice H (D-xx).
- [ ] M4 host/ops: backup retention can drop the backup a revert/rollback needs; missing backup loops; `os.install` skips `coreFree()` → AI-Trưởng (host).
- [ ] L10 packaging (LAB): `RuntimeDirectory=vedette` without User/Group makes /run/vedette root:root → AI-Trưởng (WP-08).
- [ ] M7 inventory/honeypot (latent, LAB): devices on a decoy IP are invisible; filter on (decoy IP, decoy MAC) once vedette-host reports MACs → after the host adapter replaces `notAnAppliance`; WP-08 lab.
- [ ] L15 `/core/privacy` telemetry default on → already in `fix-privacy-accuracy.md` (D-153).
- [ ] L17 `/core/data/export` and `/core/data/purge` answer 501 while PRIVACY.md promises them → AI-Trưởng core purge work, or reword the footer before release.
- [ ] LAB list for WP-08 lab: SO_PEERPIDFD + core cgroup under Quadlet; NET_RAW ambient for non-root sensor/scan; L10 chown; process-group kill and Pdeathsig; nuclei egress; nmap overriding a passive kind (M5).
