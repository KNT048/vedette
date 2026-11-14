# Deferred — b-templates (item 24 slice b, scan side, D-520)

- [ ] 2026-11-14 — N100 acceptance walk of slice b (forward httpd 2.4.49, Scan now on the box's public IP, CVE-2021-41773 "confirmed by template", probe log lists the template id) — why later: needs a deploy and the customer walk (supervisor), not an agent — where: N100, Exposure page + Scans → Probe log.
- [ ] 2026-11-14 — A template run the worker refused before nuclei started (not_own_ip, egress_unverified) or core refused (busy, older worker) leaves its probe rows at `no_response` ("sent, no answer"), though nothing was sent — why later: a truthful "refused" needs a new `scan_probe.result` value (migration of the CHECK) — where: modules/scan/migrations, cmd/vedette/exposuretemplates.go runOne.
