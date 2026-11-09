# Deferred from session fix-gui-contract-align (WP-06)

- [ ] `modules/findings/` (MANIFEST `fnd_`, depends core+feeds+inventory) does not exist yet and `modules/mitigation/MANIFEST.yaml` still says `mit_`, depends core+feeds+inventory (D-57 (6): depends on findings). The GUI mock already has module `findings` and `mitigation` depending on it. WP-21 owns the manifests.
- [ ] Anonymous signal payload: the key `ids_matches` is now `cve_matches` (counts of matches between devices and exploited vulnerabilities, by CVE) because there is no IDS (D-43). It is a rename in a fixed payload (PRIVACY.md flow 2 updated). Kiên to confirm the new key and meaning.
- [ ] Template model is one call per phase: multi-call REST of action-templates (FortiGate address object + group member, pfSense apply, AdGuard read-modify-write, MikroTik GET then DELETE) is described and uses run-time values (`{found_id}`, `{rules_before}`), but is not executable as separate steps. WP-13 needs `steps[]` and `precheck` (spec §1.1).
- [ ] FortiGate `expiry` (spec 2.3) and the other native TTLs are expressed with run-time values (`{expiry_s}`, `{timeout}`); the mock does not compute them.
- [ ] `blocked_reason: no_commitment` in exposure targets stays as a state label; only the error code changed to `commitment_required` (D-57 (10)).
- [ ] "Blocklist pull" is not a connection kind in the code: it is the box's own action `blocklist_add` (pack "box"), see `web/src/lib/connections.ts`. Confirm this reading of D-58.
- [ ] `docs/specs/blocklist-format.md` examples still show `confidence 85` (0..100) in the `reason` text; the mock now writes `confidence 0.85`.
- [ ] `api/openapi.json` documents 200 for the two endpoints that answer 201 or 200 depending on the case (`POST /exposure/box-ip/verify`, `POST /response/ai/proposals`).
