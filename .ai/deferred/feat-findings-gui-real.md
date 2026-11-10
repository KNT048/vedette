# Deferred: feat/findings-gui-real

- [ ] No way to load a confirmed pack on a box yet: `mitigation.Loader` needs the update signature `Verifier` (core/updates, Kiên). Until then a real box shows "No confirmed recommendation yet" for every CVE; the GUI checks seed `modules/mitigation/testdata` with `TestGUIReal_SeedBoxWithTestdataPacks` (a developer seed, no audit row).
- [x] Done in 1fe415d: the test pack is generated from the mock pack and packs.parity.test.ts ties them (it goes red on a changed command text and on a stray testdata file; logs ~/fgr/parity-red-field.log, ~/fgr/parity-red-extra.log). Was: the mock pack and testdata/CVE-2022-27593.json had drifted (MikroTik rule, indicator titles).
- [ ] AI buttons on a real box are locked (`aiOff` in cmd/vedette/wiring.go, 409 `ai_unavailable`); the AI path (Ask my AI, Explain, the AI label after a reload) is checked on the mock only until WP-25 wires the ai module.
- [ ] Findings that come from a scan (`confirmed`, `basis=scan`, evidence with a template) cannot appear on a real box until the scan module sends `scan.finding.confirmed`; the screens that show them (confirmed headline, evidence request/response) are checked on the mock only.
- [ ] `GET /findings` has no paging; a box with 175 Windows CVEs on one device gives 195 rows in one answer. Not measured beyond that; revisit when a box has several thousand.
- [ ] Independent QA walk of the findings screens on the real box (QA.md section 1): not done, the rows in QA.md say "agent built, not independently checked".
- [x] Done in 9693dde: the 3 red findings.spec.ts tests (4 findings in the mock sample instead of 3, 1 on a clean install) came from the box being a device with its own matching packages (D-53); expectations updated, same failure on origin/main.
- [ ] Pending QA: findings-box.spec.ts on the real box after the testdata regeneration (last real run was before it), and the manual form-matrix walk of QA.md section 3.
