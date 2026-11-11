# feat/e2e-real-inventory (WP-30 slice 6)
- [ ] inventory.spec.ts + scope.global.spec.ts: "not approved" panel (approve, mark unknown, alert switch in the panel) is `test.fixme` until a sensor-found device exists in the box (slice 7, branch feat/e2e-real-sensors); copy the steps of e2e/qa/inventory.spec.ts then.
- [ ] Not covered, not built on the box: box packages (S-INV-5, cmd/vedette/inventory.go ponytail), sensors and agents sections of /devices/setup (slice 7, agent-intake not wired).
- [ ] The mock spec e2e/qa/inventory.spec.ts is stale against the GUI: the picker shows no list until the person types (ProductPicker.tsx), and saving changed ranges does not show an "needs confirmation" alert. The real spec follows the GUI; the mock spec was not touched.
- [ ] Picker cap ("N more match"): the box has no KEV list offline, so the catalog is the 151 curated products; the spec searches for a word with more than 30 matches and fails if none exists.
