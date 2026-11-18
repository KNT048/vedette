## Summary
A device nobody approved yet now shows its findings, marked "Device not added yet", with Add device and Ignore right on the finding. Ignore hides the device and all its findings for good, including after it is seen on the network again; Findings gets an Ignored tab with Restore. Remove's confirmation says a device still on the network comes back to To review. The device page header and notes are tidied, and the vulnerability-check button says how many suspected findings have a safe check.

## Changes
- Findings (for the findings owner to review): `modules/findings/ports.go` (`AssetView.Approved`, `AssetView.Ignored`), `web/src/features/findings/contract.ts` (`FindingAsset.approved/ignored`), `NotAdded.tsx` (mark + Add device + Ignore), `IgnoredTab.tsx` (Ignored tab, Restore), `FindingsPage.tsx` (mark on list rows, ignored devices' findings only under Ignored), `FindingPage.tsx` (notice with the two actions), `modules/findings/CONTRACT.md` (INV-28), mock + locale entries. No matching or lifecycle rule changed.
- Wiring: `cmd/vedette/wiring.go` passes approved/ignored to findings; `cmd/vedette/notifyfindings.go` names the device "(device not added yet)" in alerts for such a device.
- Inventory: `DeviceRef.Ignored` (`modules/inventory/wiring.go`), INV-51; tests that an ignored device stays the same ignored device when seen again (MAC only, another address, private address folded by host name).
- Device page: not-approved banner has Approve / Ignore / Remove (no "Mark unknown", no duplicate Remove); Remove confirmation text; "Approve all" in To review; header is the name, a "Rename device" icon and the type / last-seen line; Ignore and Remove of other devices are under a "More" menu at the bottom of the page; "Check this device now" and "Run vulnerability checks now" sit in Last checks; one note per cause (no address is said once); "N of M suspected findings can be checked", and with none checkable no run is offered and the note points to the version read by SNMP or an agent, or Confirm on the finding (uses the existing `kev.has_template` of the findings list).

## Tests
- `go test` of `cmd/vedette`, `modules/findings`, `modules/inventory`, `modules/notify`, `modules/mitigation`; `make lint-go`.
- New: `TestWiringFindingsOfADeviceNotAddedYet`, `TestContract_INV38_IgnoredDeviceStaysIgnoredWhenSeenAgain`, `TestContract_INV38_IgnoredDeviceFoldsAPrivateAddressChange`.
- vitest on `src/features/{findings,inventory,scanning,scan}` and `pnpm exec tsc -b`; new web tests for the mark and actions, the Ignored tab, the banner buttons, the Remove text, Approve all, the header, the single no-address note, 0 of 2 and 1 of 2 checks.
- `TestScanningRunNow` failed once under load in the full package run and passes alone.
