# Changelog

All notable changes to Vedette are recorded here. Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions follow [Semantic Versioning](https://semver.org/). Maintainers add an entry in every PR that changes behaviour; releases are tagged by a human (the AI never creates tags).

## [Unreleased]

### Upgrade notes
- `notify` migration 0006: one approver address on a channel now belongs to one person. When an existing box upgrades, approver rows that share an address on the same channel are deleted, because a reply or button press from that address could never be matched to one person, so they could not approve anything. The channel's other approvers stay. Open Settings, Alert channels after the upgrade and add each deleted approver again with an address of their own. Zalo personal approvers saved with a phone number are kept but skipped (`notify.approval_skipped`) until the address is changed to a Zalo user ID.

### Changed
- `POST /auth/login`: the right password of a two-step account sent without its code now answers 200 `{"ok": false, "twofa": {"method": ...}}` (for the email method also `sent_to` and `resend_after`) instead of 401 `twofa_required`, so a normal two-step sign-in no longer logs an error in the browser console. A script that signs in with two-step should read `ok` and send the code when it is false. A successful sign-in answers `{"ok": true}` as before.

### Added
- SNMP credentials take an optional UDP port (1 to 65535; empty = 161) for devices that answer SNMP on another port; Test, Read now and the scan window's reads use it, and the answer and the "no answer" reason name the port tried (`sensor-active` migration 0009).
- Complete web GUI on a mock API (MSW, Zod contracts, `api/openapi.json`) for every user story.
- M2-0 specs: architecture, deployment (container appliance), data model, API conventions, module contracts, protocol specs, action template library, engineering handbook, runbook skeleton, team plan.
