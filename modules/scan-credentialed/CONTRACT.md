# Scan-credentialed Contract

> Tier: optional · Story: S-SCAN-5 · Last verified: 2026-11-21 (docs first, no code yet; every sentence checked against the code)

Source of behaviour: `web/src/features/scan/CredentialedTab.tsx`, `/scans/credentialed*` in `scan/contract.ts` and `scan/mocks.ts`. The module has no Go code yet (the folder holds only `MANIFEST.yaml`): the items below are design, not yet implemented. The GUI only has account management and the connection test; there is no button to run a scan or view results yet.

## Invariants
- **INV-1**: Scans only machines in the `inventory` scope (confirmed, not in the exclusions) and approved; `selectable=false` → 400 `out_of_scope`. Every connection of the greenbone container goes only to the `host:port` of a stored account (SYS-7).
- **INV-2**: Only for machines with `device_kind ∈ {server, nas, web}` (400 `not_server`); one account per asset (409 `exists`, to change the key it must be deleted and added again).
- **INV-3**: `username` matches `^[a-z_][a-z0-9_-]{0,31}$` (400 `bad_username`); `port ∈ 1..65535` (400 `bad_port`); `private_key` ≤ 16,384 characters and in a valid private key format (400 `bad_key`).
- **INV-4**: The SSH private key is a secret: stored with `core/secrets` (AES-256-GCM), the API returns only `key_last4`, never logged, never in export/backup/log export (SYS-4). Deleting the account deletes the key.
- **INV-5**: `POST …/test`: a 5 second timeout; the result `{ok, ts, message}` is stored in `last_test`, the message contains neither the key nor any part of it.
- **INV-6**: Greenbone runs in its own container, unmodified, not embedded in the binary (GPL/AGPL, legal rule); it is started/stopped only when the module is on, a cosign-signed image pulled by `vedette-host`.
- **INV-7**: Respects the time window, speed and exclusions of `scan`/`inventory`; shares the "Stop now" button of the scan run.
- **INV-8**: Greenbone results are untrusted data (SYS-6): the parser fails closed with size limits; they enter the system only through `findings` with a valid `basis`.
- **INV-9**: Every add/delete/test/scan writes `core_audit` (`scan.credentialed.add|remove|test`), with no secrets.

## Preconditions / Postconditions
- **PRE-1** (`POST /scans/credentialed`): `admin`, INV-1…4. **POST-1**: `CredTarget {id, asset_id, label, host, port, username, key_last4, created_at, last_test:null}` (201); the key sits in `core/secrets`.
- **PRE-2** (`POST …/{id}/test`): `operator`, the account exists (404). **POST-2**: INV-5; returns `CredTarget` with a new `last_test`.
- **PRE-3** (`DELETE …/{id}`): `admin`. **POST-3**: 204; the account and key disappear; old results are kept.
- **PRE-4** (`GET /scans/credentialed`): `viewer`. **POST-4**: `{items, enabled}`; `enabled` reflects the state of the module and the container.

## Forbidden
- **FORBID-1**: Return or log the private key; store the key in clear text.
- **FORBID-2**: Use an account for a machine outside the scope, or one that is not a server/nas/web.
- **FORBID-3**: Embed or modify Greenbone; ship GPL/AGPL in the core.
- **FORBID-4**: Run commands on the target machine beyond what Greenbone does; write nothing to the target machine.
- **FORBID-5**: Use the account's root/sudo rights; a read-only account is recommended (shown in the UI).

## Dependencies
- **DEPENDS ON**: `core` (secrets, audit, `host/client` of `vedette-host`), `inventory`, `scan`.
- **DEPENDED ON BY**: none (consumed by `findings` through events).

## Endpoints owned (minimum role)
| Route | Vai |
|---|---|
| `GET /scans/credentialed` | viewer |
| `POST /scans/credentialed/{id}/test` | operator |
| `POST /scans/credentialed`, `DELETE /scans/credentialed/{id}` | admin |

## Tables owned (`scc_`)
`scc_target` (accounts; the key sits in `core_secret`), `scc_run` (scan runs), `scc_result`.

## Events
- **Emits**: `scancred.run.finished {run_id, findings}`, `scancred.finding.reported {asset_id, cve}` (a proposal).
- **Receives**: `scan.run.stopped` (the Stop now button), `inventory.asset.deleted` (delete the account), `core.module.disabled`.

## Behaviour when off
No `/scans/credentialed*` routes (the tab shows "off" through `enabled:false` in the GUI build), the greenbone container stops, no SSH connection. Accounts and encrypted keys are kept as they are.

## Story and decisions
S-SCAN-5. Transparent licensing; the `greenbone` container is optional. **The v1 build has no backend** (core returns 501 `not_implemented` for `/scans/credentialed*`), so the GUI does not offer this module: no tab in Settings → Scanning (`ScanningPage`), no row in Settings → Modules or the setup wizard, behind the switch `CREDENTIALED_IN_UI = false` (`web/src/lib/credentialed.ts`). The GUI code, contract and mock are kept as they are.

## Mismatches / open questions
- ~~`contract.ts` says "the private key is never stored"~~ The wording in the GUI/contract was fixed: "stored encrypted on the box, never shown again" (`core/secrets`, SYS-4).
- There is no endpoint yet to run a scan or view credentialed results; it is not clear whether it uses `POST /scans/runs` (id `cred:<id>`?) or its own endpoint.
- Pulling the Greenbone NVT feed is a new outbound data flow: it is not yet in `PRIVACY.md` (the legal rule requires updating it in the same commit).
- ~~`MODULES.md` lists the `scan_*` tables~~ `scc_` is settled (manifest, mock `scc_target`).
- The `basis` of a finding from credentialed is not defined yet.
