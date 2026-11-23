# Scan-credentialed — Change Impact Map

## Modifying: `scancred.Service` — `Targets()`, `Add(ctx, in)`, `Remove(ctx, id)`, `Test(ctx, id)`
- **SPA** (`CredentialedTab`, hidden in v1 behind `CREDENTIALED_IN_UI` of `web/src/lib/credentialed.ts`: turn it back on when there is a backend; the module has no Go code yet; `ScanningPage` (Settings → Scanning), `ScansMoved`, and `ModulesSection`/`SetupPage` through `notOffered` of `web/src/lib/v1.ts`, which reads the switch), **core/audit**. Changing the error codes (`not_server`, `exists`, `bad_key`) changes the UI messages; `scan/contract.ts` is the OpenAPI source.

## Modifying: key storage through `secrets.Seal` (purpose `scc_target.private_key`, as the `core_secret` table records)
- **core** (`/core/data/export|backup` must exclude it). Changing the purpose loses the old keys on upgrade: a migration is needed.

## Modifying: running the `greenbone` container and the signed image (not built yet; design)
- **cmd/vedette-host**, `host/client`: the fixed command list must include this operation (`exposure` already uses Greenbone through its own `GreenboneHost`; that operation is not shared with this module); adding a permission = a security change.

## Modifying: calling `Settings.InScope` of `inventory` and `scan` (window, Stop now)
- **inventory**, **scan**: widening the scope there widens the credentialed scan scope.

## Modifying: results → `findings` (`basis`)
- **findings**: a `basis` value must be added if credentialed creates a finding; changing the `basis` enum changes `findings/contract.ts`.

## Disabling this module
- The Credentialed tab of Scans says "off"; the greenbone container stops; no SSH connection.
- No module depends on it, so no other module loses a function; findings from an earlier credentialed run are kept. Accounts and encrypted keys are kept.
