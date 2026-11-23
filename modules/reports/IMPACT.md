# Reports — Change Impact Map

> Go code in `modules/reports` (service.go, weekly.go, pdpl.go); the signatures below are the real ones. The gates to other modules are in `ports.go`, the adapters in `cmd/vedette/reports.go`.

## Modifying: `Service.Weekly(ctx) (WeeklyReport, error)` (`buildWeekly`) — 3 callers
- **`Preview`** (`/reports/weekly/preview`), **`WeeklyAI`** (`/reports/weekly/ai-summary`), **`send`** (the scheduled send job and `/reports/weekly/send`): changing the structure of `counts`/`actions` → the GUI `WeeklyDocument` + the print page + the email all change; old history (`HistoryEntry.report`) must remain readable (the figures are stored by schema version).

## Modifying: `buildWeekly` / `buildPdpl` → `computeWeekly` / `computePdpl` + `approvedOnly(weeklyInput)` (INV-16)
- `buildWeekly`/`buildPdpl` compute twice when there are unapproved devices: the full version and `approved_only` (no unapproved devices, no findings of theirs). The second pass reads the fixes again (`fixesFor`) for its top risks; with no unapproved devices it does not recompute. `buildPdpl` calls `computeWeekly` (it does not need the weekly view).
- **web** `features/reports/filters.tsx` (`weeklyView`, `pdplView`) reads `approved_only`, `device_approved`, `not_relevant*`: changing the names/meaning of these fields → the switch on the page, the print page and the history filter wrongly without an error.
- Changing the meaning of `Device.Approved` in the adapter `cmd/vedette/reports.go` (from `inventory` `Approved`) → "devices not in the Devices list" changes accordingly.

## Modifying: `Service.GeneratePdpl(ctx, actor) (PdplReport, error)` (`buildPdpl`, `Regime`) — 1 caller
- **HTTP** `/reports/pdpl/generate`. Changing the rule/computation of `regime`, `measures` → the legal content changes: re-check it against the official source and record the date in CONTRACT.

## Modifying: the data-reading interfaces (`inventory.AllDevices`, `findings.List`, `feeds.Store.KevVulns` / `KevPulledAt`, `feeds.Service.NewlyExploited`, `feeds.DisplayOf`)
- `kev_new`/`kev_matched` are `feeds.Service.NewlyExploited` (the same number as the home page), the product name is `feeds.DisplayOf` (the same name as Findings), and `devices` counts the whole box like the Devices page. Changing one of the three in the other module changes the report accordingly, as intended.
- A `patched` finding that Vedette closed because the device was updated (`fixed_by_update`, `resolved_by=system`) counts as handled and the row's `by` says "Vedette" (INV-13); changing the `resolved_by` of automatic closure → edit `weekly.go`.
- Reports is a **consumer** of `inventory`, findings (core) and `feeds`; changing the semantics of a finding state (`confirmed/suspected/mitigated/patched/false_positive/not_relevant/risk_accepted`; `risk_accepted` is closed but does **not** count towards the week's "handled": `Counts.Accepted`/`AcceptedUntil` and the line "Risk accepted: N (until …)"; needs `Finding.AcceptedUntil`, filled by the adapter `cmd/vedette/reports.go` from findings) or a device type → the report counts wrongly without an error. A contract test is needed in `inventory`.

- `reportsFindings.All` (`cmd/vedette/reports.go`) skips findings of ignored devices and `ClosedForIgnore` findings; `reportsInventory.Devices` skips ignored devices; `reportsKEV.Entries` keeps only the `cisa-kev` list. Changing one of the three changes the report's figures.
- `Finding.Agent` is filled by `cmd/vedette/reports.go` from `findings.Record.Evidence.Agent`; if lost → the report row says "Suspected" again for an agent's finding.

## Modifying: `notify.Service.IncidentsSince` (class of an incident) / `findings.FixedInForAll` (via `reportsRemedies`, `reportsIncidents`)
- **reports**: `modules/logs/authfail.go` titles ("N failed logins from …", "A login from … was ACCEPTED after …") are how notify's `incidentClass` tells failed-login from accepted-login incidents (`TestIncidentsSinceCountsEveryClassBeyondTheListCap`); `findings.GroupFix` kinds `fixed|none|up_to|distro|feature_update|esu` feed the action sentence (`todo.go`; the last two from a Windows release row: "Move … to a Windows release Microsoft still services", "Install the Extended Security Update …"; each its own `class()` and counted as a "fix" step).

## Modifying: `notify.Service.SendReport(ctx, to, ReportMail) error` / `EmailReady`
- **notify**: changing the signature/error → the `status`/`error` in the history are wrong.

## Modifying: `ai.Service.RunJob(weekly-report | pdpl-assessment)` (qua `reportsAI`)
- **ai**: changing `JobResult` → the AI comment block breaks; changing the `data: internal` of these two jobs → organisation data could be sent to the cloud.

## Disabling this module
- The Reports page and the send schedule disappear; recipients no longer receive the weekly report (no error on their side).
- No module depends on `reports`. `rep_*` is kept.

## Modifying: the device type (`content/devicetypes`)
- **Device type**: reads `content/devicetypes` (a leaf package, standard library only). PDPL compares the type it behaves as (`ActsAs`): a VPN gateway is a firewall, a virtual machine is a main system (server); counting by type keeps the type id.

- `Finding.Urgency` (findings' layer, 0 = not stated, reads as exploited): an action sentence says "exploited vulnerabilit(y/ies)" only while every finding of its line is layer 1 or 2, else "vulnerabilit(y/ies)"; the PDPL facts say "Open vulnerability findings". Adapter: `cmd/vedette/reports.go`.
