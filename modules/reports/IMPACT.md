# Reports — Change Impact Map

> Go code in `modules/reports` (definition.go, document.go, service.go, schedule.go, mail.go, pdpl.go); the signatures below are
> the real ones. Ports to other modules are in `ports.go`, their adapters in `cmd/vedette/reports.go`.

## Modifying: `Service.Document(ctx) (Document, error)` (`buildDocument`) — 2 callers
- **HTTP** `GET /reports/document` and **`send`** (`POST /reports/send`, the `report-send` job). The document's shape is
  `contract.ts` `ReportDocument`: a change is a change of the web's Report tab, the print page and every sent report read back from
  `rep_history` (a sent document is never recomputed, so a field added later is absent in older ones: keep new fields optional).
- The golden file `testdata/document_week.golden.json` shows every figure, order and field: a change shows in its diff
  (`go test ./modules/reports -run TestDocumentGolden -update`, then review).

## Modifying: the findings read (`findings.Service.Views`, `View.JSON`, `fnd_finding_event` kinds and details)
- `reportsViews` maps `View.JSON` (device ref, software line, status, severity, verification, fix, handled line) and the state
  events `created`, `handled`, `reopened`, `acceptance_expired`. Handled this period, open at the start and at the end of the period
  are replayed from those events (`historyOf`): a new state-changing event kind, or a handled event that no longer carries
  `from_version`/`to_version`/`note`, changes the report without an error.
- `findings.Views` leaving out ignored devices is what keeps them out of the report.
- The reasons line reads `findings.Service.View` per listed finding (open, layers 1 to 4, at most 100 per list).

## Modifying: `exposure.Service.Tree/Services/Issues`
- `reportsExposure` reads proof state, parent, last scan, service rows (`state`, `first_seen`, `last_seen`, cert expiry) and issue
  rows (`engine`, `severity`, `state`, `first_seen`). A change of these names or meanings changes the External exposure section.

## Modifying: `notify.Service.IncidentsIn(ctx, from, to, top)` / `SendReport` / `EmailReady`
- Detections counts the incidents with activity in the period by kind (the detection kinds; a kind a producer adds later is not
  named) and names the top 5 by severity with their first device. `SendReport`'s errors become the history's fixed messages.

## Modifying: `feeds` `GET /feeds/sources`, `GET /feeds/status`, `feeds.IsStale`
- Coverage lists the enabled vulnerability feeds with their last good pull (status `sources[].fetched_at`, joined by name) and
  staleness by their schedule. A change of those answers changes Coverage.

## Modifying: `core/schedule` (Owner, Fire, Skip)
- `ScheduleOwner` registers `reports.def`; `startSend` runs inside the schedule's transaction and writes `rep_definition.send_due_at`.
  `RunPending` sends outside it.

## Modifying: the PDPL assessment (`GeneratePdpl`, `buildPdpl`, `Regime`)
- **HTTP** `/reports/pdpl/generate`. Changing the rule of `regime` or `measures` changes legal content: check it again against the
  official sources and record the date in CONTRACT. It reads `Findings.All` (the legacy finding projection) and `KEV.Entries`.

## Disabling this module
- The Reports page and the scheduled sends stop; recipients get no report (no error on their side). `rep_*` are kept.
- No module depends on `reports`.

## Modifying: `ai.Service.RunJob(pdpl-assessment)` (through `reportsAI`)
- **ai**: changing `JobResult` breaks the AI comment block; changing the `data: internal` of this job could send organisation data
  to the cloud.

## Modifying: the device type (`content/devicetypes`)
- The PDPL assessment compares the type a device behaves as (`ActsAs`): a VPN gateway is a firewall, a virtual machine is a main
  system (server); counting by type keeps the type id.
