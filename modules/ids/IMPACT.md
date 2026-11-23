# Ids — Change Impact Map

> Package `modules/ids`. Entry gates: `Inventory`, `Findings`, `Incidents`, `Publisher`, `Modules`; wired in `cmd/vedette/ids.go`.

## Modifying: `Parse` / `profileKinds` / a vendor's format
- Adding or changing a format: add a line to `testdata/ips_lines.json` (documentation addresses, example.com) for both lines that are events and lines that are not; `TestCountIPSLinesPerProfile` prints the count per profile. A new source type must be a `KIND_IDS` of the logs module (`content/logs/kinds.json`).
- `NativeIPS` decides the overview's `ips_events` watcher (`cmd/vedette/detection.go`) and the mock's `IPS_KINDS` (`web/src/features/detection/mocks.ts`): change them together.

## Modifying: `Attacked(ctx, since)` — the gate for findings
- The only reader: the `idsFindings` adapter in `cmd/vedette/ids.go` (`recentlyAttacked`, window `AttackWindow`), which maps findings' state to `under_attack`/`exploited` for `Findings.Linked`; the findings module does not call `Attacked`. Changing the grouping of rows (CVE, destination address) or the meaning of `since` → the finding state in the alert and the critical level become wrong without an error.

## Modifying: the event `ids.alert.detected` (`AlertEvent`)
- **notify** (`modules/notify/events.go` `intrusionEvent`): reads through the JSON `source, target, title, what, action, severity, link, at, devices`; `link` must start with `/detection/`. Changing `IncidentKey` → the old incident is no longer counted further and the alert's `incident` read (notify `IncidentOf`) loses its link.

## Modifying: `Findings.Linked` (the merge gate: device → CVE)
- Installed in `idsFindings` (`cmd/vedette/ids.go`), reads `findings.Service.List` of each device.
- Called once per page, per `Summarize` and per flush (not per device); the `idsFindings` adapter reads `Attacked` once per call.
- Devices a person ignored are left out (one `inventory.IgnoredIDs` read per call): their findings never make an alert critical or count as affected. `TestWiringIPSEventAtAnIgnoredDeviceIsNotCriticalOrAffected`.

## Modifying: `Inventory.DevicesAt`/`Names` (the device gate)
- `idsInventory` combines `logsInventory` (cmd/vedette/logs.go: IPs in the list and addresses read through SNMP from sensor-active `ReadAddresses`; two devices with the same address → no device) and `notifyDevices.DeviceStates` for names. Changing the address-matching rule in logs → the alert's devices change accordingly.

## Modifying: `List`/`Get`/`Summarize`
- **web/features/detection** (`contract.ts` is the contract; the handler's `into`, through `core/api/apijson.Into`, rejects a response that drifts from the schema and writes an empty list as `[]`, never `null`). `Summarize` → the overview (`alerts.total/affected`, the `ips_events` watcher) in `cmd/vedette/detection.go`, together with `NativeIPS`.
- The `/detection/alerts*` routes are tied to the module in `core/server/modules.go` and `web/src/lib/apiModules.ts` (404 when the module is off); `cmd/vedette/handler.go` embeds `IDSHandlers`, `cmd/vedette/modules.go` registers migrations + jobs, `cmd/vedette/devicelifecycle.go` registers `DeviceMerged`.

## Modifying: `logs.Config.Received` (module logs)
- `cmd/vedette/ids.go` `idsReceived` connects it to `Offer` (only lines of the source type `Reads`).
- Called after the batch commit with the cleaned line; if logs changes when it calls or the content of `Text` (for example cuts differently), INV-1 of ids (a truncated line is not read) must change with it.

## Modifying: `Attacked` / `ReadAttacked` (layer 1 of a finding's urgency)
- findings' urgency pass reads `ReadAttacked(since now − 14 days)` while the module is on; a finding becomes "under attack here" for an
  attack aimed at its device or at any address while the device is affected. The selfcheck reads the same function as of the last pass.

