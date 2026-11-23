# Findings: change impact map

What else to check when you change part of this module. Signatures and behaviour are in the code; this file names the readers.

| If you change | Check |
|---|---|
| The matcher (`match.go` `MatchAsset`, `matchpass.go`, `distro.go`, `windows.go`, `platform.go`, `schemes.go`, `vendorscheme.go`) | the golden and equivalence fixtures in `testdata/` (`kev-nvd-*.json`, `equiv-*.json.gz`); exposure, which matches services at scan time with the same function (`cmd/vedette/exposurematch.go`); selfchecks `findings.matched_version_on_line`, `findings.range_precedence`. |
| What the match reads from inventory (`Asset`, `Software`, `MatchInput` fields) or feeds (`Vuln`, `MatchSet`) | the adapters in `cmd/vedette/wiring.go`; inventory's `SoftwareLine` and feeds' range readers. |
| `Transition` or the trigger list (`transition.go`) | `TestTransition_EveryStateAndTrigger`, `TestTransition_InvariantsHoldForAnySequence`; the database CHECKs in `migrations/sqlite/0001_findings.sql`; the selfchecks `findings.handled_complete`, `findings.version_moved_versions`. |
| `via` values or patch credit (`goneVia`) | the report's handled section (`cmd/vedette/reports.go` reads `fnd_finding_event` kinds and `via`); `TestCredit_*`; the selfcheck `findings.vocabulary`. |
| `FixOf`, `fix_key` | By fix, the finding page and the selfcheck `findings.fix_key_names_stored_fix`; exposure's fix line. |
| `Urgency`, `RateUrgency`, `Tell` | `cmd/vedette/urgency.go` (signal and attack inputs), notify's alerts and first-run summary, response rules, the SIEM export, the selfcheck `findings.urgency_recomputed`; `testdata/urgency-samples.json`. |
| `View`, `StatusOf`, `DeviceStatusOf`, `LayerCode` | the web (`web/src/features/findings`), inventory's device badge (`cmd/vedette/inventory.go`), notify (`notifyfindings.go`), reports, ai (`ai.go`, `ai_plan.go`), mcp-server (`mcpserver.go`), ids (`cmd/vedette/ids.go`). |
| The status lines of a list row (`listViews`, `cveRow`, `reasonsOf`) or their text (`View.ReasonsLine`, `View.VerificationLine`) | the web's one status component (`web/src/components/common/status/FindingStatusLines.tsx`) on By device, the device's Findings tab, Home, the finding page and the report; the locale parity tests in `noticetext_test.go`; notify's alert text (`cmd/vedette/notifyfindings.go`). |
| The list SQL (`lists.go`, By device, By fix, Needs your input) | Home (`overview.go`) totals; `TestModelAPI_*` and the contract conformance tests in the web. |
| Lifecycle handlers (`lifecycle.go`: `DeviceMerged`, `DeviceDeleted`, `LinesDeleted`) | they run inside inventory's transaction: write only `fnd_*`, never publish; mitigation, notify and response fold their rows by finding id through `FindingFolded`. |
| Event names or payloads (`ports.go`) | notify (`modules/notify/events.go`), response (`modules/response/events.go`), logs' SIEM export (`modules/logs/siem_run.go`), inventory (`cmd/vedette/wiring.go`). |
| `findings.Guidance`, `FindingHandlers`, `Record` (the older read model in `legacy.go`, `guide.go`) | mitigation (`modules/mitigation`), which fills "What to do" on the finding page and serves `applied` and `ai`. |
| `PinnedCVEs` | feeds' catalogue retention (`cmd/vedette/feeds.go`). |
| `content/catalog/platform-limits.json`, `network-os.json`, `content/catalog/products` | the matcher's platform, network OS and alias rules; their data tests (`TestPlatformLimits_DataIsValid`, `TestNetworkOS_*`). |
| A table or column (`migrations/sqlite/0001_findings.sql`) | `make schema` (`docs/SCHEMA.sql`), the export policy (`modules/core/export_policy.go`), the schema allow-lists (`cmd/vedette/schema_rules_test.go`), mitigation's foreign keys to `fnd_finding(id)`. |

## Switching the module off

Routes and jobs stop; tables stay. Mitigation depends on findings and is reported affected. Notify sends no vulnerability alerts;
inventory shows no badges; reports lose the vulnerability section. When it is switched on again, the `reconcile` job matches
every device again.
