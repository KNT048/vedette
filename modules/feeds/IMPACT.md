# Feeds: change impact map

What else to check when you change part of this module. Signatures and behaviour are in the code; this file names the readers.

| If you change | Check |
|---|---|
| Product names of ranges and exploited entries (`core/productid`, `Range.MatchRow`, `RangeProducts`, `KevIndex`) | inventory "do you have it" matching and the findings match pass; findings golden tests (`modules/findings/testdata/kev-nvd-*.json`, `equiv-*.json.gz`). |
| Range readers (`Ranges`, `RangesOf`, `Catalogue`, `SchemeRangesOf`, `SchemeCVEs`, `DistroFixesFor`, `DistroCVEs`) or NVD-over-vendor precedence | the findings match pass through `cmd/vedette/wiring.go`; the selfcheck `findings.range_precedence`. |
| Vendor version schemes (`RangeScheme`, `core/versionscheme`, `scheme` in `content/catalog/products`) | which vendor rows become matchable; the brief's fixed releases. |
| `PickCVSS`, `Severity` | the severity shown on every finding, list, report and notice. |
| `Store.Brief` fields | the CVE page and finding page (`web/src/features/feeds/brief.ts`, `cmd/vedette/findingcase.go`), the AI context (`cmd/vedette/ai.go`, `ai_plan.go`), MCP (`cmd/vedette/mcpserver.go`). |
| `feeds_signal` or `feeds_kev` columns, `UrgencyReader`, `ReadSourceNames` | finding urgency (`cmd/vedette/urgency.go`, selfcheck `findings.urgency_recomputed`) and notice text (`cmd/vedette/notifyfindings.go`). |
| Catalogue retention (`retention`, `pruneCatalogue`, the 365-day window, `Deps.Pins`) | `findings.PinnedCVEs`; the selfchecks `findings.cve_in_catalogue` and `findings.catalogue_retention` (same window). |
| Event names or payloads (`service.go`) | the subscribers in `cmd/vedette/wiring.go` (inventory re-match, scan re-scan, baseline handling in notify). A renamed event silently stops re-matching. |
| The custom-feed parser (`ParseFeed`, limits, reject reasons) | `parse-test` and the parser editor: `web/src/features/feeds/parsers.ts` applies the same rules in the browser, and `parse_test.go` (`TestCross_*`) runs the cases of `parsers.test.ts`; golden files in `testdata/golden`. |
| Indicator normalisation or verdict (`IOCKey`, `Judge`, whitelist) | logs indicator hits (`cmd/vedette/logsioc.go`), the AI and MCP `lookup_ioc`. |
| `KevVulns`, `IsStale`, `DisplayOf` | the weekly report (`cmd/vedette/reports.go`). |
| `feeds.Inventory`, `DistroLister`, `PlatformChecker`, `TxSettler` | the adapter `feedsInventory` in `cmd/vedette/wiring.go`. |
| Windows release data (`winrel.go`, `LearnWindowsReleases`) | `core/winrel`, which decides Windows patch levels for findings. |
| The schedule owner `feeds.source` (`feedschedule.go`) | `core/schedule` limits and the shared schedule editor. |
| A built-in source (`sources.go`) | `PRIVACY.md` flow 1 and Settings → Privacy, `THIRD_PARTY_NOTICES.md` for a new data source, `TestHeldNotes_EveryBuiltinFeedIsDecided`, `TestContract_INV1_OnlyDeclaredSources`. A source removed from the list is deleted at start with its rows. |
| A table or column (`migrations/sqlite/0001_feeds.sql`) | `make schema` (`docs/SCHEMA.sql`), the export policy (`modules/core/export_policy.go`), the JSON and value-list allow-lists (`cmd/vedette/schema_rules_test.go`). |
| `DeviceMerged`, `DeviceDeleted` (`devicelifecycle.go`) | runs inside inventory's write transaction: write only `feeds_*`, never publish. |

## Switching the module off

Routes and the pull job stop; tables stay. Findings keep matching against what is stored, with no new exploited entries or ranges.
Logs stops getting new indicators. Nothing else fails.
