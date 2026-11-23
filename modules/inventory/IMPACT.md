# Inventory: change impact map

What else to check when you change part of this module. Signatures and behaviour are in the code; this file names the readers.

| If you change | Check |
|---|---|
| Observation precedence (`merge.go`: `sourceRank`, `better`), `RecomputeAsset` | every device field on every page; `TestContract_*` in `contract_test.go`; the selfcheck `inventory.chosen_observation_is_the_devices_own`. |
| `core/observe` types or the sinks (`Record`, `ReplaceSoftware`, `ReplaceServices`, `AddServices`) | the writers: sensor-passive (`cmd/vedette/sensorpassive.go`), sensor-active, agent-intake. |
| Identity rules (`join.go` `sameDevice`, `sameMachine`, `claimIP`, `ipTrust`, `inv_hand_seen`) | duplicate or wrongly joined devices; every module's rows move through `core/lifecycle` on a join. |
| Addresses, merge and split (`addresses.go`, `mergesplit.go`, `inv_asset_address`) | the selfcheck `inventory.address_has_one_home`; lifecycle participants (`cmd/vedette/devicelifecycle.go`); the Devices list and device page in `web/src/features/inventory`. |
| A lifecycle call (`joinAs`, `DeleteDevice`, `ForgetBoxOwned`) | every participant registered in `cmd/vedette/devicelifecycle.go` (findings, mitigation, notify, response, connections, feeds, ids, agent-intake, sensor-active). They run inside inventory's transaction. |
| Software identity (`product_key` from `core/productid`, `line`, `identify`) | the findings match pass and its golden tests (`modules/findings/testdata`); the selfchecks `inventory.one_line_per_product_and_train`, `inventory.line_is_the_train_of_its_readings` (Go, `selfcheck.go`: every reading's release is of its line's train). Changing the product catalogue (`content/catalog/products`) re-resolves stored lines. |
| The resolver (`resolve.go` `Resolve`, `settleLine`, `lapse.go`) | the effective version every reader sees; selfchecks `inventory.line_value_is_the_resolvers` (Go, `selfcheck.go`: `Resolve` recomputed on every line, the same code the fixture tests' `assertResolved` runs), `inventory.present_line_has_a_reading`, `inventory.removed_line_has_no_reading`; patch credit in findings (`version_moved`). |
| `SoftwareLine`, `MatchInput`, `MatchDevice` fields | findings through `cmd/vedette/wiring.go` (match pass, finding page, device page counts). |
| `DeviceRefs`, `AllDevices`, `DevicesOfKind`, `AssetIDs`, `BoxName` | notify, scan, sensor-active, audit names, response, ai, logs, reports, honeypot, the exposure gateway. A reader that returns a short list makes findings or response act on missing devices (INV-18/19/21). |
| `ReadIgnoredIDs`, `ReadDeviceIDs` (readers on a bare handle, no service) | the selfchecks registered in `cmd/vedette`: `findings.urgency_recomputed` (`urgency.go`) and `sensor-active.no_pending_run_about_a_deleted_device` (`devicelifecycle.go`). A short list makes the selfcheck count rows of devices that exist. |
| `ScanPolicy`, `VulnScanPolicy`, `ProtectedIPs`, `Checks`, the `active` settings | sensor-active (`owed.go`, `runnow.go`, `allports.go`), scan (`targets.go`, `reach.go`, `config.go`): what may be scanned and how fast. |
| Per-device sources (`scan_source`, `snmp_source`, `agent_source`, `devicesources.go`) | sensor-active and scan policies, agent-intake's refusal of agent data, the Sources card. |
| Ignore, approve, quiet devices (`SetIgnored`, `ApproveEnrolled`, `quiet.go`) | notify's new-device incidents, findings' lists of ignored devices, the To review count. |
| `AddManualDevice`, `Settle`, `DevicesRunning` | feeds "I have this" and the hot table (`cmd/vedette/wiring.go`). |
| `SetupScope` | core's first-run setup (`modules/core/handlers_setup.go`). |
| Device kinds (`content/devicetypes/types.json`, `rules.json`) | fragility, scanning templates, the kind picker in the web UI. |
| Catalogue (`content/catalog/curated.json`, `kev-products.json`, `Catalog.Curated`) | the Add software picker, the reach audit (`cmd/vedette/reach.go`). |
| Event names or payloads (`types.go`) | the subscribers listed in `CONTRACT.md` (notify, scan, sensor-active, findings, feeds). |
| A table or column (`migrations/sqlite/0001_inventory.sql`) | `make schema` (`docs/SCHEMA.sql`), the export policy (`modules/core/export_policy.go`), the schema allow-lists (`cmd/vedette/schema_rules_test.go`). |

## Switching the module off

Routes stop; tables stay. Sensors and agent-intake depend on inventory and stop with it. Findings keeps its rows but gets no new
matches; scan has no internal targets; feeds answers `you_have: null`.
