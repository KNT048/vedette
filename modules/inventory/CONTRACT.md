# Inventory contract

> Tier: standard · Stories: S-INV-1…5 · Tables: `inv_*` ([`docs/DATA_MODEL.md`](../../docs/DATA_MODEL.md) 4.2, 5.1)

Inventory is the one list of devices and the software they run. Sensors, agents and people report through `core/observe` and the
inventory service; everything else reads devices and software lines through inventory's Go ports, never its tables.

## Endpoints

| Route | Minimum role |
|---|---|
| `GET /inventory/devices`, `/inventory/devices/{id}`, `/inventory/devices/{id}/sources`, `/inventory/possible-same`, `/inventory/catalog`, `/inventory/export.csv`, `/inventory/import-template.csv` | viewer |
| `POST /inventory/devices`, `PATCH`/`DELETE /inventory/devices/{id}`, `POST /inventory/devices/{id}/approve`, `…/suspicious`, `…/ignore`, `…/software`, `…/differs/{field}/use`, `…/differs/{field}/keep`, `PATCH`/`DELETE /inventory/devices/{id}/software/{sid}`, `POST /inventory/import`, `PUT /inventory/notify-new` | operator |
| `GET`/`PUT /inventory/settings`, `PUT /inventory/devices/{id}/sources`, `POST /inventory/devices/{id}/merge`, `GET /inventory/devices/{id}/merge-preview`, `POST /inventory/devices/{id}/split`, `POST /inventory/devices/{id}/keep-separate` | admin |

The other `/inventory/*` routes belong to the modules that serve them: `/inventory/agents/*` (agent-intake), `/inventory/snmp/*`
(sensor-active), `/inventory/sensors/*` (sensor-passive). Shapes: `web/src/features/inventory/contract.ts`.

## Invariants

IDs are stable (code comments cite them); a retired ID is not reused. Where one function holds a rule, the line names it and the
detail is in its doc comment.

**Writing**
- **INV-1** Observations are append-only (a trigger refuses changing a value). A device field's value is the winning observation
  by the precedence of DATA_MODEL 5.1 (`merge.go`), written only by `RecomputeAsset` in the same transaction.
- **INV-2** Every write to `inv_*` goes through `inventory.Service`.
- **INV-16** At most 32 observations per (device, field, source); `Record` trims the oldest in the same transaction.
- **INV-17** An address the box answers for itself (the honeypot decoys, `Config.BoxOwnedIPs`) is never a device: observations
  and lists for it are dropped.
- **INV-22** Text from sensors and agents is untrusted: `cleanText` drops control, format and invisible characters.
- **INV-23** Open services are written only by `ReplaceServices` (replaces the source's rows within its scan scope and address)
  and `AddServices` (adds, never deletes). Services no source reports for 90 days are deleted.
- **INV-43** Only source `snmp` may name an existing device directly in its hint (an answer from that device's read address).

**The box**
- **INV-3** Exactly one device is the box (`is_box`), created at install with its own package list; it cannot be deleted
  (409 `box_device`) or have its sources switched.

**Identity: one machine, one device**
- **INV-29** A switch, router, access point or firewall seen only by MAC joins exactly one device with an address that does not
  state otherwise (`sameDevice`).
- **INV-31** Two rows with private (locally administered) MACs and the same specific host name are one machine (`sameMachine`).
- **INV-35** An address is an attribute, never the identity: a device added by hand binds a sensor's MAC at its address only when
  that is a burned-in MAC, the address was confirmed by a person within 72 hours, and it is the first and only MAC seen there.
- **INV-34** What the join rules cannot decide, a person does: "possibly the same device" pairs, merge, and keep separate
  (`inv_separate`; a kept pair is never offered again).
- **INV-57** A device has one main address (`inv_asset.ip`/`mac`) and any number of other addresses (`inv_asset_address`). An IP or
  a MAC has one home (selfcheck `inventory.address_has_one_home`). A person can merge devices (preview first) and split an
  address off into its own device.
- **INV-53** A merge or delete calls every `core/lifecycle` participant inside inventory's write transaction, so every module's
  rows change with the device or none do. A merge folds colliding rows instead of dropping them.

**Software lines**
- **INV-54** One `inv_software` row per installed software line: unique on (device, `product_key`, `line`); the id never changes
  (a version move is an update with a `version_changed` event). Readings per source are `inv_software_reading`; history is the
  append-only `inv_software_event`. Removal is a state; a removed line is deleted after 400 days.
- **INV-52** The effective reading is written only by `Resolve` (`resolve.go`), in every write path: a person's entry holds until
  a reading first seen after it reads a newer release; otherwise the strongest source, newest release among equals.
- **INV-50** `SoftwareLine` is the one read model of a device's software: the device page reads it, and other modules get it
  through `cmd/vedette/wiring.go`, never from the readings.
- **INV-24** Agent readings (osquery, Wazuh) not reported again for 30 days are deleted (the job counts only while inventory and
  agent-intake are on).
- **INV-28** `inv_source` records when each source first reported (the "still learning" window). An agent's packaged row keeps the
  full package version and source package for distribution matching.
- **INV-41** A person corrects what a device runs (OS, a software's version); the correction drives matching until cleared or
  lapsed (INV-52). A person can mark a line not installed; it holds until a reading first seen after the mark.
- **INV-42** nmap's OS guess is stored and shown but never matched, and is used only when nothing better names the OS.
- **INV-44** What a device states about itself (LLDP on its own vendor's card, SNMP) ranks above a scan's guess.
- **INV-45** An OS or firmware a person declared is a software line the matcher reads as the device's OS, and a stored decision on
  the device.
- **INV-10** A product added by hand is matched against the exploited lists at once (`KEV` port); `inventory.match.changed` is
  emitted only for a newly matched CVE.
- **INV-15** `DevicesRunning` answers "yes" for an exact product key and "maybe" for a vendor-only match of a "multiple products"
  entry.
- **INV-30** `MatchInput` also gives the newest agent-reported and SNMP-reported OS, even when a person's value wins the field.

**Devices and people**
- **INV-4** A device added by hand: a unique IPv4, bounded name, vendor, product and version; a duplicate software is 409.
- **INV-5** A device added by hand is not scanned or read by SNMP until a person turns that source on (see INV-37).
- **INV-37** Network scan and SNMP are on, off or default per device (`scan_source`, `snmp_source`; default on for a discovered
  device, off for one added by hand). A change is audited.
- **INV-56** The agent source can be switched off per device; while off, every agent's data for that device is refused.
- **INV-55** A device's three sources (network scan, SNMP, agent) and their states are decided on the server
  (`GET /inventory/devices/{id}/sources`).
- **INV-9** A device a sensor finds is not approved and is listed under To review; `inventory.asset.discovered` is always emitted.
- **INV-49** A device with only private Wi-Fi addresses that shows nothing to look at is listed but not To review and sends no
  new-device notice; once it shows a reason, its review is sticky (`review_earned_at`).
- **INV-25** An osquery machine's first report approves the device it enrolled for (`ApproveEnrolled`, called by agent-intake).
- **INV-26** `approved_at` is set by a person's approval or an agent's first report. One naming rule gives every device its shown
  name.
- **INV-36** The name a person gives (`user_name`) is separate from the host name the network reports.
- **INV-38** An ignored device is known, not watched: every scan and SNMP policy reads its sources as off, and its findings are
  listed apart. Ignoring changes no stored setting, so un-ignoring restores them.
- **INV-51** `DeviceRefs` says both whether a device is approved and whether it is ignored.
- **INV-46** A device's manual-source time is when a person last entered something, never a report.
- **INV-47** A value a person entered keeps winning; the device page says when a trusted source reads another (`detected_differs`),
  and the person can use it or keep theirs (`inv_detected_keep`).
- **INV-11** Deleting a device deletes its findings (the count is shown first).
- **INV-27** Device kinds come from `content/devicetypes/types.json`; each kind acts as one of the base kinds for fragility and
  scanning.
- **INV-20** `TrustedKind` is true for a kind from a person or an agent, or from SNMP/nmap on an approved device.
- **INV-40** The device badge comes from findings (`RiskSource.DeviceStatuses`); with findings off no device has one.
- **INV-48** `SimilarDevices` lists devices sharing a maker or known kind (read-only, for sensor-active's SNMP settings).

**Scanning scope and safety**
- **INV-6** LAN ranges: at most 16, each with an explicit prefix and no host bits, private (RFC 1918) or shared (100.64.0.0/10)
  only.
- **INV-7** Turning on active scanning needs at least one range, one day and a confirmed scope (who and when are stored).
- **INV-8** A fragile or unclassified device is scanned lightly once when first seen, afterwards only passively.
- **INV-32** `active` is the one store of the safety settings every LAN engine shares (window, exclusions, rates).

**Lists and readers**
- **INV-12** `GET /inventory/catalog` returns at most 30 entries with a total; curated ids are fixed, exploited-list entries are
  `kev:<vendor>:<product>`.
- **INV-13** CSV import: at most 200 KB and 500 rows; bad rows are reported by number and valid rows still added.
- **INV-14** `AddManualDevice` runs inside the caller's transaction (feeds); its event waits for `Settle` after the commit.
- **INV-18, INV-19, INV-21** Readers that other modules use to decide (`DevicesOfKind`, `AssetIDs`, `AddressInUse`, `AddressMap`,
  `KnownMACs`, `AllDevices`, `BoxName`) read every row with no list limit, and return an error, never a short list.
- **INV-33** The device list and the CSV export take the same filters; a list row carries counts, never the software lines.
- **INV-39** `AgentDevice` gives agent-intake a device's agent key and addresses for "ask the agent now".

## Preconditions and postconditions

- **PRE-1** `Record`: a non-manual source, a known field, confidence 0–1, a printable value. **POST-1**: the device is found or
  created unapproved; current values recomputed.
- **PRE-2 / POST-2** `ReplaceSoftware`: a source allowed to send lists; replaces only that source's readings in its scope, then
  resolves every touched line (INV-52). An OS guess is stored without a match key (POST-2d); an item with a CPE but no key takes the
  curated product of that CPE (POST-2c).
- **PRE-2b / POST-2b** `ReplaceServices`, `AddServices`: a hint with a MAC or an IPv4; the device is found by MAC, then IP, or
  created unapproved.
- **PRE-3 / POST-3** `ScanPolicy`: whether discovery may scan a device, at what rate, and why (INV-5, 7, 8); never the box.
  `VulnScanPolicy` (PRE-3b): `explicit` only when a person picked exactly this device. POST-3c/3d: the careful and fragile flags.
- **PRE-4 / POST-4** `PATCH /inventory/devices/{id}`: operator; a kind or fragile edit adds a manual observation; a name sets
  `user_name`.
- **PRE-5 / POST-5** `PUT /inventory/settings`: admin, INV-6/7; keeps the scope confirmation when ranges do not change; emits
  `inventory.settings.changed`. PRE-5b: `SetupScope` runs only inside core's setup transaction.

## Forbidden

- **FORBID-1** Overwriting or deleting an old observation (except INV-16's trim).
- **FORBID-2** Deleting the box device.
- **FORBID-3** Guessing the prefix of a network range.
- **FORBID-4** Another module reading or writing `inv_*` tables.
- **FORBID-5** Sending device data off the box except through a module the customer configured (ai, notify).

## Events

| Event | Subscribers |
|---|---|
| `inventory.asset.discovered` | notify (new-device incident), sensor-active (first light scan), findings and feeds (`wiring.go`) |
| `inventory.asset.updated` | notify, scan (stop scanning a device no longer allowed), sensor-active, findings, feeds |
| `inventory.asset.deleted` | sensor-active |
| `inventory.asset.approved`, `inventory.asset.ignored` | notify |
| `inventory.software.changed`, `inventory.match.changed` | findings (match pass for the device) |
| `inventory.settings.changed` | sensor-active, the module container wiring |
| `inventory.asset.merged`, `inventory.asset.unignored` | none today (merges are handled by `core/lifecycle`) |

Inventory listens to `findings.finding.created`, `findings.finding.urgency_raised` and `honeypot.hit.created` (a device earns review),
and to the feeds events (re-match: `feeds.vuln.new_kev`, `feeds.vuln.updated`, `feeds.ranges.updated`, `feeds.sync.baseline`).

## Dependencies

- **Depends on**: `core`, `feeds` (the `KEV` port for matching and the catalogue; with feeds off the catalogue uses
  `content/catalog/kev-products.json` and matches nothing). Optional: agent-intake (`WazuhAgentAddresses`), honeypot (`DecoyIPs`), findings (`DeviceStatuses`).
- **Used by** (adapters in `cmd/vedette`): findings (`MatchInput`, `SoftwareLines`, `DeviceRefs`, `AssetIDs`), sensor-active
  (`ScanPolicy`, `SimilarDevices`, `AddressMap`, `KnownMACs`), scan (`VulnScanPolicy`, `Checks`), feeds (`AddManualDevice`,
  `DevicesRunning`), agent-intake (`ApproveEnrolled`, `AgentDevice`), response, ai and logs (`DevicesOfKind`), reports, ai,
  honeypot and the exposure gateway (`AllDevices`), notify and audit names (`DeviceRefs`), core setup (`SetupScope`), the reach
  audit (`Catalog.Curated`).

## When off

No routes; the Devices list is empty; sensors and agent-intake have nowhere to write; findings gets no new matches; scan has no
internal targets; "Do you have it?" is `null`. Data is kept.
