# Inventory contract

> Tier: standard · Stories: S-INV-1…5 · Tables: `inv_*` ([`docs/DATA_MODEL.md`](../../docs/DATA_MODEL.md) 4.2, 5.1)

Inventory is the one list of devices and the software they run. Sensors, agents and people report through `core/observe` and the
inventory service; everything else reads devices and software lines through inventory's Go ports, never its tables.

## Endpoints

| Route | Minimum role |
|---|---|
| `GET /inventory/devices`, `/inventory/devices/{id}`, `/inventory/devices/{id}/sources`, `/inventory/possible-same`, `/inventory/catalog`, `/inventory/export.csv`, `/inventory/import-template.csv`, `/inventory/removed` | viewer |
| `POST /inventory/devices`, `POST /inventory/box/check` (the box reads its own packages now), `PATCH`/`DELETE /inventory/devices/{id}` (`?agent=stop` admin, INV-59), `DELETE /inventory/removed/{id}`, `POST /inventory/devices/{id}/approve`, `…/suspicious`, `…/ignore`, `…/software`, `…/differs/{field}/use`, `…/differs/{field}/keep`, `PATCH`/`DELETE /inventory/devices/{id}/software/{sid}`, `POST /inventory/import`, `PUT /inventory/notify-new` | operator |
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
  (409 `box_device`) or have its sources switched. It reads its own packages and ports every hour (`BoxEvery`); its device page
  shows that as its agent row (last and next read) with Check now (`POST /inventory/box/check`, operator).

**Identity: one machine, one device**
- **INV-29** A switch, router, access point or firewall seen only by MAC joins exactly one device with an address that does not
  state otherwise (`sameDevice`). A card seen at an address of its own whose MAC is the chassis MAC such a join left on a device with
  an address is that device's card (`chassisCard`): its address and MAC become one of the device's other addresses, and the
  device's main address stays.
- **INV-31** Two rows with private (locally administered) MACs and the same specific host name are one machine (`sameMachine`).
- **INV-35** An address is an attribute, never the identity: a device added by hand binds a sensor's MAC at its address only when
  that is a burned-in MAC, the address was confirmed by a person within 72 hours, and it is the first and only MAC seen there.
- **INV-34** What the join rules cannot decide, a person does: "possibly the same device" pairs, merge, and keep separate
  (`inv_separate`; a kept pair is never offered again). A device added by hand without any address and a found device that run
  the same OS or firmware at the same version or build are offered as such a pair (`same_os`): nothing on the wire ties them. It
  is offered only when that found device is the only one running that release (devices a person kept separate from it left out):
  a fleet of hosts at one build is normal, and the reason says what matched (the same OS, version and build).
- **INV-57** A device has one main address (`inv_asset.ip`/`mac`) and any number of other addresses (`inv_asset_address`). An IP or
  a MAC has one home (selfcheck `inventory.address_has_one_home`). The main address is the one the Devices list and the device
  page show, and the one runs and SNMP reads go to. A burned-in main card seen at another address within 10 minutes of answering at its
  main address has both: the other address becomes an address of the main card (`main_card`), and later sightings at either, in
  any order, never move the main address while the main address answers (within 72 hours, since the card was first seen at the
  other). Where the card stays at the other address and the main address stops answering, the other becomes the main one once and
  the old one stays listed. A card seen at a new address later than that moved (DHCP), and the main address follows it; an agent,
  a device an agent is bound to and a private MAC follow their reports as before. Another MAC seen at an address of the main card
  is another machine. A person can merge devices (preview first) and split an
  address off into its own device. A person's merge keeps what each merged device brought (`inv_merged_from`,
  `inv_merged_reading`): splitting off that device's interface gives it back with its id, its origin (a device added by hand
  stays added by hand), its name in Vedette, its maker, model, host name, type and OS (at least the strongest observation of each
  series when there are more than the record holds), and its software readings (a line it brought whole goes back whole, with its
  id and history), so its findings follow its software again; the kept device gets back its own name, and the type and OS a person
  set on it, when the merge changed them and nobody changed them since. The preview lists
  the type and OS rows also when only one device states them (the other's type as the rules guess it, or none).
- **INV-53** A merge, split or delete calls every `core/lifecycle` participant inside inventory's write transaction, so every module's
  rows change with the device or none do. A merge folds colliding rows instead of dropping them. A split names every software line of
  the device that stays whose readings went to the device split off (`lifecycle.Split.Software`, with whether
  the device that stays still has that software); a line that moves whole keeps its id and is named mapped to itself, gone. It also
  names the device split off as Devices shows it and its main address (`IntoName`, `IntoIP`), which a participant cannot read through
  the inventory's ordinary reads inside the write.

**Software lines**
- **INV-54** One `inv_software` row per installed software line: unique on (device, `product_key`, `line`); the id never changes
  (a version move is an update with a `version_changed` event). Readings per source are `inv_software_reading`; history is the
  append-only `inv_software_event`. Removal is a state; a removed line is deleted after 400 days. Of a product whose trains install
  side by side, a reading without a release and a train are one line (`lineOf`, and `joinTrains` for lines stored apart before):
  a reading without a release joins the device's line of a train of the product, and the first train read of a line that holds
  only readings without a release becomes its train in place (id kept).
- **INV-52** The effective reading is written only by `Resolve` (`resolve.go`), in every write path: a person's entry holds until
  a reading first seen after it, or an agent's report after it, reads a newer release (history `entry_lapsed`, audit
  `inventory.software_correction_lapsed`); a source that reads another release after the entry that is not newer leaves it, said
  once per source and release (history `entry_kept`, audit `inventory.software_correction_kept`); otherwise the strongest source,
  newest release among equals. A person's entry without a version names the product, never its release: when a source (not nmap's
  guess) reads a release of the line, that source's release is the line's value under the person's name for it, the entry stays
  a reading (the line stays the person's, `personsLine`), and nothing asks the person for a version the device states. A version is stored as its product's version scheme writes it (`statedRelease`: ESXi "8.0 U3" is "8.0.3" with its
  build in the name, DSM "7.2.1-69057 Update 5" is "7.2.1-69057-5", Debian's "X+reallyY" is Y). The selfcheck
  `inventory.line_value_is_the_resolvers` recomputes `Resolve` on every line, and `inventory.line_is_the_train_of_its_readings` checks
  that every reading's release is of its line's train (`selfcheck.go`).
- **INV-58** A line's product and train are what the product catalogue of the running build says of what its sources sent. Each
  reading keeps the item its source sent (`inv_software_reading.item_*`); when a start finds another catalogue revision than the
  one the lines were identified under (`inv_catalogue_pass`), the job `catalogue-reidentify` identifies every reading again in the
  background and moves it through the write path (`reidentify.go`): a line whose readings all moved is renamed in place (its id
  stays), every touched line is settled, and each changed device gets `inventory.software.changed` and the match events of a
  source's read. A reading that keeps no item follows its line. The pass is resumable and changes nothing when nothing moved.
- **INV-50** `SoftwareLine` is the one read model of a device's software: the device page reads it, and other modules get it
  through `cmd/vedette/wiring.go`, never from the readings.
- **INV-24** Agent readings (osquery, Wazuh) not reported again for 30 days are deleted (the job counts only while inventory and
  agent-intake are on).
- **INV-28** `inv_source` records when each source first reported (the "still learning" window). An agent's packaged row keeps the
  full package version and source package for distribution matching.
- **INV-41** A person corrects what a device runs (OS, a software's version); the correction drives matching until cleared or
  lapsed (INV-52). A person can mark a line not installed; it holds until a reading first seen after the mark.
- **INV-41a** What a person gives a line is a claim checked against the line's evidence (`Edit`, `checkClaim`), never trusted or
  dropped silently: a package release only on a distribution package (`packageLine`: the device's OS names a Linux distribution, or a
  source read the line from a package database or with a package release; or the text is itself a distribution's release,
  `pkgrel.Release`), else 400 `not_a_package` (firmware such as Junos OS has one release string); a version the device itself states
  as another release (its agent, its SNMP answer, the OS it states over LLDP; `pkgrel.Same` false) is refused once with that evidence
  (409 `contradicts_device`) and kept only with `confirm`; clearing the version of a line a source reads a release of is refused
  with that reading, who read it and when (409 `version_read`, `checkClear`: an entry without a version never hides it, INV-52); an edit that changes nothing writes nothing (no reading re-stamped, no
  event, no audit row, no rematch) and answers `changed: false`. Every version a person gives has its author, also when the device is
  added by hand or imported (`createManual`, `set_by`). `SoftwareLine.package_line` tells the dialog which value to ask. A history row
  never reads "X → X": a package release equal to the version is not a version change (`settleLine`). The job `entry-cleanup`
  (`CleanStoredClaims`) brings entries stored before these rules to them once: a stray package release on a line that is no package
  is dropped, an entry with no author gets `UnknownAuthor` ("unknown (entered before this release)"); one audit row
  `inventory.entry_cleaned` per entry, the device matched again. `TestEdit_ClaimsAreCheckedAgainstTheLine`,
  `TestCleanStoredClaims_DropsStrayPackageReleasesAndNamesLostAuthors`, `cmd/vedette/versionentry_matrix_test.go`.
- **INV-42** nmap's OS guess is stored and shown but never matched, and is used only when nothing better names the OS.
- **INV-44** What a device states about itself (LLDP on its own vendor's card, SNMP) ranks above a scan's guess.
- **INV-45** An OS or firmware a person declared is a software line the matcher reads as the device's OS, and a stored decision on
  the device.
- **INV-10** A product added by hand is matched against the exploited lists at once (`KEV` port); `inventory.match.changed` is
  emitted only for a newly matched CVE.
- **INV-15** `DevicesRunning` answers "yes" for an exact product key and "maybe" for a vendor-only match of a "multiple products"
  entry.
- **INV-30** `MatchInput` also gives the newest agent-reported and SNMP-reported OS, even when a person's value wins the field. Each
  software row names the person who entered its version (`MatchSoftware.SetBy`, "" for a source's reading).

**Devices and people**
- **INV-4** A device added by hand: a unique IPv4, bounded name, vendor, product and version; a duplicate software is 409.
- **INV-5** A device added by hand is not scanned or read by SNMP until a person turns that source on (see INV-37).
- **INV-37** Network scan and SNMP are on, off or default per device (`scan_source`, `snmp_source`; default on for a discovered
  device, off for one added by hand). A change is audited.
- **INV-56** The agent source can be switched off per device; while off, every agent's data for that device is refused.
- **INV-55** A device's three sources (network scan, SNMP, agent) and their states are decided on the server
  (`GET /inventory/devices/{id}/sources`). The agent row says `cert_changed` (red, button: the install command again) when the
  device's agent pins a certificate authority the box no longer has (a reinstall or a data purge made a new one): the box heard
  the device's address refuse its certificate at least twice in the last two hours (`Config.TLSRefusals`: osquery's "bad record
  MAC" or the alert unknown_ca, never a browser's refusal; kept in memory since the start, `refused` says since when and how
  often), or its osquery agent is quiet or never reported and was last seen before the CA in use began (`Config.TrustSince`).
  An agent that reports, a Wazuh agent and the box itself never say it; a person's off switch wins.
- **INV-9** A device a sensor finds is not approved and is never in the Devices list until a person adds it (or its agent's first
  report does, INV-25); `inventory.asset.discovered` is always emitted. One rule gives every device its state (`DeviceState`,
  `stateSQL` in `quiet.go`): ignored, added (approved), seen (INV-49) or review. The Devices list (`approved=true`), To review and
  its Seen briefly group (`approved=false`), the row and page text (`Device.state`), the counts and `ToReviewIDs` all read it,
  as endpoint tools keep discovered devices apart from the ones people manage. `DeviceCounts` (Home's devices tile) counts the
  added devices the Devices list holds, and To review. `TestContract_DeviceLifecycleMatrix`.
- **INV-49** A device with only private Wi-Fi addresses that shows nothing to look at (state seen) is in To review's collapsed Seen
  briefly group, outside the To review count and with no new-device notice; once it shows a reason, its review is sticky
  (`review_earned_at`).
- **INV-59** A device a person removed stays removed (`DeleteDevice`, `removed.go`): its row goes with everything known about it,
  and what identified it stays (`inv_removed`, `inv_removed_id`): its MACs that are no private (rotating) one; for a device with no MAC
  at all, its addresses. One admission check (`admit`) decides every way a sighting reaches a device: `resolve` calls it first for
  every observation and list (passive, scans, SNMP, Wazuh, software and services lists), and again where a found device would be made
  (`resolve`'s insert, `ownDevice`). A sighting that names a kept card (its hint's MAC, or a mac value the same report states, as
  Wazuh and an agent by address send it) reaches nothing, so it neither makes a device nor binds the card to one; one with no card
  makes no device at a kept address (another machine given the address is a new device), nor at the address a removed device was
  last shown at (a device check that was running when it was removed). A list (software, services) with neither a card nor an agent
  key never makes a device: it only attaches to the device its report's observations made (a list is what a device runs, not who it
  is), so a Wazuh list from the removed machine's new DHCP address makes nothing. No device takes a kept card as its MAC from an
  observation stored before the removal (`RecomputeAsset`). An osquery agent's report is a person's act: admitted, and it forgets the
  removals of its cards and of the address where it makes the device, so the Removed list does not name it (audit
  `inventory.removal_forget`). By design a re-enrolled agent (the person ran the install command again) brings a removed device back,
  and so does any enrolled node that reports the card: a node is a credential a person handed out. A stopped agent on a shared token
  cannot enrol again (`RemovedAgent`, agent-intake INV-28). A kept card is in `KnownMACs`, so a sweep spends no new-device budget on it. Merge and split
  only move identifiers between devices that exist, and an SNMP read with a device hint carries no MAC, so neither can bring one
  back. A person undoes a removal by forgetting it (`GET /inventory/removed`, `DELETE /inventory/removed/{id}`) or by adding a device by
  hand at a kept address, which forgets only removals kept by that address (a removed card stays out though the address is reused).
  It does not expire. With an agent bound to the device and the Agents module on, the person chooses (`?agent=`): `stop` (admin)
  hands the agent to agent-intake inside the delete (`lifecycle.Delete.StopAgent`) and keeps the machine's enrolment on a shared
  token; `keep` leaves the agent running and keeps nothing, since its next report adds the device back. With the module off there is
  no choice (`Detail.agent` false) and the device is kept out as one with no agent. The audit row `inventory.delete` names the choice.
  `TestContract_INV59_ARemovalKeepsTheDeviceOut`, `TestContract_INV59_EveryWayBackIsChecked`,
  `TestContract_INV59_AnAgentOfAModuleThatIsOffIsNoChoice`, `TestMigrationRemovedKeepsTheStoredDevices`, agent-intake
  `TestContract_RemovingADeviceWithAnAgent`.
- **INV-25** An osquery machine's first report approves the device it enrolled for (`ApproveEnrolled`, called by agent-intake).
- **INV-26** `approved_at` is set by a person's approval or an agent's first report. One naming rule gives every device its shown
  name (`DisplayName`): a maker that only a network scan or the passive sensor reports is the network card's (MAC prefix), so
  without a model it gives way to the OS or firmware the device states, then reads "<maker> device". The box is just seen on
  every read.
- **INV-36** The name a person gives (`user_name`) is separate from the host name the network reports.
- **INV-38** An ignored device is known, not watched: every scan and SNMP policy reads its sources as off, and its findings are
  listed apart. Ignoring changes no stored setting, so un-ignoring restores them.
- **INV-51** `DeviceRefs` says both whether a device is approved and whether it is ignored.
- **INV-46** A device's manual-source time is when a person last entered something, never a report.
- **INV-47** A value a person entered keeps winning; the device page says when a trusted source reads another (`detected_differs`),
  and the person can use it or keep theirs (`inv_detected_keep`).
- **INV-11** Deleting a device deletes its findings (the count is shown first); the removal stays (INV-59).
- **INV-27** Device kinds come from `content/devicetypes/types.json`; each kind acts as one of the base kinds for fragility and
  scanning.
- **INV-20** `TrustedKind` is true for a kind from a person or an agent, or from SNMP/nmap on an approved device.
- **INV-40** The device badge comes from findings (`RiskSource.DeviceStatuses`); with findings off no device has one.

**Scanning scope and safety**
- **INV-6** LAN ranges: at most 16, each with an explicit prefix and no host bits, private (RFC 1918) or shared (100.64.0.0/10)
  only.
- **INV-7** Turning on active scanning needs at least one range, one day and a confirmed scope (who and when are stored).
- **INV-8** A fragile or unclassified device is scanned lightly once when first seen, afterwards only passively.
- **INV-32** `active` is the one store of the safety settings every LAN engine shares (window, exclusions, rates).

**Lists and readers**
- **INV-12** `GET /inventory/catalog` returns at most 30 entries with a total; curated ids are fixed, exploited-list entries are
  `kev:<vendor>:<product>`. An exploited-list name a curated product covers is that product's entry (its id still finds it). A product
  typed by hand is the exact exploited-list pair, else the curated or catalogue product of that name, else its own key: never every
  product of its vendor.
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
  created unapproved; a list by address only with no agent key attaches to an existing device and creates none (INV-59), as for
  `ReplaceSoftware`.
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
| `inventory.asset.discovered` | notify (new-device incident), sensor-active (first light scan; `no_address` is published for it to skip a device with no IPv4 address), findings and feeds (`wiring.go`) |
| `inventory.asset.updated` | notify, scan (stop scanning a device no longer allowed), sensor-active, findings, feeds |
| `inventory.asset.deleted` | sensor-active |
| `inventory.asset.approved`, `inventory.asset.ignored` | notify |
| `inventory.software.changed`, `inventory.match.changed` | findings (match pass for the device); a write that sends a device's `match.changed` sends no `software.changed` for it, so the device is matched once |
| `inventory.settings.changed` | sensor-active, the module container wiring |
| `inventory.asset.unignored` | none today |

Inventory listens to `findings.finding.created`, `findings.finding.urgency_raised` and `honeypot.hit.created` (a device earns review),
and to the feeds events (re-match: `feeds.vuln.new_kev`, `feeds.vuln.updated`, `feeds.ranges.updated`, `feeds.sync.baseline`).

## Dependencies

- **Depends on**: `core`, `feeds` (the `KEV` port for matching and the catalogue; with feeds off the catalogue uses
  `content/catalog/kev-products.json` and matches nothing). Optional: agent-intake (`WazuhAgentAddresses`), honeypot (`DecoyIPs`), findings (`DeviceStatuses`).
- **Used by** (adapters in `cmd/vedette`): findings (`MatchInput`, `SoftwareLines`, `DeviceRefs`, `AssetIDs`, `ToReviewIDs`), sensor-active
  (`ScanPolicy`, `AddressMap`, `KnownMACs`), scan (`VulnScanPolicy`, `Checks`), feeds (`AddManualDevice`,
  `DevicesRunning`), agent-intake (`ApproveEnrolled`, `AgentDevice`, `RemovedAgent`), the selfcheck (`ReadIgnoredIDs`, `ReadDeviceIDs` on its read-only handle), response, ai and logs (`DevicesOfKind`), reports, ai,
  honeypot and the exposure gateway (`AllDevices`), notify and audit names (`DeviceRefs`), core setup (`SetupScope`), the reach
  audit (`Catalog.Curated`).

## When off

No routes; the Devices list is empty; sensors and agent-intake have nowhere to write; findings gets no new matches; scan has no
internal targets; "Do you have it?" is `null`. Data is kept.
