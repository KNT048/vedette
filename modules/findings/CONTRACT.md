# Findings contract

> Tier: standard · Stories: S-MIT-1, S-INV-2, S-SCAN-3, S-ALERT-1, S-UI-1, S-TIER-1, S-TIER-4 · Tables: `fnd_*`
> ([`docs/DATA_MODEL.md`](../../docs/DATA_MODEL.md) 4.3, 5.2)

A finding is one CVE on one software line of one device, with how Vedette knows, what was done about it and how urgent it is.
Findings matches inventory's software lines against feeds' catalogue, keeps the state machine, and is the one place the rest of
the product reads findings from.

## Endpoints

| Route | Minimum role |
|---|---|
| `GET /findings/devices`, `/findings/fixes`, `/findings/input`, `/findings/answered`, `/findings/handled`, `/findings/overview`, `/findings/{id}/view` | viewer |
| `GET /findings?asset=` (one device), `GET /findings/{id}` (the finding page's evidence and "What to do", filled by mitigation) | viewer |
| `POST /findings/handle`, `POST /findings/{id}/reopen`, `POST /findings/questions/{id}/answer`, `POST /findings/questions/{id}/unanswer` | operator |
| `POST /findings/{id}/verify`, `POST /findings/{id}/unverify` | admin |

`POST /findings/{id}/applied` and `POST /findings/{id}/ai` are served by mitigation under the same prefix. Shapes:
`web/src/features/findings/contract.ts`.

## The model

IDs are stable (code and tests cite them); a retired ID is not reused.

- **M-1 Identity.** One `fnd_finding` row per (device, CVE, software line) that was affected at some time, unique on
  `(asset_id, cve, ifnull(software_id, ''))`. `software_id` is NULL only for a finding on no line (a safe check's hit, an OS a
  device states without a line); it takes the line it is later found on. A CVE on two lines of one device is two findings. A pair
  checked and not affected has no row; a pair Vedette cannot decide is a `fnd_question`, never a finding.
- **M-2 Three facts, one writer each.** Detection (`detected` … `evidence`) is written by the match pass and safe checks; handling
  (`state` … `to_version`) only through `Transition`; urgency (`urgency`, `urgency_at`) only by the urgency pass. `evidence` and
  event `detail` are for display; no logic reads them.
- **M-3 One state machine.** `Transition(finding, trigger)` is total over every state and trigger and returns the row and the
  events to append; `TestTransition_EveryStateAndTrigger` covers the whole table. In short: a detection creates or detects again; a finding
  Vedette closed opens when detected again; a person's `patched` opens on a reading newer than their mark (`still_detected`);
  mitigated, accepted, false positive and not relevant hold while detected; an accepted risk reopens after its last day. "Gone"
  closes an open finding as `patched` when something changed on the device (`version_moved`, `software_removed`, `distro_fixed`,
  `scan_clear`) and as `not_relevant` when only data changed (`data_corrected`) or a person said the software is not installed
  (`not_installed`). When the match's proof explains Vedette's close (the distribution's fixed package release, its word on the package),
  the proof's sentence is the closing note, so the handled line says the real reason; the proof is that of the finding's own CVE and
  software line, so of two lines of one product each closes with its own sentence. A safe check's or a person's confirmation is undone only by a newer reading of the device, never by range data.
- **M-4 Invariants.** Held by database CHECKs, `Finding.Validate` and `vedette selfcheck`: open exactly when there is no
  resolution, `via`, `resolved_by` or `resolved_at`; accepted exactly with a last day; `version_moved` exactly with two different
  versions; every open vocabulary value is one the Go type lists; every open finding's `fix_key` names its stored fix (`findings.fix_key_names_stored_fix`).
  Open total = sum by device = sum by `fix_key`: every open row is in exactly one group of each, so the API test
  `TestModelAPI_OpenEqualsSumByDeviceEqualsSumByFix` proves it, not a selfcheck query.
- **M-5 Patch credit by structure.** How a finding went away depends on what changed on the device, never on which source read the
  version. A person's correction of what a source reads is not an update (`data_corrected`, no credit). A person who changes the
  version they entered themselves (a line that is only their entry) updated the device and said so: `version_moved` with credit,
  handled by that person (`resolved_by`), never by Vedette; setting it back opens the finding again with the person named in the
  reopen event (`detail.by`, View `reopened.by`) and in its audit row (that person's row, detail "the version was set back by
  <person>"). The person is inventory's `MatchSoftware.SetBy` of the line, read with the rest of the match input
  (`Software.SetBy`).
- **M-6 Device lifecycle.** Findings take part in inventory's merge, split and delete inside inventory's transaction (`lifecycle.go`,
  `followline.go`): a merge moves findings to the kept device and line and folds two findings of one (CVE, line) into one, keeping
  events; a delete removes findings, events and questions. Lines inventory deletes for good are settled first (`LinesDeleted`). A
  split (`DeviceSplit`) moves the findings and questions of every line the device that stays no longer has (`lifecycle.SplitLine.Gone`)
  to the line of the device split off that holds its readings now: the line itself when it went whole, or a line of a new id when its
  readings went back as one. The same finding id, handling, notes, events and the rows other modules keep by its id go with it, never
  a handled copy left behind and a new finding opened; two findings of one (CVE, line) fold as in a merge (audit
  `findings.moved_with_line`). A line both devices have after the split keeps its findings on the device that stays; the device split
  off gets its own at its match. So no finding or question names a line of another device once the split commits (selfcheck
  `findings.line_on_its_device`). A row that still does (stored by a match write that read its device before the split committed, or
  left by an older split) moves at the next match write of either device (`followLines`, when inventory's word on both devices
  agrees). Before a finding moves, the modules that keep a device id next to its id are told (lifecycle `FindingMoved`, in the same
  write). Ignoring a device changes no finding;
  lists, Home, the AI context and reports leave its findings out.
- **M-7 One match pass.** Reconcile reads every device and asks feeds once for the match set (`Feeds.MatchSet`). A CVE that matches
  with version evidence is a finding whatever its urgency. Every finding whose CVE is in the set and that the pass no longer detects
  goes away the way the data says. A pass that changes nothing writes nothing; a device whose inputs did not move is not matched
  again (`matchstamp.go`). Findings tells feeds which CVEs to keep (`PinnedCVEs`).
- **M-8 One fix resolver.** `FixOf(device, line, CVE)` is the only reading of what fixes a finding; the match write stores it with
  `fix_key` and `range_origin`.
- **M-9 One urgency.** `Urgency(cve, facts, target, attacks, now)` is the only rule of a finding's layer: 1 an intrusion alert in
  the last 14 days named the CVE; 2 a qualifying exploited signal; 3 a qualifying public-exploit signal; 4 CVSS ≥ 9, network, no
  privileges, automatable, on an edge product class; 5 the rest. Only the urgency pass stores it. Each rise of an open finding into
  layers 1–4 is one `findings.finding.urgency_raised`, told once by `Tell` (news, a first-run summary line, or backlog). A device a
  person ignored is not rated. A finding above layer 2 is never called exploited.
- **M-10 Vendor rows and distribution fixes.** A vendor's own version notation is read through the product's version scheme
  (`core/versionscheme`); when it places the line's version, the vendor's verdict decides before NVD's ranges. A distribution's
  fix for a package the device runs is compared before NVD's product ranges.
- **M-11 One read model.** `View` is a finding as every place shows it (row, device, line, CVSS; `Service.View` adds history and
  urgency reasons). `StatusOf` is the one status; `DeviceStatusOf` the one device badge. A list row (By device, the device's Findings
  tab, Home's Fix first) carries the same urgency reasons and verification as the finding's own view (`listViews`), so every screen
  draws one status the same way; `View.ReasonsLine` and `View.VerificationLine` are those lines as text for notices, mails and reports.
  By device and By fix group the same open rows in SQL, so their totals always agree. The fixes of one product on one line combine
  into one block (`combine`), read the same way by By device, By fix, Home, the report (`ListedFixes`) and the handling of a block:
  an update block names the lowest release the CVEs' ranges name that clears every CVE it lists on that line, and splits when no
  such release clears them all (`blocktarget.go`, `TestBlockTarget_Count_TargetsThatLeaveAListedCVEOpen`). The Needs your input queue is computed from
  rows, never stored, and searched like the other lists (`q`: the device's name or address, the software, the CVE id); a device not
  added yet is also found by the CVE ids and software names of its open findings, which its item does not show (read only when `q`
  is set); a question answered "not affected" is listed (`/findings/answered`) and can be asked again (`unanswer`).

## Invariants

**Matching**
- **INV-1** One finding per (device, CVE, line) (M-1).
- **INV-4** Exploited-list entries are keyed `vendor|product`; a "multiple products" entry yields a finding only through an NVD row
  that names the software itself.
- **INV-4a** Version ranges come from feeds' match set (NVD's when NVD has any, else the CVE record's). A line with no usable
  version that cannot be decided is a question, not a finding.
- **INV-4b** The finding page's fixed version comes from the same rows as the match; a version is a fix only when it is outside
  every applicable range.
- **INV-4c** Network device operating systems become software lines through one table, `content/catalog/network-os.json`. The
  device page shows the OS the matcher decides on (`DeclaredOSRow`).
- **INV-4d** Questions are computed in the same match pass and written in the same transaction as the findings (`fnd_question`).
- **INV-4e** `Reachability` sorts every exploited-list entry into the first class that explains whether it can reach a device; the
  result of each run is kept in `fnd_reach_run`.
- **INV-4f** A finding needs version evidence on every path; a product-name-only match is a question.
- **INV-4g** A question is asked only when an answer can change the verdict. A CVE on no exploited list is compared only with a
  version the device or a person gives (its agent, its SNMP answer, the network OS release it states over SNMP or LLDP, also when
  another source recorded that very release, the firmware it states on its management interface, a person's entry); against a
  version read from the network (a banner, the passive sensor) it is neither compared nor asked. A line NVD names only at exact
  releases older than its own is not asked either: the release numbers each side starts with decide, whatever update or build
  follows them (ESXi 8.0.3 is later than `esxi:6.5:update1`, not than `esxi:8.0:update_3`). A version inside a range with an end
  and an open-ended one is read with the range that has an end. A release the device states is stored as `device_version`.
- **INV-5** The severity a match reports for a new finding: version evidence is `high` (`critical` with ransomware use or EPSS ≥ 0.5);
  product only is `medium`. The shown severity of a finding is the CVE's CVSS band.
- **INV-6** Writing a match is idempotent per (device, CVE, line) and goes only through `Transition`.
- **INV-6c** A line a person marked not installed is not matched; its findings close as `not_relevant` via `not_installed` under
  that person's name.
- **INV-11** "I have this" on a versionless product matches, on exactly the declared device, only entries added since its start date.
- **INV-14** A packaged agent line on Ubuntu or Debian is judged by the distribution's fix data before NVD's ranges.
- **INV-15** A Windows release line is judged by its build revision against Microsoft's fixed builds (`windows.go`).
- **INV-16** CVEs in `content/catalog/platform-limits.json` affect only the platforms listed; platform evidence comes only from the
  device's own reading (agent OS, its SNMP answer). No platform evidence is a `platform` question (INV-16c); the fixed versions per
  release are built from the distribution's data, never copied by hand (INV-16d). A person's correction follows the corrected
  source's rules and earns no credit (INV-16a).
- **INV-17** A version match on an agent line says, in its evidence, what the agent reported.
- **INV-19** An exploited-list CVE published and added more than 365 days ago no longer matches by product name only.
- **INV-21** Edge Legacy CVEs do not affect Chromium-based Edge.
- **INV-28** One software on one device is one line everywhere: inventory decides the effective reading (`MatchInput`), findings
  matches the readings it gives.

**Handling**
- **INV-2** The older read model (`LegacyStatus`, `legacy.go`) is a projection of `state`, `resolution` and `verified`; nothing of
  it is stored.
- **INV-3** The finding page changes a finding through `POST /findings/handle` (a resolution, a note of at most 500 characters,
  required for false positive, not relevant and accepted), `reopen`, and a person's `verify` / `unverify` (admin).
- **INV-13** An accepted risk always has a last day, from tomorrow to 365 days ahead (UTC days).
- **INV-27** Every list row carries `resolution_reason` (Vedette's close with or without patch credit), `software_id` and the proved
  version.
- **INV-29** A recommended update has no "done" mark: a person marks its findings patched, and a later reading that still shows the
  affected version reopens them.

**Reading**
- **INV-8** A finding's exploited-list facts come from feeds, never from mitigation's packs.
- **INV-12** A device is named as on the Devices page, never by an internal id.
- **INV-22** Every finding row carries the CVE's base CVSS as feeds picks it (`Feeds.CVSS`).
- **INV-23** `GET /findings/overview` is Home in one read; its totals equal By device's. `devices.affected` counts every device with an
  open finding (the Vedette box included, with its badge like any device: one rule on Devices, By device and Home); the trend starts at `trend_start`, the day this box began keeping
  findings when that is inside the 30 days. `first_run_summary` is notify's first-run summary of the newest load made in the last 7
  days (`HomeSources.FirstRun`, a notice, never an incident): shown on Home even when no channel took it; `null` when there is none or
  notify is off.
- **INV-30** Findings of a device not yet added show, marked; an ignored device's findings are listed only under Ignored, and readers
  of one finding outside its page answer "not found" for them.

**Consistency**
- **INV-7** Deleting a device deletes its findings and questions inside inventory's transaction (M-6).
- **INV-9** The event bus is best-effort, so the `reconcile` job (at start, then hourly) matches every device again and removes the
  findings of devices that are gone. An event handler writes under its own one-minute timeout.

## Preconditions and postconditions

- **PRE-1 / POST-1** `UpsertFromMatch` (from `OnMatchChanged`): the device exists; each new (CVE, line) becomes an open finding
  through `Transition` (event `created`, audit row); an ignored device writes nothing.
- **PRE-2 / POST-2** `ConfirmFromScan` (scan module): the template evidence is checked and cut like any untrusted answer; the
  finding of the line the matcher reads the CVE on is detected with `basis=scan`, `verified=scan`. A person's decision holds.
- **PRE-3 / POST-3** `GET /findings/{id}`: 404 for an unknown id; "What to do" comes from an optional `findings.Guidance` provider
  (mitigation registers it; it is skipped while mitigation is off).
- **PRE-4 / POST-4** handle and reopen (operator), verify and unverify (admin): handle answers how many it handled and skipped and
  is all or nothing.

## Forbidden

- **FORBID-1** Writing to a customer device or firewall, or blocking traffic; actions belong to response.
- **FORBID-2** Closing a finding without a person's action or a match or safe check that no longer detects it; crediting a patch
  when nothing on the device changed; deleting a finding outside the device and line lifecycle.
- **FORBID-3** Creating a "vulnerability" kind of incident.
- **FORBID-4** Claiming affected or not affected when the version cannot be compared.
- **FORBID-5** Another module writing `fnd_*`; others read through findings' Go API.

## Events

| Event | Subscribers |
|---|---|
| `findings.finding.created` | inventory (device earns review), notify, response, logs (SIEM export) |
| `findings.finding.urgency_raised` | inventory, notify, response, logs (SIEM export) |
| `findings.urgency.first_run` | notify (one summary per first load) |
| `findings.finding.status_changed` (older read model) | notify, response, logs (SIEM export) |

Findings listens to `inventory.match.changed`, `inventory.software.changed` and `inventory.asset.discovered` / `updated` with
`match=true` (match the device), and to stored intrusion alerts (rate urgency).

## Dependencies

- **Depends on**: `core` (lifecycle, audit, version schemes, Windows releases, org time zone), `feeds` (`MatchSet`, CVSS,
  urgency facts, `HaveSince`), `inventory` (`MatchInput`, `AssetIDs`, device refs, ignored devices).
- **Used by** (adapters in `cmd/vedette` unless noted): mitigation (imports findings: guidance, AI answers), notify
  (`notifyfindings.go`), scan (`ConfirmFromScan`), response, reports (`Views`, events), ai and mcp-server (`Views`, `ByDevice`),
  inventory (`DeviceStatuses`, `EarnReview`), exposure (`MatchAsset`, `FixOf` in `exposurematch.go`), feeds (`PinnedCVEs`), ids
  (urgency reasons), the finding page (`findingcase.go`).

## When off

No `/findings*` routes and no `reconcile` or `urgency` jobs; tables stay. Notify has no vulnerability alerts, scan results carry
no finding, the Devices page loses findings and badges, reports lose their vulnerability section, and mitigation loses its input.
