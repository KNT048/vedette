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
| `POST /findings/{id}/identity/reject` (Not this product, P-9) | operator |
| `POST /findings/handle`, `POST /findings/{id}/reopen`, `POST /findings/questions/{id}/answer`, `POST /findings/questions/{id}/unanswer`, `POST /findings/questions/ignore`, `POST /findings/questions/accept-risk` | operator |
| `POST /findings/{id}/verify`, `POST /findings/{id}/unverify`, `GET /findings/coverage` | admin |

Needs your input (`GET /findings/input`) is one card per added device (`device_needs`), collapsed by default: its entries are what runs
there (`device_unchecked`), urgent findings not confirmed yet (`unconfirmed`) and its questions grouped by software line (`software_group`,
one entry per line with the CVEs counted once, the line's `fnd_question` rows inside, the one whose action fixes the most first). A device
nobody added keeps its own `device_not_added` card and is that one item (its urgent findings and questions are not listed again
under a second card: Add device first); `total` counts cards. A question stays one row per (line, CVE, kind), since Affected
or Not affected is a per-CVE judgement; the version or edition a person enters lives on the software line, so one entry fixes every CVE of
it at the next match. `POST /findings/questions/ignore` (a device, or one line of it) answers Not affected to every open question there
in one transaction with one audit row (`findings.questions_ignored`); each answer is listed under Answered and can be asked again.
`POST /findings/questions/accept-risk` (admin, as answering affected; a device, one line of it, or one question) is the other bypass, for a person who knows the
software may be affected and lives with it: each open question there is answered affected, the finding of each CVE it asks about is
recorded on the person's word and handled as accepted until a required day (one required note), and so is every open finding, confirmed or suspected, of
a device or line scope, all in one transaction with one summary audit row (`findings.risk_accepted_in_bulk`) next to each finding's own
history row. The findings open again after the day; a CVE that matches later is a new question.

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
  mitigated, accepted, false positive and not relevant hold while detected; an accepted risk reopens after its last day. Open means
  detected: a person's reopen of a finding the latest match no longer detects is recorded, and Vedette closes it again at once the way
  the data last said it went away (its own close, else the newest `no_longer_detected` event; `version_moved` names the release the
  device runs now), with that reason as the note; "gone" also closes an open finding that is not detected, also when the pass no
  longer reads its CVE. "Gone"
  closes an open finding as `patched` when something changed on the device (`version_moved`, `software_removed`, `distro_fixed`,
  `scan_clear`) and as `not_relevant` when only data changed (`data_corrected`), a person said the software is not installed
  (`not_installed`) or the CVE left the reporting window (`outside_window`, M-15). The Handled list leaves out what Vedette closed by correcting its own match (`data_corrected` by Vedette: never
  a flaw someone handled) unless asked (`corrections=true`), and counts it under the same filters (`HandledList.corrections`;
  `TestHandled_LeavesOutVedettesMatchCorrections`). When the match's proof explains Vedette's close (the distribution's fixed package release, its word on the package),
  the proof's sentence is the closing note, so the handled line says the real reason; the proof is that of the finding's own CVE and
  software line, so of two lines of one product each closes with its own sentence. A safe check's or a person's confirmation is undone only by a newer reading of the device, never by range data.
  A version match on a version a person typed or corrected is that person's word, and so is a match on the distribution package
  release a person gave (basis `package`) when the distribution's data decides on it: it is confirmed by them when it is made (verified
  `person`, the history names them and the version; `entryConfirms`, which needs the author inventory keeps for every entry), never queued for their confirmation, and its confirmation is no
  Undo's (409); resting on the ranges, it is judged again at every match like the device's own report (`proofHolds`: a range
  correction closes it as `data_corrected`). A person's own Confirm stays as on any other basis: it holds at every match and Undo takes
  it back, also on a finding that rests on an entered version; the two are told apart by the newest `confirmed` event (Vedette's for
  the entry, `Finding.byEntry`), no column of their own. `TestMatch_EnteredVersionIsThePersonsWord`,
  `TestMatch_OwnConfirmOnEnteredVersionHolds`.
- **M-4 Invariants.** Held by database CHECKs, `Finding.Validate` and `vedette selfcheck`: open exactly when there is no
  resolution, `via`, `resolved_by` or `resolved_at`; accepted exactly with a last day; `version_moved` exactly with two different
  versions; every open vocabulary value is one the Go type lists; every open finding's `fix_key` names its stored fix (`findings.fix_key_names_stored_fix`);
  an open finding is detected (`findings.open_is_detected`).
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
  write; a split also passes the device split off as Devices names it and its address, `IntoName`/`IntoIP` from `lifecycle.Split`). Ignoring a device changes no finding;
  lists, Home, the AI context and reports leave its findings out.
- **M-7 One match pass.** Reconcile reads every device and asks feeds once for the match set (`Feeds.MatchSet`). A CVE that matches
  with version evidence is a finding whatever its urgency. Every finding whose CVE is in the set and that the pass no longer detects
  goes away the way the data says. A pass that changes nothing writes nothing; a device whose inputs did not move is not matched
  again (`matchstamp.go`). Findings tells feeds which CVEs to keep (`PinnedCVEs`).
- **M-8 One fix resolver.** `FixOf(device, line, CVE)` is the only reading of what fixes a finding; the match write stores it with
  `fix_key` and `range_origin`. The fix carries its channel (`fix_channel`): `ubuntu_pro` when only Ubuntu Pro's archive has the
  distribution's fixed package (a public fix of the same package wins), `esu` when the Windows build comes only with Extended Security
  Updates, else `public`. A non-public channel ends the `fix_key` (`|ubuntu_pro`), so it is its own By fix group and never combines with
  a public fix, and every place that says the fix (`FixWords`, the web fix line, the report and its mail) says the subscription and
  what a person without it can do.
- **M-9 One urgency.** `Urgency(cve, facts, target, attacks, now)` is the only rule of a finding's layer: 1 an intrusion alert in
  the last 14 days named the CVE of a flaw exploitable over the network (an AV:L or AV:P flaw is never under attack from network
  traffic); 2 a qualifying exploited signal; 3 a qualifying public-exploit signal; 4 CVSS ≥ 9, network, no
  privileges, automatable, on an edge product class; 5 the rest. Only the urgency pass stores it. Each rise of an open finding into
  layers 1–4 is one `findings.finding.urgency_raised`, told once by `Tell` (news, a first-run summary line, or backlog). A device a
  person ignored is not rated. A finding above layer 2 is never called exploited.
- **M-10 Vendor rows and distribution fixes.** A vendor's own version notation is read through the product's version scheme
  (`core/versionscheme`); when it places the line's version, the vendor's verdict decides before NVD's ranges. The vendor's
  statements that only support "not affected" (`SchemedRange.Unaffected`: a range it states unaffected for every device, feeds INV-35;
  `ModelOnly`: an affected range limited to some models) decide "not affected" when the version is inside an unaffected range and
  inside no affected one, or outside every affected range in a train one of them ends in; they never decide "affected", and a version
  inside a model-limited range is left to NVD. On a disagreement the affected side wins: when an NVD row (a range or an exact release)
  covers the version, the statements decide nothing and NVD's rows decide (`nvdCovers`). A model-limited row of the vendor's own
  record (`SchemedRange.Complete`: its `defaultStatus` unaffected, feeds keeps it only from the product's own CNA) whose hardware
  (`Platforms`) the device's stated model cannot be is not about the device (`otherHardware`, read by the names' shape only: "<letters>
  Series", "<letters><number>", a numbered series; a model or a platform of another shape is never ruled out, nor is a device by a model
  word without "Series" of other letters, which may name a part it carries ("MPC10E"), and only an operating
  system's or firmware's rows are read so, `deviceFirmware`); when every row of the product is such a row, the device is not affected
  ("lists the OS as affected only on QRX Series, and the switch is a ZX4200-48T"); a version of the vendor's rows for every device, an NVD
  row covering it or an unread row still decide as before. With no row for every device, the starts of the vendor's own model-limited
  rows say where the flaw came in (`olderThanEveryStart`, below). `TestOtherHardware`, `TestMatchAsset_ModelRowsOfOtherHardware`. (`notAffectedByStatements`,
  `TestMatchAsset_VendorStatementsSayOnlyNotAffected`, `TestJuniperRecord_UnaffectedStatementDecidesTheSwitch`,
  `TestJuniperRecord_NVDAffectedRowBeatsUnaffectedStatement`). Where the vendor's affected ranges start also decides "not affected" (Junos OS only: the one scheme whose
  first release of a branch is read, `branchStart`; the proof says "NVD lists" when NVD's rows are the ones read):
  when every one of them has a start and the version is older than the first, and that first start is a release inside its branch
  (Juniper's "23.2 versions from 23.2R2-S1 before 23.2R2-S5"), the flaw came in with it and the older release is not affected
  (`olderThanEveryStart`; the proof and closing note say "older than the first affected release the vendor lists (23.2R2-S1)"). A range
  with no start ("all versions before 23.2R2-S7") reaches every older release; ranges that all start at a branch's start or first
  release ("24.2 before 24.2R2-S3") say nothing about an older branch, which stays a question (`older_line`); an NVD row covering the
  version still wins (`nvdCovers`). Nor when one of the product's affected rows did not read in the scheme (Juniper's "22.2" lessThan
  "22.2*", kept as `SchemedRange.Unread`), or a row is one exact release (Oracle's "8u503", the newest affected update of a train):
  the starts are then not the vendor's whole word on where the flaw came in. `TestVendorRangeStartMatrix`,
  `TestVendorRangeStartNeedsEveryRowRead` (cmd/vedette). A distribution's fix for a package the device runs is compared before
  NVD's product ranges.
- **M-11 One read model.** `View` is a finding as every place shows it (row, device, line, CVSS; `Service.View` adds history and
  urgency reasons). `StatusOf` is the one status; `DeviceStatusOf` the one device badge. A list row (By device, the device's Findings
  tab, Home's Fix first) carries the same urgency reasons and verification as the finding's own view (`listViews`), so every screen
  draws one status the same way; `View.ReasonsLine` and `View.VerificationLine` are those lines as text for notices, mails and reports.
  By device and By fix group the same open rows in SQL, so their totals always agree. The fixes of one product on one line combine
  into one block (`combine`), read the same way by By device, By fix, Home, the report (`ListedFixes`) and the handling of a block:
  an update block names the lowest release the CVEs' ranges name that clears every CVE it lists on that line, and splits when no
  such release clears them all (`blocktarget.go`, `TestBlockTarget_Count_TargetsThatLeaveAListedCVEOpen`). A release in a vendor's
  notation (ESXi's "8.0 U3d (build 24585383)", DSM's "7.2.1-69057 Update 6") is ordered by the product's version scheme and judged
  with the vendor's rows, so one line names one release (`TestCumulativeTarget_Count_LinesWithSeveralUpdatesOfOneProduct`). A block is
  keyed by the catalogue's product, so one product read under two names (Oracle Java SE, Eclipse Temurin) is one By fix row
  (`TestBlockKey_Count_ByFixCardsWithARepeatedTitle`). A fix version no order reads stays its own block without keeping the line's
  other fixes from combining (`orderable`), and every release name a scheme writes reads back (`TestRelease_Count_WrittenNamesThatDoNotReadBack`),
  so a line is in one By fix step whenever one release clears all its CVEs (`TestOneStep_Count_LinesSplitWhereOneReleaseCoversAll`); when
  it is in several, each step's device row names the others (`FixDevice.others`). `ListedFix` is one finding's listed fix, for its own page. The Needs your input queue is computed from
  rows, never stored, and searched like the other lists (`q`: the device's name or address, the software, the CVE id); a device not
  added yet is also found by the CVE ids and software names of its open findings, which its item does not show (read only when `q`
  is set); a question answered "not affected" is listed (`/findings/answered`) and can be asked again (`unanswer`).
- **M-12 Audit lines in words.** The audit page and its CSV export show a detail as written, so every audit line of this module
  says each stored code in words (resolution, way, reason to reopen, detection basis, question kind; an unknown code of an open
  vocabulary with its underscores as spaces), never the code: `auditAction`, `questionAuditDetail`, `TestAuditDetailsSayEveryCodeInWords`.
  Lines written before keep their text (the log is append-only).
- **M-13 Release-line verdicts.** A vendor's statement per release line (feeds INV-40) is read in one place, `lineJudge`, inside `judge`
  after the distribution, platform and Edge steps and before the vendor's scheme rows and NVD's ranges. The line of the version is the
  product's trains after its `version_map` (catalogue data). Only the vendor's explicit rows and its fresh convention change a decision:
  a row whose affected releases hold the version is a finding (range origin `vendor_line`, the vendor's fix of the line as `FixOf`'s
  release, the evidence naming the vendor and its advisory); a row whose fix the version is at or past, or one stating the line
  unaffected, is "not affected" unless an NVD row covering the version names the line itself (starts or ends on it, or lists one
  of its releases); a line the source does not list is "not affected" by the convention `unaffected_if_supported` only when the vendor supported
  the line on the day the CVE was published (line support), the source is fresh and its statement not older than the CVE, and no NVD row
  covers the version; a convention row of the source (`explicit` false: Oracle's "a line the document assessed and does not list") holds
  under the same freshness, date and NVD conditions. A version past the vendor's affected releases of the line is fixed only for the builds
  the source numbers (`LineCover.Builds`: Oracle's own Java, not Temurin's 8u492); for another build it decides nothing. A statement
  limited to some builds (`LineCover.OnlyBuilds`: a CVE in Oracle's installer or JavaFX in Java 8) says nothing about another build. A version the
  product's version scheme does not read after its `version_map` decides nothing. Where the scheme reads the version and a row's bound, they
  are compared in it, and a patch build the bound states counts (`versionscheme.ComparePatch`: Oracle's 8u511b33 is after 8u511 with no
  or an earlier build, before 8u521; a bound with no build is the whole release). A line the vendor no longer assessed, a status that is
  not public yet, and a row limited to some platforms decide nothing: the CVE record's own statement decides as before. A distribution's
  package is never read here. `TestLineJudge_EveryVerdict`, `TestLineJudge_EvidenceFixAndOrigin`, `TestLineJudge_OracleJava`,
  `TestLineJudge_OracleTexts`, `TestLineJudge_OracleOwnBuildPart`.
- **M-14 Decision coverage.** Each match pass counts, for every (software line, CVE) the catalogue relates on the devices it matched
  (a row of the line reached by the entry's key or rows, or a finding or question of the pair), what decided it: the source (the
  `range_origin` vocabulary, `platform_list` for the hand list of platform limits, `person` for an answered question, `advisory` for a
  check the box settled, `ai_read` for a finding the AI's reading opened; an AI "not affected" decides only once a person confirms it,
  `person`) as affected or not affected; else why it is undecided: its
  cause (`PossibleCause`, as the lists show it) with the matcher's own reason under it (`CoverageCause.details`: the question's
  `Undecided.reason`, else its kind, so the record shapes behind a cause stay visible; a row stored before details were kept reads with
  its undecided reason as the cause and no details), for a distribution's package its distribution's data has no word on and no
  question asks about, why (`DistroSilences`:
  `distro_other_packages`, `distro_other_releases`, `distro_other_build`, `distro_not_listed`, `distro_no_data`,
  `version_needed` for an agent's package row without its release; `TestCoverage_EveryDistributionPackagePairIsDecidedOrNamed`), or an
  unnamed class (`other_distro_silent`, `other_record_unread`, `other_dropped`: the matcher reached the pair and neither decided nor
  asked, so nobody is told why; the target is none). Beside it, the software lines by identity method (`stated`, `catalogue`, `record`, `none`). A device the
  pass finds unchanged keeps the counts of its last full match; the sum of each pass is one row of `fnd_coverage_run` (the newest 30
  kept, in the data export) and `GET /findings/coverage` (admin, counts only, Settings → Diagnostics) serves the last one. Counting reads the pass's readings and the rows its write left and
  changes no finding or question. The test-only build tag `holdout` runs the matcher without the catalogue's CPE aliases, so the same pass
  shows what rests on catalogue rows. `TestCoverage_SyntheticProductsAreIdentifiedAndDecidedWithoutCatalogue` (made-up products in every
  standard record shape; shapes not decided yet are skipped with the rule that will decide them). The CVEs of the pass's match set it
  set aside as outside the reporting window (M-15) are counted apart (`Coverage.outside_window`), never as pairs or as undecided.
- **M-15 The reporting window.** Feeds marks a catalogue CVE of the match set that is outside its reporting window (feeds INV-34:
  published before the last 12 months, no exploited-list entry, no exploited signal, no public exploit dated in the last 12 months, no
  intrusion alert of this network naming it in the last 12 months, and
  CVEs of every age not reported): `Vuln.OutsideWindow`. The matcher never reads such an entry (`inWindow`, in the pass, the match of
  one device and `matchOne`): it is no finding and no question (not "undecided": out of scope). Every detected finding of it goes away
  through Transition as `not_relevant` via `outside_window` by Vedette (`closeOutside`, before the devices are matched; its event and
  audit row like any close), unless a safe check proved it or a person confirmed it (`proofHolds`: a flaw proved on the device is
  reported whatever its age). Nothing is deleted: the finding opens again when its CVE is back inside the window and the match detects
  it. Its pin keeps the CVE's data in the catalogue, never inside the window. `TestWindow_AFindingOutsideTheWindowClosesAndOpensAgain`,
  `TestWindow_AConfirmedFindingStaysOpen`, `TestWindow_NoQuestionAndCountedApart`.

## Possible findings and the check of their advisories

- **P-1 Possible.** A CVE Vedette cannot decide for a line of a device is a possible finding: an open `fnd_question` about that CVE (each
  CVE of a `version_needed` question; `older_line` is one question per CVE), never a `fnd_finding` row, so never in the open totals, an
  alert, a report or Home's trend. It is counted apart (`GET /findings/possible` counts, `Overview.possible`) and a finding of the same
  (device, CVE, line) always wins (`possibleItems`). The device badge `possible` counts a device's possible CVEs when nothing open is more
  urgent; a device with nothing to check gets no badge.
- **P-2 Why undecided.** Every possible CVE carries a machine-readable `detail.undecided` (`UndecidedReasons`: the reason, the range rows
  read, the advisory text that blocked a decision with its address), also in the export (`fnd_question.detail`,
  `fnd_possible_check.detail`) and grouped by `GET /findings/possible/audit`. `TestPossible_Count_EveryPossibleCVEHasAReason`.
  An operating-system row a CVE's rows do not name, when every row is an application and NVD's running-on condition of one names an
  operating system of the row's vendor (cpeMatch vulnerable false: the environment, not the affected product), is `named_as_platform_only`
  (`platformOnly`), its evidence the rows that name the system: not affected as a product. Only an exploited list ties such a CVE to the
  system's row, so the row stays possible with cause `needs_person`; an application row is matched by the same rows as always.
  `TestPlatformOnly_OperatingSystemNamedOnlyAsTheEnvironment`.
- **P-3 Check identity.** The match pass gives each checkable question (one CVE, a line with a version, no_range_data, older_line, a
  not_comparable no build attribute decides or one whose edition is known and whose release line the rows do not list, `unlisted_line`, NVD answered) `check_key`: the CVE, product, release line, exact version and the CVE record's
  stamp (`feeds.RecordStamps`). A changed version or record gives a new key. `TestPossibleCheck_KeyFollowsTheEvidence`. A changed
  record alone never drops a verdict: the last check of the same CVE, product, release line and release (version and stated build) keeps
  applying, either way, until a check of the new key replaces it, and the CVE is checkable again (`checksFor`).
  `TestPossibleCheck_ARecordChangeKeepsTheLastVerdict`.
- **P-4 The app first.** A check (`POST /findings/possible/check`, operator, one at a time, at most 40 keys, in the background) reads each
  key once (`fnd_possible_check`): the box fetches the CVE's reference pages (https, by the catalogue's tags, never an exploit page;
  through the ai module's guarded fetcher) and reads a CSAF advisory or a vendor's plain-text ranges itself (`readAdvisory`; "not
  affected" only from the vendor's own advisory: a reference tagged vendor-advisory or a page on the vendor's host; "affected" from any
  page, `TestPossibleCheck_NotAffectedOnlyFromTheVendorsAdvisory`); a decision there is the box's own
  (`decided_by advisory`, quoted) and the next match applies it like range data (affected: a finding, range origin `advisory`, its basis
  and confirmation from who stated the version; not affected: the question stays, listed as settled). Only the rest goes to the AI
  (P-6: a reading of the release line; checks `decided_by ai` stored before P-6 stay proposals, `confident` or `likely`); unsure keeps the
  CVE possible with the reason. A failed or budget-stopped call stores nothing. The AI reads the whole CVE record beside the pages (its
  description, the CNA's solution and the affected rows of every product it names, the line's own first, at most 40), and the record
  alone when no page could be read (none referenced, every page failed, or a script-rendered shell): a person reads the record too
  (`TestPossibleCheck_NoPageReadTheAIReadsTheRecord`, `TestLineReading_TheRecordAloneIsReadWhenNoPageIs`); a record with no text and no
  page read is not sent and nothing is stored. A check stored before this that says only that no page could be read (`no_reference_page`,
  `fetch_failed`, `decided_by structured`) is checkable again (`TestLineReading_ACheckThatReadNoPageIsReadAgainFromTheRecord`). A page
  whose text has no CVE id and no version number, or names neither the CVE nor the product (a script-rendered portal's shell), is not
  read and its text is not sent (`TestPossibleCheck_AScriptShellIsNotARead`). The AI request carries no device data. `TestPossibleCheck_AppFirstThenAIProposalsOnce`, `TestPossibleCheck_SendsNoDeviceData`, `TestPossibleCheck_AStopKeepsWhatWasDecided`.
- **P-5 A person decides proposals.** Confirm one (`POST /findings/possible/{id}/confirm`; affected needs an admin) records the finding
  (range origin `ai_confirmed`, kept by the match while the answer applies; its confirmation from the version's source, never from the AI;
  its view carries the AI's check as `ai_check`: pages, quote, model) or answers not affected (the Answered list carries the check as
  `check`, `TestAIChecked_ViewAndAnsweredCarryTheCheck`); confirm a class at once (`POST /findings/possible/confirm`), never an exploited CVE proposed not affected (an
  exploited list that cannot be read confirms nothing); reject
  (`POST /findings/possible/checks/{key}/reject`) makes it possible again and is not checked again for the same evidence. An exploited CVE
  never vanishes: `TestPossibleCheck_Count_ExploitedNeverVanish`.
- **P-6 The AI reads the vendor's statement for the release line.** What the box's own reading leaves goes to the AI once per release
  line (product and line; the versions on it named together), not per version: it answers by schema the vendor's statement for the line
  (`affected`, `fixed` with `fixed_in`, `not_affected`, `unsure`; `introduced`, `fixed_in`, `last_affected`, `line`, a verbatim `quote`, the
  page's number). The box keeps it in `fnd_line_statement` (`LineStatement`), keyed by the CVE, product, line, the CVE record's stamp
  (`CheckID.Record`) and the cited page's text hash: `quote_found` when the quote is in the text the box fetched itself, word for word;
  a bound only when the quote or the cited page names it (a tracker's "present-in" and "fixed-in" lines), of which only a bound the
  quote names places a version past it or becomes the fix (`TestLineReading_ABoundOnTheCitedPageOpensButNeverSettles`); `fixed`
  with no named bound is `unsure`; an answer inferred from another product's release line of the same record (`inferred_from`: the record
  states line N of that product fixed or affected in a release N.x and nothing for this product's line N) is stored with `basis inferred`
  (`fnd_line_statement.basis`, else `stated`; an answer whose quote is only in another product's row of the record is inferred whatever
  it says, `otherProductsRow`, `TestLineReading_AQuoteOfAnotherProductsRowIsAnInference`; so is one whose quote names another product of
  the record and pairs a release of the answer (a bound, the "before X" fix on the version's train, or the version or line itself, at
  any place the quote names it) with the other product, the nearest product name before it, a name inside a longer one being the longer
  one's ("Mail" in "Mail Server") and this product's edition ("Browser ESR") being this product: `unpairedBound`,
  `TestLineReading_ABoundPairedWithAnotherProductIsAnInference`, `TestLineReading_AReleaseTheQuotePairsWithAnotherProductIsAnInference`),
  keeps no bound and stands only
  as `affected`, with a quote naming that release, and only while no row of this product names a release of line N
  (`ownRowOnLine`), or as `not_affected` (a proposal for a person like every AI "not affected"), never as `fixed`; a cited page that names neither the CVE nor an advisory
  the CVE record references (the id in a reference's address, `aboutCVE`) makes the reading `unsure`, so it decides nothing either way. Only the newest reading of a (CVE, product, line) is kept;
  one a person rejected stays, so the same page is never applied again. The match applies it to every device and version on the line, and
  to another line of the product when the quote names a line containing the version (`readingFor`, `coversLine`), by the product's
  scheme or the generic order (`verdictFor`). An inferred reading is decided from its basis, not its quote: it never gives a fix, and when its quote names its stated line only through releases of it ("115.42" for line 115) it speaks for a
  version on that line before every such release (`namedByRelease`), with evidence that says the AI inferred it
  (`TestLineReading_AnInferenceFromAnotherProductsLineOnlyOpens`, `TestLineStatement_AnInferredReadingIsNeverAFix`).
  Asymmetry: inside the stated affected releases is a finding by itself (range origin
  `ai_read`, evidence "Read by AI from <host>", fix only the release the quote names, its `fixed_in` or a "before X" on the version's
  own train: `LineStatement.fix`; What to do cites the page and the sentence), rejected in one click
  (`POST /findings/possible/checks/{key}/reject` with the reading's key, audit `findings.ai_reading_rejected`: every device of the CVE is
  matched again at once, the finding closes `data_corrected` and the CVE is possible again, `findingKeys`). **An AI reading never settles
  "not affected" by itself:** past the stated fix on the same line, or the line named not affected, on any page and with any basis, is an
  AI proposal a person confirms or rejects (P-5: `needs_person`, an exploited CVE's never in bulk;
  `TestLineReading_AnAIReadingNeverSettlesNotAffected`, `TestLineReading_NotAffectedOnlyFromTheVendorAndNeverAloneForAnExploitedCVE`).
  The vendor's own page (`FetchedPage.Vendor`: tagged vendor-advisory or on the vendor's host, never by what a path reads,
  `TestMarkVendorPages_OnlyTheVendorsTagOrHost`) is shown with the proposal. The fix of a finding a reading opened comes only from a
  `basis stated` reading: every version-like token of the quote follows this product's own name as the record or the catalogue writes it,
  with only spaces or its own edition word between, and the word before that name is the vendor's name, the start, punctuation or a
  lower-case word (`namedWithThisProduct`: "Mail 115.42", "Mail ESR 115.42"; never "Mail Server 115.42", "Thunder Mail 115.42", "fixed in
  115.42" or a quote with a second version not so named, which are `basis unpaired`;
  `TestLineReading_OnlyAVersionNamedWithThisProductIsStated`, `TestLineStatement_AFixOnlyFromAReleaseNamedWithThisProduct`,
  `TestNamedWithThisProduct_EveryVersionLikeToken`, `TestNamedWithThisProduct_TheWordBeforeTheName`); readings stored before the basis
  existed are `unpaired` until read again. Anything else decides nothing. A reading is read again when the record changes (the old one
  applies until then), after 30 days when `unsure`, and its page is fetched again after 30 days (no AI call when its text is unchanged:
  `seen_at`). A finding the reading opened has no question, so the match notes its line when due (`noteReadingDue`) for the next check.
  `TestLineReading_*`, `TestLineStatement_VerdictFor`.
- **P-7 The reading runs by itself.** What it reads never closes a CVE by itself: its "affected" opens a suspected finding, its "not
  affected" is a proposal a person confirms (P-6). After each reconcile pass the box starts the automatic reading (`AutoRead`, actor `system`, at most
  200 evidence identities, exploited CVEs first, then the highest CVSS score) while a check can run, the AI settings have it on and its
  reads for today are not used up (`PossibleChecker.Budget`); a person's check still runs as before. It runs only after the hourly
  reconcile pass, not on its own timer. Only a real stop ends a run (`CheckStop`: the AI unavailable, the reading switched off, a budget
  or the runaway fuse, the provider unreachable). A call refused for its own text or answer (`ItemRefused`: a hook, an answer outside the
  schema or cut off) is that call's items alone: the run goes on with the next item, and the automatic reading leaves those items until
  their retry time (a day), so one item that cannot be read is never first again at every run. Any other failed call (the provider
  answered an error, the hooks could not finish in time: they decided nothing) does the same with an hour's wait; `aiFailStreak` (3)
  such calls in a row, or unusable answers (`ItemRefused.Systemic`: outside the schema, cut off), with no answer between, stop the run,
  also within one CVE; a hook's refusal neither counts nor resets. The run ending its own time stops it (`CheckStop`). The ai module paces
  the automatic calls below the runaway fuse (ai INV-4), so a person's Explain in the same minute is not refused. A held item's row says
  until when and why (`PossibleRow.held`: `until` and a `reason` of the closed list `HeldReasons`: `hook_refused`, `answer_unusable`,
  `ai_failed`; never the provider's words; its cause stays as P-8 names it); `held` is null while the automatic reading cannot run
  (switched off, today's reads used up, no AI profile), so the row never promises a reading that does not come. A person's check reads held items at once; an answer clears
  the hold (kept in memory only; a restart forgets it). `TestAutoRead_RunsOnlyWhenSwitchedOn`,
  `TestAutoRead_ARefusedItemDoesNotStopTheNext`, `TestPossibleCheck_TheAIFailingInARowStopsTheRun`,
  `TestPossibleCheck_TheAIFailingInARowStopsWithinOneCVE`, `TestPossibleCheck_UnusableAnswersInARowStopTheRun`,
  `TestPossible_AHeldItemSaysUntilWhenAndWhy`.
- **P-8 Every possible CVE names its cause.** `PossibleCause` (one exported function, also for the coverage of a match pass) gives each
  possible CVE one cause of the closed list `PossibleCauses`: `vendor_silent`, `page_unreadable`, `needs_reading` (no AI, or the reading to
  come), `ai_unsure`, `ai_budget`, `identity_unproven`, `version_needed`, `pending_nvd`, `needs_person`; `null` only for a settled row. The
  list row carries it (`PossibleRow.cause`) and the counts group by it (`PossibleCounts.causes`); an unlisted release line the reading can
  decide (checkable) has the reading's cause, not `version_needed` (`TestCheckable_AnUnlistedLineIsRead`).
  `TestPossibleCause_EveryPossibleRowHasOne`, `TestLineReading_CauseWithoutAIAndWithTheBudgetUsedUp`.
- **P-9 The customer's AI identifies what no standard data names.** A software line with no CPE, no distribution package, no catalogue
  alias and no CVE record that writes its names (coverage identity `none`), whose version the agent, SNMP or a person stated, is asked
  about after a match pass (`AutoIdentify`, the same switch, readiness and daily reads as P-7, before the reading). The box generates up to
  20 candidates itself (`identitycand.go`), only from products its own catalogue names (`Identifier.Products`: a range's CPE
  vendor:product, a CVE record's product key, an exploited-list entry; nothing is fetched): the publisher and display name are cleaned
  (legal-entity words, the line's version, version numbers, architecture, language and text in parentheses dropped, `IdentityKey`) and
  ranked by the words they share with each product's vendor and name; the same cleaned name is only the first candidate, never a link.
  A name no product shares a word with is not asked (it stays `none`). The AI answers by schema a candidate's id, `none` or `unsure`,
  whether the program is that product itself (`exact`) or only a part of its family (`family`: an agent, a client, a plugin of it), with
  a reason (at most 5 names a call, exploited-list candidates first); the box keeps a product only when it is one it offered and shares
  a non-stopword with the name (`verifyChoices`; anything else is stored `unsure`; a product not said to be `exact` is `family`). A
  `family` match is stored and counted (coverage identity `ai_family`) and opens nothing yet. One row per cleaned (publisher, name) in
  `fnd_identity` serves every device. It is asked again (`askAgain`) only when the chosen product left the candidates, or, for `none` and
  `unsure`, after 30 days, or after 7 days when a product it was not offered entered the top 5 (the top 5 are kept as short hashes); other
  candidates coming and going ask nothing. A call that fails after it was sent (an answer outside the schema, the provider) makes its
  names wait a day and the run goes on with the next names (a call a hook refused too); `aiFailStreak` failed calls in a row (a hook's
  refusal aside) stop it, as in P-7 (`TestAIIdentity_FailingInARowStopsThePass`); a budget, the runaway fuse, a missing profile or an
  unreachable provider stops the run (the binary's `aiCallError`, the same rule as P-7). Every call that reached the
  provider counts toward the daily number, and the identification may use at most half of it (ai INV-6d). The names sent
  have the box's device and account names, email addresses and user folders replaced (`scrubber`, `Identifier.PrivateNames`). Effect
  (`Software.AIProduct`, set by every `MatchInput` this service reads, `aiInventory`; `devMatch.aiGuard`): the chosen product only
  opens. A version inside its ranges is a finding unless the line's own names decide the CVE; the finding's evidence carries the
  identity (`Evidence.Identity`), it is never confirmed by the version alone (suspected: the device states its version, not that the
  CVE is about this software), and the view says "Identified by AI as <title>" (`View.identity`, with the AI's reason and model). What
  its ranges say otherwise (outside, a version needed, a question) decides nothing: the pair reads as the line's own names read it, so
  nothing is closed, proved or asked on the AI's word. "Not this product" (`POST /findings/{id}/identity/reject`, operator, audit
  `findings.ai_identity_rejected`) stores a `rejected` row for the name that wins over the AI (the product is never offered for it
  again), drops the AI's choice and matches again at once the finding's device and every device whose last match had a line of that
  name (the findings close `data_corrected`, resolved by that person: `goneVia`, `identityRejectedBy`). No AI: nothing runs, the lines stay `none` in the coverage. `TestAIIdentity_*`,
  `TestIdentityCandidates`, `TestIdentityScrubber`.

## Invariants

**Matching**
- **INV-1** One finding per (device, CVE, line) (M-1).
- **INV-4** Exploited-list entries are keyed `vendor|product`; a "multiple products" entry yields a finding only through an NVD row
  that names the software itself.
- **INV-4a** Version ranges come from feeds' match set (NVD's with the CVE record's CNA rows beside them, else the record's). A record
  row beside NVD's that is not its vendor's complete list (`Affected.AffectedOnly`) only ever makes a version affected, and only a version
  it states: outside it, it neither applies nor proves "not affected" (`decide`, and `viaNVD` never closes on a reach only such a row
  gives). A row of a complete record list (`VendorList`) decides both ways, an exact release it lists too (`nvdNames`). A finding the
  record's rows alone call affected stores `range_origin` `cna` (`recordDecided`). A line with no usable version that cannot be decided is
  a question, not a finding. A row inside one release branch that is not the version's and does not compare with it (VLC's `0.4.3-ac3`
  against 3.0.20, `otherBranch`) is set aside: the rows that compare decide, and rows set aside alone decide nothing
  (`TestDecide_RowOfAnotherBranchDoesNotBlockTheDecision`). OpenSSL's letter releases past `z` (`0.9.8za`, `1.0.2zd`, `1.1.1zk`) order
  after `z` and compare like any other (`TestDecide_OpenSSLLetterBranches`).
- **INV-4f** Record shapes (`recordshape.go`), read from the rows' shape, never from the product they name: an application row whose
  version is NA (`-`) beside a row that versions the same product is about no version and does not apply to a line with a version (CPE
  name matching: NA and a value are disjoint; alone, or on an operating system or firmware, it stays undecided; an NA row that names a
  build, an edition, system or architecture, is apart only beside a versioned row of that same build); a bare row of every version
  beside a row of the same product and build that ends and has no start is NVD's legacy "and earlier" marker, and the bounded row decides; an exact
  row named by a word ("preview_release") is set aside, and decides nothing unless the version is past the end of a row that says No. A
  partial CVE record proves "not affected" for a version past a fix it states (an excluded end; an included end, "through", is the last
  version known affected, not a fix) on a train it covers (OSV's introduced/fixed): past a row from
  0 with no listed row above the version, or past a row that starts on the version's own major.minor, or at or past a fix the record
  states above all its rows (feeds `LineFix`: a lone unaffected version) on that fix's own first number with no listed row above the
  version; a version between listed trains, or between the last one listed affected and such a fix, stays a question (`pastRecordFix`).
  A version at or past a fix (an excluded end) on that fix's own major.minor, inside no row and below the start of no row of that
  train, is not affected under both readings of such a list (every affected release listed, or only the trains its writer tested), and
  so is decided, also for a record's rows read beside NVD's when no NVD row names the line (`fixTrainReadings`); never for a CVE on an
  exploited list, which a person closes. A record row limited to one operating system (feeds `recordSystems`) names it as target_sw. A
  question left by a row that does not compare is `version_scheme_mismatch` only when the version does not read, a row is in another
  scheme, or a row is of the version's own train; else `ranges_do_not_decide`. `TestRecordShape_*`.
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
  follows them (ESXi 8.0.3 is later than `esxi:6.5:update1`, not than `esxi:8.0:update_3`). Nor is one NVD's exact list leaves out
  by its release line, in a notation whose lines are known (`lineOrder`: Junos 25.4R1 against 24.4 and 25.2 releases, Java 8
  Update 491 against 8u441 and Java 11, 17 and 21): the list enumerates the affected releases. Only a line newer than or between the
  listed ones is left out: a line older than every listed one stays asked (end-of-life lines are often not evaluated: Junos 15.1R7.9,
  Java 7 Update 401), and so does an older update of a listed line (Oracle's "8u77 and earlier").
  `TestUnchecked_OtherReleaseLinesAreNotListed`, `TestUnchecked_OlderLineThanEveryListedStaysAsked`. A release the product's version
  scheme reads as written (Junos "15.1R7.9", `schemeReads`) that NVD's rows do not decide is `no_range_data` listed (answered per CVE),
  never `not_comparable`, whose only action is to type the version again. NVD's NA in an edition ("-") is the plain
  edition, one of the alternatives. The build attributes NVD pins after the version (sw_edition, target_sw, target_hw) are derived
  for a line from evidence the box holds, in one table (`installattrs.go`, `installRules`, `installOf`): the architecture its name states
  ("(64-bit)", "x64", "(x86)"), or a product that ships one only (SQL Server 2016 and later: x64), or a 32-bit system; the system family
  its own agent reports (`platformOS`); Mozilla's version shape for Firefox and Thunderbird (an ESR build is M.N.x with N of 1 or more on
  an ESR major, a normal release M.0 or M.0.x on another major); Node.js's "-" and "lts" are release phases of one line, so its version
  alone decides. A row the derived attribute satisfies is read without that pin; a row about another build does not apply (`judge`): for
  Mozilla, NVD lists the ESR rows whenever an ESR is affected, so an ESR build inside only the plain rows is not affected, except when
  the CVE lists ESR rows and none spans the build's ESR line: Mozilla lists supported ESR lines only, so an end-of-life line
  (Thunderbird 115, or Firefox ESR 140 between the listed 115 and 153; an exact ESR row lists its own line only) stays asked whether that
  line is affected (`detail.attribute` `unlisted_line`, never the edition: `TestMatchAsset_UnlistedESRLineStaysAsked`). A platform's
  "-" alone is every build (Visual Studio Code); beside named systems (Office's "-" and "macos") it is the build for none of them. A
  derived attribute is the device's evidence (the finding is verified `device`) and the evidence names it. What is not derivable stays
  pinned (#906): a version inside the range of every edition NVD lists is a version finding whichever it runs (`pinnedInside`); inside
  some only, a `not_comparable` question whose `detail.attribute` names what decides it (`edition`, `architecture`, `platform`,
  `blockingAttribute`), so the queue asks for it and never to retype the version; a row that states its edition is judged by it
  (`TestMatchAsset_EditionOfTheBuildDecides`, count test `TestQueue_Count_InstallAttributes`). A version inside a range with an end
  and an open-ended one is read with the range that has an end. A release the device states is stored as `device_version`. An ESXi
  update is never read as later than NVD's exact GA entry (`esxi:8.0:-`): NVD lists only 8.0 GA for flaws VMware fixed in 8.0 Update
  3d, so the question stays (`TestLaterThan_ESXiUpdateIsNotLaterThanTheGAEntry`). A `no_range_data` question says whether the CVE lists
  versions of the software at all (`detail.listed`, `versions_listed`): "gives no affected versions" only when it lists none. When
  the vendor's own rows (`Vuln.Schemed`) name fixed releases only on release lines later than the line's own and nothing about it
  (Synology naming DSM 7.3.2 and 7.4.1 for a device on 7.2.1), those CVEs of one line are one `older_line` question (`cve_list`, `line`,
  the newest fix of each later line in `fixes`): no verdict either way. A person's answer to one CVE's own question keeps that
  question whatever its kind, while it was given for the version the line runs (`answeredFor`): the CVE is not asked again under
  another kind nor in an `older_line` group; a CVE joining an answered `older_line` asks it again (`replaceQuestions`).
- **INV-4h** A device a person added (not the box) that the matcher has nothing to match by (no software line, no network OS it
  states as a line, no OS its agent, SNMP or LLDP states or a person set: `nothingToCheck`) has one `nothing_to_check` question. The
  queue shows it as a `device_unchecked` item (add its firmware, SNMP read access, or an agent) and the device badge counts it; it
  cannot be answered "not affected" and leaves once something says what runs there (`TestNothingToCheck_QueueBadgeAndAnswer`). Count
  test: `TestQueue_Count_ResidueByKindAndCause`.
- **INV-5** The severity a match reports for a new finding: version evidence is `high` (`critical` with ransomware use or EPSS ≥ 0.5);
  product only is `medium`. The shown severity of a finding is the CVE's CVSS band.
- **INV-6** Writing a match is idempotent per (device, CVE, line) and goes only through `Transition`.
- **INV-6c** A line a person marked not installed is not matched; its findings close as `not_relevant` via `not_installed` under
  that person's name.
- **INV-11** "I have this" on a versionless product matches, on exactly the declared device, only entries added since its start date.
- **INV-14** A packaged agent line on Ubuntu, Debian or Alpine Linux is judged by the distribution's fix data before NVD's ranges, one
  path for every distribution the feeds supply (`distroVerdict` through the distribution's adapter `distroData`: its release, release
  order, own builds and which row decides). A fixed release compares with the distribution's own build of the same upstream release, or
  of a later one (never a kernel's). An Alpine package release (`-rN`) counts within its branch only: only the device's own branch's
  fix of the same upstream release proves a package fixed; another branch's fixes on the package's own upstream release line
  (major.minor, `apkLine`) only show a release below them (an older upstream release than every one of them), never fixed; a fix on
  another line says nothing; otherwise NVD's upstream ranges decide, on an exploited CVE as on any other (`alpineFixBranch`,
  `TestMatchAsset_AnotherAlpineBranchsFixNeverPatches`, `TestMatchAsset_AnotherAlpineBranchsFixOfAnotherLineOpensNothing`). Alpine's data
  lists fixed releases only (secdb), so a CVE it names no fix of leaves its package to NVD's upstream ranges (`upstreamJudges`, as
  Grype's apk matcher); Ubuntu's and Debian's silence decides nothing. The distribution's "affected, no fix yet" of a CVE on no exploited
  list raises no finding (it would ask for an update that does not exist) until the fix or an exploited list comes; the coverage counts
  it decided affected (`distro_no_fix`).
  `TestMatchAsset_AlpineRowsDecideCatalogueCVEs`, `TestMatchAsset_UnfixedDistributionWordRaisesOnlyExploitedCVEs`. A package the
  distribution built (its revision carries the distribution's mark, or it is the distribution's kernel) is judged by that data alone
  while the distribution's feeds are on (`Vuln.DistroOn`, `distroDecides`): its word "affected, no fix yet" (status `open`) is a
  finding with no fixed package yet (fix `none_yet`; Debian's reason when it publishes no security update), and with no word yet NVD's
  upstream ranges still raise a finding, never confirmed, whose evidence says the distribution has not published its answer yet
  (`awaitingDistro`): the distribution's word, when it comes, closes or confirms it. A person's patched mark on a fix only Ubuntu Pro
  has reopens saying so.
  A vendor's own .deb with a plain revision, and a distribution whose feeds are off, keep NVD's ranges. A version move on a line with
  a package release is ordered by the package scheme alone ("1ubuntu2" to "1ubuntu2.1", "+esm3" or "+deb13u1" is `version_moved`).
- **INV-14k** A distribution kernel is judged once per CVE, on its Kernel line (intake makes it of the running kernel's image alone).
  On Ubuntu and Debian an agent's package built from a kernel source package that is not the Kernel line (the ABI-named headers,
  modules and tools of any installed kernel, an image that does not run, a metapackage, linux-libc-dev) is never matched. When an
  installed image the device does not run, built by the distribution, is at or above the distribution's fix, the fix is `restart`
  (`fix_version` = that image's package release) and the evidence says so. Debian's own kernel builds compare across upstream point
  releases inside one kernel series (its stable kernel moves to them; a release never changes series), and a long-term-support
  series shipped as a source of its own (Debian 11's linux-6.1, signed by linux-signed-6.1-amd64) is judged by that source's rows.
  `TestDistroKernelOnceOnTheRunningKernel`, `TestCount_DistributionKernelFindings`, `TestMatchAsset_DebianKernelComparesOnlyInsideItsSeries`.
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
  (mitigation registers it; it is skipped while mitigation is off). The stored evidence sentence keeps its last clause "no scan has
  confirmed it yet, so this is only suspected" only while the finding is suspected (`evidenceForStatus`; the stored row is unchanged).
  `known_version` comes from the row the exploited-list entry matches, or, for a finding on no exploited list, from the finding's
  stored software line; on a row with a package release it is that release, the one the match compared. Every history action has a label on the page; urgency_changed and fix_changed carry a note naming the new
  status or fix. Tests: `TestFindingPage_EvidenceFollowsTheStatus`, `TestFindingPage_FindingOnNoListKeepsItsSoftware`,
  `TestFindingPage_EveryHistoryActionHasALabel`.
- **PRE-4 / POST-4** handle and reopen (operator), verify and unverify (admin): handle answers how many it handled and skipped and
  is all or nothing. A person's claim is checked against the evidence: `patched` on a finding the latest match still detects on a
  version reading (`stillReported`: device version, package, banner or an entered version inside the affected versions) is refused once
  with that reading (409 `still_reported`, nothing written) and kept only with `confirm` (`HandleConfirmed`); it then opens again on a
  newer reading that still shows the version (M-3). `TestVersionEntryMatrix` (cmd/vedette).

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
  urgency facts, `HaveSince`), `inventory` (`MatchInput`, `AssetIDs`, device refs, ignored devices, `ToReviewIDs` for the one card of the devices not added yet with no open finding).
- **Used by** (adapters in `cmd/vedette` unless noted): mitigation (imports findings: guidance, AI answers), notify
  (`notifyfindings.go`), scan (`ConfirmFromScan`), response, reports (`Views`, events), ai and mcp-server (`Views`, `ByDevice`),
  inventory (`DeviceStatuses`, `EarnReview`), exposure (`MatchAsset`, `FixOf` in `exposurematch.go`), feeds (`PinnedCVEs`), ids
  (urgency reasons), the finding page (`findingcase.go`).

## When off

No `/findings*` routes and no `reconcile` or `urgency` jobs; tables stay. Notify has no vulnerability alerts, scan results carry
no finding, the Devices page loses findings and badges, reports lose their vulnerability section, and mitigation loses its input.
