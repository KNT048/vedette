# Feeds contract

> Tier: standard · Stories: S-FEED-1…5 · Tables: `feeds_*` ([`docs/DATA_MODEL.md`](../../docs/DATA_MODEL.md) 4.1)

Feeds pulls vulnerability knowledge and indicator lists straight from their publishers, parses them on the box, and keeps one
vulnerability catalogue plus the signals that make a CVE urgent. Other modules read it through Go functions, never through its
tables.

## Endpoints

| Route | Minimum role |
|---|---|
| `GET /feeds/status`, `/feeds/hot`, `/feeds/weekly`, `/feeds/cve/{id}`, `/feeds/cve/{id}/tier`, `/feeds/search`, `/feeds/sources`, `/feeds/window` | viewer |
| `POST /feeds/weekly/{id}` | operator |
| `PUT /feeds/sources/{id}`, `PUT /feeds/window`, `POST /feeds/sources/{id}/fetch`, `POST /feeds/custom`, `PUT`/`DELETE /feeds/custom/{id}`, `POST /feeds/parse-test` | admin |

Request and response shapes: `web/src/features/feeds/contract.ts` (the source of `api/openapi.json`).

## Invariants

IDs are stable (code comments cite them); a retired ID is not reused.

**Outbound traffic**
- **INV-1** The box pulls only declared sources that are on: the built-in list (`sources.go`) and custom feeds. A pull is a GET to
  exactly the feed's URL and sends no customer data. Feed data never comes through the project's own repository or a central
  server. `TestContract_INV1_OnlyDeclaredSources`.
- **INV-2** A feed URL is `https`; `http` only to an internal host. Limits of a pull: 5,000,000 bytes, 50,000 rows (a built-in
  source may set its own byte and row caps, counted after the transport's decoding: Oracle's CSAF documents 16 MB each, read as a stream),
  60 seconds; redirects only to the same host, at most 5.
- **INV-13** Every built-in host is listed in `PRIVACY.md` flow 1 and on Settings → Privacy.
- **INV-17** No pull connects to Vedette itself (loopback, the core container, the honeypot decoys, Vedette's own ports on the
  machine's address), to link-local or to cloud metadata addresses. The guard runs on the resolved address right before connect
  and on every redirect. A literal address it would refuse is already refused when the feed is saved (`blocked_host`).
- **INV-21** VulnCheck KEV needs the customer's own key: it cannot be turned on without one and sends nothing until then.
  It reads the whole list by VulnCheck's cursor paging (`start_cursor`, then each page's `_meta.next_cursor`, 100 entries a page,
  at most 500 pages), whatever the number of pages. A read that is not provably complete (no `total_documents`, a repeated or
  ignored cursor, an empty page, fewer entries than `total_documents`, more than 500 pages) fails the pull and keeps the rows
  loaded before. A refused key (401, 403), a rate limit (429, with VulnCheck's `Retry-After`) and a plan without the list (402)
  each say so in the feed's error.
- **INV-22** After its first fill, a distribution feed is pulled only while a device runs that distribution (Alpine: only with an
  Alpine device at all).
- **INV-22a** A distribution feed keeps, for every CVE of the CISA list, the distribution's word fixed, not affected and "affected, no
  fix yet" (`open`), and for the catalogue's CVEs of the last 12 months (the tier CVEs) the same words for the source packages and
  releases the devices run (`DistroWant`, `DistroLister`: Alpine every branch); ubuntu-vex keeps only "not affected", Ubuntu's only word
  that a release's package is not affected. Findings reads them all (`DistroFixes`, `DistroFixesFor`) and judges a package the
  distribution built by that word alone while the distribution's feed of fixed and affected rows (debian-tracker, ubuntu-osv; never
  ubuntu-vex) is on (`DistroOn`: on and loaded, or loading). Debian's open entries it will not fix in a security update (no DSA,
  postponed, ignored, unimportant, end-of-life) are kept with that reason (`feeds_distro_fix.reason`, `DistroReasons`).
- **INV-22b** A distribution pull depends on the catalogue's window and the inventory: a feed whose last good pull kept no tier row
  while both are there now (`distroPartial`: the first pulls of a new box come before the window loads) shows as an error on the Feeds
  page and is pulled again at the next check, not a day later; a device's new package or release pulls it again at the next check
  after 6 hours (`distroBehind`). A pull whose rows of a CVE on no exploited list changed runs findings' match pass now
  (`RangesUpdatedEvent.Catalogue`), as does turning a distribution feed on or off. `TestDistroPullRunsAgainWhenTheWindowAppears`.
- **INV-38** Spamhaus DROP (`spamhaus-drop`) is off on a new box and on a box that updates to a version that adds it
  (`Source.DefaultOff`): the box asks `www.spamhaus.org` nothing until an administrator turns it on. Once on, it reads Spamhaus's
  `drop_v4.json` once a day by default, conditional on the last file. Spamhaus asks that the list be downloaded at most once a day,
  and automated downloads at least an hour apart (`Source.MinHours` = 24): the feed's schedule cannot be set below 24 hours
  (`sourceLimits`, the schedule's `LimitsOf`: the editor says "Spamhaus DROP asks for at most one download every 24 hours."), and
  neither the pull job nor Fetch now asks it sooner than 24 hours after its last good pull or an hour after any attempt, a failed one
  included (`fetchFloor`); Fetch now then answers 409 `fetch_too_soon` with the time it becomes possible (orgtime, zone named).
  `TestSpamhausDROPIsOffByDefaultAndMatchesTheAddressesInsideItsNetworks`, `TestSpamhausDROPIsFetchedAtMostOnceADay`.

**Parsing**
- **INV-3** The parser fails closed: an invalid row is dropped and counted by reason, never stored. Feed text is untrusted plain
  text; consumers escape it for their own output.
- **INV-7** `POST /feeds/parse-test` writes nothing and makes no network call: it parses the caller's sample or the built-in one.
- **INV-39** The Spamhaus DROP list is read by `ParseSpamhausDROP` (its JSON form, and the text form for a mirror: comments after
  `;`). A row is kept only as a canonical network (no host bits, not IPv4-mapped) of IPv4 /8 to /32 or IPv6 /16 to /128 that is
  neither inside nor around a private, reserved or documentation range; a network of one address is stored as the address. The list
  is refused whole (the networks stored before stay) when it is over 5,000,000 bytes or 20,000 rows, has no accepted network, or
  its JSON form does not end with exactly one metadata record whose `records` equals the rows read. `TestParseSpamhausDROP`,
  `FuzzParseSpamhausDROP`.

- **INV-41** The CVE Program's list of CNAs (`cve-cna-list`, `CNAsList.json` from `CVEProject/cve-website`, the list cve.org shows) is
  pulled once a week, at most 2,000,000 bytes, conditional on its ETag, and replaces `feeds_cna` whole: per CNA its short name (lower
  case; a short name two CNAs share is left out), organization name and whether it may be a vendor (`cnaMayBeVendor`: typed Vendor or
  Open Source, and a scope that does not define itself against another CNA's scope); no contact data. A list that is not one JSON array,
  holds no usable entry, or holds fewer than half the CNAs stored is refused and the stored list kept. A record's CNA is the vendor's
  own by the list when one form of its organization name (`cnaOrgForms`: case, punctuation, a leading "The", parts in parentheses and
  trailing legal-form words set aside) is the row's vendor; no name of a vendor or CNA is written in code or data. The list is read only
  while its feed is on and its last good pull is under 30 days before the box's newest pull of any feed; else the rules of INV-35
  stand alone. A list that changes what is read emits `RangesUpdatedEvent` (`Catalogue`), and the feed's pulls move `MatchStamp`, so
  findings matches again without the records being read again. `TestOwnCNA_TheCNAListNamesTheOrganization`, `TestParseCNAList_RefusesWhatIsNotTheList`,
  `TestCNAList_PullDecidesWhoseUnaffectedCounts`, `TestCNAList_ArrivingLaterDecidesOnlyTheVendorsOwnRecord` (cmd/vedette).

**Feeds and pulls**
- **INV-4** A built-in feed cannot be deleted, only switched off or pointed at a mirror. Deleting a custom feed deletes what it
  loaded and its schedule. A built-in feed the code no longer lists is deleted at start with its rows (INV-16).
- **INV-5** A feed's schedule is the `core_schedule` row `feeds.source:<id>`, an interval of 1 to 168 hours. Feed names are unique
  ignoring case; a custom feed's URL may not equal another feed's (`duplicate_url`).
- **INV-6** Feed credentials are sealed with `core/secrets`; the API returns only the last four characters, and a blank secret on
  save keeps the stored one.
- **INV-8** One pull at a time per feed; "fetch now" on a feed that is off is 409 `feed_disabled`. A pull's result is one
  transaction (an indicator list goes in batches of 2,000 rows so the single writer is not held); a feed edited, switched off or
  deleted while it pulls has its result dropped (`rev`). A failed pull records the error and backs off (5 minutes, doubling, never
  past the feed's interval) without stopping the job.
- **INV-9** A feed that is on and reachable is never more than 60 minutes past its interval (`IsStale`); the UI always shows when
  the data was fetched.
- **INV-15** The CISA list is asked at cisa.gov and at CISA's GitHub copy on every check; the newer plausible catalogue wins and
  `answered_by` names the copy. One failing copy is a note on a good pull.
- **INV-29** When both CISA copies fail at two consecutive checks, one critical alert goes out through notify, and one "up to date
  again" message when it recovers.

**Catalogue**
- **INV-34** The reporting window (`window.go`). A CVE is inside it while it was published within 365 days, or has an exploited-list
  entry (the CISA list, VulnCheck KEV, a custom list), or a qualifying `exploited` signal (a vendor or a research team says it is
  exploited) of any age, or a qualifying public exploit that appeared within 365 days. Only a date that means the exploit appeared
  counts: `first_seen` of Exploit-DB (date_published) and PoC-in-GitHub (the repository's date) (`datedSignalSources`). Metasploit's
  `first_seen` is a module's last change (mod_time) and the scan templates' is the day this box first read them: for those the day the
  box first stored the entry (`stored_at`) counts, and only once the box has held entries of that source since before the window (its
  oldest `stored_at`), so a box that first read an index inside the window renews nothing from it. `TestWindow_OnlyADateThatMeansTheExploitAppearedRenews`.
  This network's own intrusion alerts naming a CVE keep it inside the window, at any age, until 12 months after the latest such alert:
  the pull job's maintenance reads the alerts of the last 30 days (`Deps.Attacked`, the ids module's through wiring) into one
  `attacked_here` signal per CVE (source `intrusion-alerts`, first and latest alert; a later read never moves a date back), so the
  window never depends on how long alerts are kept. Never a public list (never asked for by ID); left out of the AI context.
  `TestWindow_AnAlertOnThisNetworkKeepsTheCVEForTwelveMonths`. An administrator
  may report CVEs of every age (`PUT /feeds/window`, core_setting `feeds.cve_window`, off by default, audited
  `feeds.report_window`): every CVE is then inside. The catalogue keeps the CVEs inside the window that NVD has not rejected, and the
  CVEs a finding pins (`Deps.Pins`): a pin keeps the CVE's data (its page, a finding's history, a report), never puts it inside the
  window. `Store.OutsideWindow` is the one reading of the window; the match set marks a catalogue CVE outside it and findings sets it
  aside (findings M-15). `Store.Kept` reads the same rule's kept set (`keptSQL`: an exploited-list entry, a qualifying exploited signal,
  an alert here, a public exploit dated inside the window) for given CVEs; findings keeps such a CVE out of its older-build group (P-10). Pulls store only CVEs this rule keeps, and ask by ID only for kept ones (`Window.publicListedSQL`). Switched
  on, the next catalogue pulls read NVD's whole set (`everyAgeOwed`, `feeds_nvd_cursor` row `walk_every_age`) and the CVE Program's
  whole list (`recordsEveryAge`, row `cve_record_every_age`) once more, never within 24 hours of the last read a switch started
  (`everyAgeCooldown`; a read for another reason never holds the first switch-on back); switched off, the pull job's prune drops the older CVEs at its next check.
  A change wakes findings' match pass (`feeds.ranges.updated`, `catalogue`). `TestWindow_OldCVEsStayOnlyWithEvidenceOfExploitation`,
  `TestWindow_SettingIsAdminsAuditedAndRematches`, `TestCataloguePull_EveryAgeReadsTheWholeSetOnce`.
- **INV-35** Affected ranges are kept per origin (`nvd`, `cna`, `adp`). When read for matching (`matchRows`, the exploited-list view
  `KevAffected`), NVD's rows lead and the CNA's rows of the CVE record are read beside them, as CVE JSON 5 states a version's status (the
  entry that names it, else the entry's `defaultStatus`, else unknown; cve-schema `versions.md`): a version either calls affected is
  affected. A CNA row whose product's list is complete (every row says what an unlisted version is) also decides "not affected"
  (`VendorList`); any other CNA row beside NVD's only says "affected" (`AffectedOnly`), and only for a version it states. An ADP row is
  read only when NVD gives none. `defaultStatus: unaffected` counts only from the vendor's own CNA (`ownCNA`: assigner and vendor name
  the same company, or the assigner is the name of a catalogue product only that vendor ships, `productVendors`, or the CVE Program's
  CNA list (INV-41) gives the assigner an organization whose name is the vendor's; an entry that names no vendor is no one's own). A
  CNA row stores the record's word (an ADP's and a no-vendor entry's `unaffected` is stored `unknown`), and every reader of stored ranges
  reads a third-party CNA's `unaffected` on a generic or model-limited row as `unknown` (`trustRow`: `readRanges`, `Catalogue`'s
  `RangesComplete`, `RecordStamps`; reader `ranges-15`). The
  rows an older reader stored carry no assigner: migration `0003_feeds_record_trust` stores their generic `unaffected` as `unknown`
  until the whole list is read again with reader `ranges-6`, so no stale third-party list decides "not affected" in between
  (`TestCVE5Status_StoredBeforeTheReRead`). An entry whose
  `defaultStatus` is affected states every version affected: the matcher reads its row from version 0 (`recordEvery`); a version word
  ("all") without it does not. `TestCVE5Status_DefaultStatusByAssigner`, `TestCVE5Status_EndToEnd` (cmd/vedette). The record's assigner is stored with
  the CVE (`feeds_cve.assigner`, at most 64 bytes, `clipAssigner`; reader `ranges-12`), and every row read for matching says whether it
  is the row's vendor (`Range.VendorCNA`, `ownCNA`; never for an ADP row): the matcher reads a list of exact releases as the vendor's
  enumeration only then. `TestRecordAssigner_RowsSayWhetherTheVendorAssigned`. A vendor row that
  no version scheme can order is shown, never matched. A record row that states no version is never read in a version scheme (it stays
  the generic comparison's); for a scheme whose vendor states its fixed releases in the description only (DSM: "before 7.2.1-69057-10,
  7.2.2-72806-7"), those releases are the record's rows (`describedRows`), each from the start of its line. A line the description
  says is not affected ("(7.2.1-69057 is not affected)") is an empty row ("7.2.1" before "7.2.1": not affected). A line older than
  every line the list names gets no row (a question, never a finding, never "not affected"): a fix the vendor ships on that line for
  another CVE does not say this one leaves it unaffected.
  NVD's rows of a product NVD writes in the vendor's notation (DSM) are read in the scheme too (`SchemeRangesOf`).
  Juniper's fixed release of each maintenance branch after lessThan ("22.3 before 22.3R2-S2, 22.3R3-S1") is one row per branch
  (`branchFixes`: 22.3 to 22.3R2-S2, 22.3R3 to 22.3R3-S1; a plain R fix starts its branch fixed and has none), so the Junos scheme reads
  the vendor's word; a list in another form stays as written and decides nothing. Two such rows of one train are not a conflict
  (`versionscheme.Conflicts`: they name stretches that do not overlap). `TestParseCVERecord_JuniperFixPerBranch`.
  A range inside one letter-release branch ("1.1.1" lessThan "1.1.1zk", OpenSSL's 1.x beside its numeric 3.x ranges) is left out
  alone, not the entry's product: the entry is then not complete (its rows' default is `unknown`), and the numeric ranges beside it
  are read. Only where the product's version scheme cannot read that range: a product whose scheme reads it keeps the rule before
  (its rows kept as the vendor states them, which the scheme reads). `TestParseCVERecord_Ranges`,
  `TestEntryRows_LetterBranchOnlyWhereTheSchemeCannotReadIt`.
  A version a CNA writes in a notation of its own inside the version fields is read into the bounds the fields would give
  (`recordNotation`): GitHub's advisory comparators in `version` ("= 8.9.6.1", "< 8.9.6.4", ">= 2.0, < 2.3.1"; `=`, `<`, `<=`,
  `>`, `>=`, two clauses joined by a comma are both required, at most one lower and one upper bound); the entry's product name in
  front of a version ("openssl-1.1.0", "iOS 12.3", an npm package "@scope/product"), never another name and never before a range
  written with a hyphen in a bound ("lessThan": "Tika 1.0-1.23"); a range written with a hyphen in `version` (`hyphenRead`, after the
  product's name too) from the first release through the second, as CISA's ADP and NVD read it ("1.0-1.23", "14.1.0-14.1.0.5",
  "1.0.0-6.6.1", "1.1.0-1.1.0g"; "6.2.0-6.2.0" is that release), while a release with a package revision or build after the hyphen
  stays one release ("0.6.9-5", "8.0.0-8", "9.3.1-2.1", "3.1.1-190328", versionType rpm or deb, a release the product's version
  scheme reads: NetScaler's "14.1-73.37", a package's file name "dovecot22-2.2.13-3.7.1", `packageFile`) and a string that can be either ("0.154-3.1", "20-30.05.24", "v9.20-v9.26") keeps the product unusable,
  never read narrower than the record means (`TestParseCVERecord_HyphenRange`, `TestEntryRows_HyphenReleaseOfAScheme`); a list after lessThan
  (lessThanOrEqual) with one release per release train, trains strictly up as written ("1.20.4,2.0.2") or strictly down in a
  list of three or more ("1.46.0, 1.45.4, 1.43.9"): one row per train, each later one
  from the train after the one before it, so an unlisted train between two listed ones stays affected; an item that is its train's
  first release ("1.46.0" after "1.45.4") gives no row after lessThan and that one release after lessThanOrEqual. A list whose items
  are not plain dotted numbers of one length on trains in that order ("10.0.111, 10.0.400": .NET writes the SDK's numbers on the
  runtime; two items newest first, "3.11.4, 3.2.0", can be two products' releases; "2.4.9, 2.4.8-p5") and any other text keeps the product unusable, as before. `TestParseCVERecord_RecordNotation`.
  An entry limited to operating systems (platforms "Windows", "macOS", "Linux", "Android", "iOS", beside processor words or not) of a
  product without a version scheme gives each row once per system, the system in `platforms` (`recordSystems`); the match reads it as
  the CPE's target_sw (`kevRecordRow`, `Range.MatchRow`), so the row speaks for that system only. NVD's running-on platforms are not
  read so: they reach the matcher with their NVD row (`AffectedRow.Platforms`, `KevAffected`, `Range.MatchRow`) as the environment
  the row's product runs on, never as an affected product (findings P-2). `TestKevAffected_CarriesNVDsRunningOnSystems`. An entry naming any other platform (a model) still leaves its product's generic rows out. `TestRecordSystems_EntryLimitedToSystems`.
  When the reader cannot keep an entry of a product (it gives no generic row: an "unspecified", "n/a" or unknown-status version and no
  defaultStatus, or the product's entries do not read; or an affected version of it names no version beside its ranges), every
  generic row of that product in the record, named by its CPE or by its own words (`lostKey`), is stored with version_type
  `record-lost` (`markLost`, `Range.Lost`, reader `ranges-14`): read for matching it only ever says "affected" (`AffectedOnly`, never
  `VendorList`, `AffectedRow.Lost`), its list is never complete (`Range.StatesUnlisted`), and the matcher proves nothing "not
  affected" while such a row names the line (findings `lostRow`). An entry whose product the reader cannot tell (no vendor or product
  it can read, a CPE list naming two products) or a container with more entries than it keeps marks every row of the record so. A
  version of status unknown makes its entry not complete. A third party's row that calls every version on one system affected
  (defaultStatus affected) does not make the list complete: it says nothing of another system (`StatesUnlisted`, also read by the
  wiring's catalogue entries). `TestRecordSystems_ADroppedEntryMakesTheProductAffectedOnly`,
  `TestRecordSystems_WhatAListStatesOfTheVersionsItDoesNotName`.
  An entry whose only unaffected statements are single versions above the end of every affected row it lists ("0 through 6.49.18",
  "7.0.0 through 7.11.2", "7.24.0 unaffected"; a fixed release per train, "7.21.5" and "7.23.1" above 7.20.8) keeps the highest of them,
  when it is on the release line (first number) the highest row ends on, as `fixed` of that row (`highestAbove`, `lineFixOf`, OSV's
  fixed): the match reads it as the fix of that line (`LineFix`, findings `pastRecordFix`): a release past every fix the entry states.
  Any other unaffected version stays as before. `TestParseCVERecord_Ranges`, `TestRecordRanges_LineFixReachesTheMatcher`,
  `TestRecordRanges_SeveralFixedReleasesGiveTheLineFix`.
  For a product with a version scheme, a record also keeps two kinds of rows that can only support "not affected", never "affected",
  and that no reader of affected ranges reads (`RangeScheme` refuses them; `StatementScheme` reads them): a range the vendor states
  unaffected ("0 before 24.4R1": version_type `vendor:unaffected`, `unaffectedRows`; a start written as words that name no release,
  "all version prior to" lessThan "23.4R1", is no start, as "0": `TestUnaffectedRows_ProseStartIsTheFirstRelease`), which holds for every device: kept only beside
  the product's affected rows, never when an entry of the product is kept in no form, and from an entry limited to some models only
  when every entry of the product names the same models (`TestParseCVERecord_UnaffectedOnlyBesideEveryEntry`); and the rows of
  an entry limited to some models (Juniper's "EX4000-48T", "EX Series"), stored with the models in `platforms` (`Range.ModelLimited`;
  at most 64 names of 100 bytes, else the entry is kept in no form). Such a row's `defaultStatus: unaffected` counts only from
  the vendor's own CNA (`ownCNA`); a third party lists the hardware it tested, so its rows are read `unknown` (`trustRow`): only the vendor's word says
  the product is affected on the named hardware alone (findings `otherHardware`). The brief does not list unaffected rows as affected versions.
  `TestParseCVERecord_VendorUnaffectedAndModelRows`, `TestStoreCVERecord_ModelsKept`, `TestParseCVERecord_ModelRowsKeepTheDefaultOnlyFromTheVendor`.
  A record's open-ended row ("from 1.25.0, every later version") of a product whose bounded rows above its start name fixed
  releases is read as ending where the lowest of those rows starts (`CutCatchAll`, when the match set and the exploited-list view
  read the rows; the stored rows are as the record states them): the vendor's evaluated trains keep their own fixes, versions below
  them stay affected with no fix named, and the cut row's default status is unknown (a version above the cut that no row
  names is a question, never proved unaffected). F5's NGINX records list each train with its fix next to such a row for the trains it no
  longer evaluates; read literally, no release would ever fix the flaw. `TestCount_RecordFixesCalledAffectedByACatchAllRow`.
  VMware's records that state ESXi's versions in words ("8.0 prior to ESXi80a-20842819", "7.0 before ESXi70U1c-17325551") give one
  row per clause from the line's start to the fixed build (`esxiTextRows`, version_type `vendor:record-text`); a line any clause states
  in another form (a patch bulletin with no build, "fix pending") gets no such row, and words inside ESXi's list that are no clause
  give none at all. When read (`SchemeRangesOf`), an update of the line that began after every stated fix (its first build in
  `esxi-builds.json` later than each fix, its update number higher) gets the row "line before its first release": not affected. A
  line on which a generic row (NVD's, CISA's) states a release affected that these rows call not affected, or states one that cannot
  be placed, keeps none of them: the affected side wins. NVD's exact `esxi:8.0:-` (GA) entry alone never says a later update is not
  affected.
- **INV-37** Every CVE the catalogue keeps for a reason every box shares (a public list or signal names it, or it was published within
  365 days) gets its CVE record once the whole list is read, also when it entered the catalogue after the files that would have brought
  it: the records still missing are asked by ID, the exploited lists' first and then the newest, within 460 asks by ID a pull in all
  (one hourly pull of a box whose indexes named about 29,000 older CVEs after its first read reads about 450 of them). A record the
  source does not have is remembered and not asked again at the next pulls. A CVE only a custom list, a box-built signal or a finding
  keeps is never asked by ID. When a CVE only a custom list or a box-built signal keeps has no record (and none is published inside the
  window), the whole list is read again early instead (`recordsOwn`): only once the last whole-list read is finished and its archive is
  older than the one it would read, at most once per 24 hours (the start time is kept in `feeds_nvd_cursor`, row `cve_record_own`, so a
  restart does not reset it), through the same download, rate and fetch log as any whole-list read; that read stamps the CVEs the list
  does not hold, so they start no second one.
- **INV-40** Vendor statements per release line come from line sources declared in `content/catalog/line-sources.json` (the feed, its
  catalogue products, what a listed row states (`semver_range`, `last_affected`) and what a line it does not list means:
  `unaffected_if_supported`, `unaffected_if_assessed` or `unknown`; the builds whose releases it numbers; how a CSAF document names the
  product), never from per-product code. The Node.js security working group's index (`nodejs-security-wg`) is read into `feeds_line_cve` (the source
  speaks about the CVE for the product, with the day of its statement and the advisory link) and `feeds_line_status` (one row per
  release line its vulnerable range names: from the start it gives, up to the release its patched range gives for that line; limited to
  the platforms the entry names). An entry whose ranges do not read, name one line twice or disagree is dropped whole and counted, never
  stored in part; a CVE several entries list is read from all of them, and dropped whole when one of them is not read or two state
  one line differently. Only catalogue CVEs are kept (INV-34; the catalogue's pruning drops the rest), and a statement that did not change keeps
  its day, so an unchanged index changes nothing for findings. endoflife.date (`endoflife-date`) fills `feeds_line_support` (release day,
  end of security support, latest release) of the products the file names, and is never a CVE verdict. `LineData` gives findings the
  rows, covers and support of the sources that are on; a cover is `Stale` when its source is more than a day past its interval.
  Oracle's CSAF feed (`oracle-cpu-csaf`, every 6 hours) is its RSS and each document it lists, asked of the feed's own host with the
  validators the document last gave (a 304 is not read again while the box runs): of the catalogue's products (a CPE line-sources.json
  names, else the product tree branch it names; another edition such as the Performance Pack is not the product) one row per release
  line with the newest affected release, read through the product's `version_map` (`8u491` = `1.8.0_491`, a patch build kept: `8u511b33` = `1.8.0_511-b33`); a line the document assessed
  (has a release of) and does not list is a convention row (`explicit` 0, `unaffected`), a line whose every release it lists not affected
  an explicit `unaffected` row. A statement is dated by its document's first release. A CVE that names a release Vedette cannot read, a
  status it does not read, or a release not affected at or below an affected one on the same line (in one document or across several) is
  dropped whole; several documents on a CVE are combined (the newest affected release of a line wins). When a document of the feed
  cannot be read, no convention row is written until it can. A CVE whose Java SE description names only components only Oracle's own
  build ships (line-sources.json `own_components`: installer, Java plugin, JavaFX in Java 8) is stated for those builds only
  (`feeds_line_cve.only_builds`, `LineCover.OnlyBuilds`); one of any other component, or none named, for every build.
  `TestParseNodeLines_Count`, `TestParseNodeLines_FailsClosed`, `TestParseEOL_Count`, `TestLineSourcesPull`, `TestOracleLines_Count`,
  `TestOracleLines_FailsClosed`, `TestOracleLinesPull`, `TestOracleLines_OwnBuildParts`.
- **INV-28** A CVSS score is stored per assessor and version and chosen only by `PickCVSS`, banded only by `Severity`.
- **BRIEF-1** `Store.Brief` is the one read model of a CVE (the CVE page, the finding page, the AI context, MCP). Its product name is
  the exploited list's, else the catalogue product most of its counted rows and the rows a product's version scheme reads from the
  same assessor name (`catalogueProduct`), else the first range product. A workaround text that only says none exists ("None", "No
  workarounds known.") is no workaround (`statedWorkaround`).
- **INV-36** An exploited-list entry is written with its `exploited` signal in the same transaction. The first pull of the CISA or
  VulnCheck list into an empty table emits one `feeds.sync.baseline`, not one `feeds.vuln.new_kev` per CVE. A custom feed emits no
  KEV events.

**Indicators**
- **INV-12** An indicator's verdict, score and category are computed on read from `feeds_ioc_source` by `Judge`: `block` for two
  independent sources or one block-class source (a CC0 list, or Spamhaus DROP: `Source.DropClass`), `alert` below that. An IP a
  list names is never widened to a network. Only a list that publishes networks (Spamhaus DROP) lists one: a network is stored as an
  indicator of type `ip` whose value is the canonical network (`192.0.2.0/24`), and `IOCLookup` of an address also reads every
  stored network that holds it (`networksAround`: the address's networks of IPv4 /8 to /31 or IPv6 /16 to /127, one indexed read),
  one sighting per feed. Private, reserved, documentation and local names or addresses
  never become indicators. An indicator no feed lists for 30 days is deleted.
- **INV-12b** An indicator's confidence (the search `score`, logs' hit `confidence`) is computed on read by `IOCConfidence` over
  the switched-on feeds that list it. A built-in indicator list carries no confidence per line, so `IOCLookup` rates its listing
  by what the list is (`Source.Weight`), whatever `feeds_ioc_source.confidence` holds: abuse.ch Feodo Tracker 0.95 (confirmed
  botnet command-and-control servers, `Source.C2`), Spamhaus DROP 0.9 (hijacked or criminal-controlled networks), ET Open
  compromised IPs 0.85, IPsum by the level its address names (`levels/N.txt`: 0.9 from level 3, the default, and for an address
  that names none; level 1 0.4, level 2 0.64), hagezi TIF 0.45 (a pooled domain list with known false positives that matches every
  subdomain: medium alone, high only with an independent feed beside it), the Tor exit list 0.2 (it says what an address is, not
  that it is bad). A custom feed's listing weighs what the feed said, or 0.5.
  Independent feeds add up (1 − ∏(1 − weight)) under `Judge`'s independence rules (an aggregate with one of its upstreams adds
  nothing, and the result is never below that aggregate's own weight; all aggregates count once); the Tor exit list counts only
  when nothing else lists the address, and aggregates that list a Tor exit relay count half. Two decimals. No stored row is
  rewritten: a listing stored before is rated the same way on its next lookup. Tests:
  `TestIOCConfidenceRatesEachFeedAndRisesWithIndependentFeeds`, `TestIOCConfidenceOfIPsumFollowsTheLevelOfItsAddress`,
  `TestIOCConfidenceOfHageziTIFAloneStaysBelowHigh`, `TestIOCEveryBuiltinListIsRated`, `TestSpamhausDROPAndAnAddressListAddUp`.
- **INV-12c** A listing by a list whose terms ask for credit with a time (`Source.CreditFetch`: Spamhaus DROP) is named, wherever it
  is shown (logs' hit and incident, Feeds → Look up, the AI), by `CreditName`: "Spamhaus DROP (list fetched 26 Nov 2026, 14:00 +07)", written by `orgtime.StampZone` in the organization's zone with the zone named,
  the time of the feed's last good pull (`feeds_source.last_success`, `IOCSighting.FetchedAt`). The credit is never stored: logs
  stores the plain name on a hit and shows the credit from `IOCCredits` when it reads or announces the hit, so one feed is one name
  across the days of a row. Every other listing is named by its feed's name.

**Other modules**
- **INV-10** Feeds works without inventory: `you_have` is `null`, `matched_assets` empty, nothing fails.
- **INV-11** `you_have` is `yes` for a device with a firm product match, `maybe` for a vendor-only match of a "multiple products"
  entry, else `no`. On the CVE page, a device the findings platform rule proves unaffected is counted in `not_affected`.
- **INV-14** "I have this" (`answer=have`) creates exactly one manually declared device through `feeds.Inventory.AddManualDevice`,
  inside feeds' own transaction; findings matches that product on that device from `have_since` (`Store.HaveSince`).
- **INV-33** On a device merge or delete (`core/lifecycle`), a "have" answer moves to the device that stays, or keeps no device.

## Preconditions and postconditions

- **PRE-1 / POST-1** `Fetch` needs the feed on and its URL valid; it updates the feed's last fetch, count, status and note. Feeds
  whose count is not self-describing show what they hold, counted from the stored data when read (`heldNotes`).
- **PRE-2 / POST-2** `GET /feeds/hot`: `window` is `24h` or `7d`; rows with `you_have=yes` first, then by CVE count, then EPSS.
- **PRE-3 / POST-3** `GET /feeds/cve/{id}`: 404 `not_in_data` unless the catalogue holds the CVE; returns the brief plus the
  matched devices (`null` when inventory is off or the CVE is on no exploited list).
- **PRE-4 / POST-4** `GET /feeds/search`: `q` 1–200 characters; answered from the local database only. An indicator counts as
  listed only by a feed that is on; the AI and MCP `lookup_ioc` follow the same rule.
- **PRE-5 / POST-5** Saving a custom feed checks name, URL, `blocked_host`, schedule, format, authentication, parser and
  `duplicate_url`, in that order, and writes `core_audit` without the secret.

## Forbidden

- **FORBID-1** Distributing feed data through a central server or the project's repository.
- **FORBID-2** Sending customer data (devices, logs) to a feed source.
- **FORBID-3** Pulling an undeclared source or one that is off.
- **FORBID-4** Reading or writing `inv_*` tables; matching goes through `feeds.Inventory`.

## Events

| Event | When | Subscribers |
|---|---|---|
| `feeds.vuln.new_kev` | a CVE newly on the CISA or VulnCheck list (not on the baseline pull) | inventory (re-match the CVE), scan (re-scan when a template exists) |
| `feeds.vuln.updated` | listed CVEs whose entry changed | inventory (re-match) |
| `feeds.ranges.updated` | affected versions, distribution fixes or Windows releases changed | inventory (findings match pass for the CVEs named; every device on the first fill) |
| `feeds.sync.baseline` | the first fill of an exploited list | inventory (re-match every device as a baseline, so notify does not alert per CVE) |

Feeds listens to inventory's device discovered/updated events only to wake the Alpine feed for the first Alpine device.

## Dependencies

- **Depends on**: `core` (jobs, schedules, secrets, audit, lifecycle). Optional: `inventory` through `feeds.Inventory` (product
  matching, "I have this", the distributions and packages in use).
- **Used by** (adapters in `cmd/vedette`): inventory and findings (`wiring.go`: exploited entries, ranges, distribution fixes, CVSS,
  published dates, `HaveSince`, `Catalogue`, `MatchStamp`), the finding page (`findingcase.go`), urgency and notices (`urgency.go`,
  `notifyfindings.go`: `UrgencyReader`), logs (`logsioc.go`: indicator lookups), ai and mcp-server (`Brief`, indicator lookups, the
  hot table), reports (`reports.go`: `KevVulns`, feed staleness), `core/winrel` (Windows releases), `scripts/release` (signal seed).

## When off

No `/feeds/*` routes and no pulls; data is kept. Matching gets no new knowledge; logs gets no new indicators.
