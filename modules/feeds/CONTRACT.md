# Feeds contract

> Tier: standard · Stories: S-FEED-1…5 · Tables: `feeds_*` ([`docs/DATA_MODEL.md`](../../docs/DATA_MODEL.md) 4.1)

Feeds pulls vulnerability knowledge and indicator lists straight from their publishers, parses them on the box, and keeps one
vulnerability catalogue plus the signals that make a CVE urgent. Other modules read it through Go functions, never through its
tables.

## Endpoints

| Route | Minimum role |
|---|---|
| `GET /feeds/status`, `/feeds/hot`, `/feeds/weekly`, `/feeds/cve/{id}`, `/feeds/cve/{id}/tier`, `/feeds/search`, `/feeds/sources` | viewer |
| `POST /feeds/weekly/{id}` | operator |
| `PUT /feeds/sources/{id}`, `POST /feeds/sources/{id}/fetch`, `POST /feeds/custom`, `PUT`/`DELETE /feeds/custom/{id}`, `POST /feeds/parse-test` | admin |

Request and response shapes: `web/src/features/feeds/contract.ts` (the source of `api/openapi.json`).

## Invariants

IDs are stable (code comments cite them); a retired ID is not reused.

**Outbound traffic**
- **INV-1** The box pulls only declared sources that are on: the built-in list (`sources.go`) and custom feeds. A pull is a GET to
  exactly the feed's URL and sends no customer data. Feed data never comes through the project's own repository or a central
  server. `TestContract_INV1_OnlyDeclaredSources`.
- **INV-2** A feed URL is `https`; `http` only to an internal host. Limits of a pull: 5,000,000 bytes, 50,000 rows (a built-in
  source may set its own row cap), 60 seconds; redirects only to the same host, at most 5.
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
  fix yet" (`open`), and findings reads all three (`DistroFixes`, `DistroFixesFor`): findings judges a package the distribution built by
  that word alone while the distribution's feed of fixed and affected rows (debian-tracker, ubuntu-osv; never ubuntu-vex, which holds only "not affected") is on (`DistroOn`: on and loaded, or loading). Open rows of other CVEs are kept only
  for the plan (tier CVEs of the packages devices run). Debian's open entries it will not fix in a security update (no DSA, postponed,
  ignored, unimportant, end-of-life) are kept for the CISA list's CVEs with that reason (`feeds_distro_fix.reason`, `DistroReasons`).
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
- **INV-34** A CVE stays in the catalogue while it was published within 365 days (and NVD has not rejected it), or has an
  exploited-list entry, or a qualifying signal, or an open finding pins it (`Deps.Pins`). Pulls store only CVEs this rule keeps.
- **INV-35** Affected ranges are kept per origin (`nvd`, `cna`, `adp`). When read for matching (`matchRows`, the exploited-list view
  `KevAffected`), NVD's rows lead and the CNA's rows of the CVE record are read beside them, as CVE JSON 5 states a version's status (the
  entry that names it, else the entry's `defaultStatus`, else unknown; cve-schema `versions.md`): a version either calls affected is
  affected. A CNA row whose product's list is complete (every row says what an unlisted version is) also decides "not affected"
  (`VendorList`); any other CNA row beside NVD's only says "affected" (`AffectedOnly`), and only for a version it states. An ADP row is
  read only when NVD gives none. `defaultStatus: unaffected` is kept only from the vendor's own CNA (`ownCNA`: assigner and vendor name
  the same company; an entry that names no vendor is no one's own); a third-party CNA's is stored `unknown` on the generic rows. The
  rows an older reader stored carry no assigner: migration `0003_feeds_record_trust` stores their generic `unaffected` as `unknown`
  until the whole list is read again with reader `ranges-6`, so no stale third-party list decides "not affected" in between
  (`TestCVE5Status_StoredBeforeTheReRead`). An entry whose
  `defaultStatus` is affected states every version affected: the matcher reads its row from version 0 (`recordEvery`); a version word
  ("all") without it does not. `TestCVE5Status_DefaultStatusByAssigner`, `TestCVE5Status_EndToEnd` (cmd/vedette). A vendor row that
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
  For a product with a version scheme, a record also keeps two kinds of rows that can only support "not affected", never "affected",
  and that no reader of affected ranges reads (`RangeScheme` refuses them; `StatementScheme` reads them): a range the vendor states
  unaffected ("0 before 24.4R1": version_type `vendor:unaffected`, `unaffectedRows`), which holds for every device: kept only beside
  the product's affected rows, never when an entry of the product is kept in no form, and from an entry limited to some models only
  when every entry of the product names the same models (`TestParseCVERecord_UnaffectedOnlyBesideEveryEntry`); and the rows of
  an entry limited to some models (Juniper's "EX4000-48T", "EX Series"), stored with the models in `platforms` (`Range.ModelLimited`;
  at most 64 names of 100 bytes, else the entry is kept in no form). The brief does not list unaffected rows as affected versions.
  `TestParseCVERecord_VendorUnaffectedAndModelRows`, `TestStoreCVERecord_ModelsKept`.
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
  catalogue products, what a listed row states and what a line it does not list means: `unaffected_if_supported` or `unknown`), never
  from per-product code. The Node.js security working group's index (`nodejs-security-wg`) is read into `feeds_line_cve` (the source
  speaks about the CVE for the product, with the day of its statement and the advisory link) and `feeds_line_status` (one row per
  release line its vulnerable range names: from the start it gives, up to the release its patched range gives for that line; limited to
  the platforms the entry names). An entry whose ranges do not read, name one line twice or disagree is dropped whole and counted, never
  stored in part; a CVE several entries list is read from all of them, and dropped whole when one of them is not read or two state
  one line differently. Only catalogue CVEs are kept (INV-34; the catalogue's pruning drops the rest), and a statement that did not change keeps
  its day, so an unchanged index changes nothing for findings. endoflife.date (`endoflife-date`) fills `feeds_line_support` (release day,
  end of security support, latest release) of the products the file names, and is never a CVE verdict. `LineData` gives findings the
  rows, covers and support of the sources that are on; a cover is `Stale` when its source is more than a day past its interval.
  `TestParseNodeLines_Count`, `TestParseNodeLines_FailsClosed`, `TestParseEOL_Count`, `TestLineSourcesPull`.
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
