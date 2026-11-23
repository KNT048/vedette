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
- **INV-22** After its first fill, a distribution feed is pulled only while a device runs that distribution (Alpine: only with an
  Alpine device at all).

**Parsing**
- **INV-3** The parser fails closed: an invalid row is dropped and counted by reason, never stored. Feed text is untrusted plain
  text; consumers escape it for their own output.
- **INV-7** `POST /feeds/parse-test` writes nothing and makes no network call: it parses the caller's sample or the built-in one.

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
- **INV-35** Affected ranges are kept per origin (`nvd`, `cna`, `adp`); NVD rows win over vendor rows when read. A vendor row that
  no version scheme can order is shown, never matched.
- **INV-28** A CVSS score is stored per assessor and version and chosen only by `PickCVSS`, banded only by `Severity`.
- **BRIEF-1** `Store.Brief` is the one read model of a CVE (the CVE page, the finding page, the AI context, MCP).
- **INV-36** An exploited-list entry is written with its `exploited` signal in the same transaction. The first pull of the CISA or
  VulnCheck list into an empty table emits one `feeds.sync.baseline`, not one `feeds.vuln.new_kev` per CVE. A custom feed emits no
  KEV events.

**Indicators**
- **INV-12** An indicator's verdict, score and category are computed on read from `feeds_ioc_source` by `Judge`: `block` for two
  independent sources or one block-class source, `alert` below that. An IP is never widened to a network. Private, reserved,
  documentation and local names or addresses never become indicators. An indicator no feed lists for 30 days is deleted.

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
| `feeds.ioc.updated`, `feeds.fetch.failed` | an indicator list changed; a pull failed | none today |

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
