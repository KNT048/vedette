// Hợp đồng API module feeds. Kiểu UI suy ra từ schema ở đây (types.ts), nên UI ↔ mock ↔ OpenAPI không lệch.
import { z } from 'zod'
import { defineEndpoints } from '@/lib/contract'

const cveId = z.string().regex(/^CVE-\d{4}-\d{4,}$/)
const isoDate = z.string().regex(/^\d{4}-\d{2}-\d{2}$/)

export const Vuln = z.object({
  cve: cveId,
  vendor: z.string(),
  product: z.string(),
  name: z.string(),
  description: z.string(),
  required_action: z.string(),
  links: z.array(z.string().regex(/^https?:\/\//)).describe('http(s) addresses only'),
  date_added: isoDate,
  due_date: isoDate.nullable(),
  ransomware: z.boolean(),
  epss: z.number().min(0).max(1).nullable(),
  epss_7d_ago: z.number().min(0).max(1).nullable(),
  has_template: z.boolean(),
  source: z.string().optional().describe('Which list the entry is on: "cisa-kev", "vulncheck-kev" (VulnCheck KEV) or the id of a custom feed; texts name it, an entry of VulnCheck is never called CISA\'s'),
})

export const YouHave = z.enum(['yes', 'maybe', 'no'])

export const HotRow = z.object({
  key: z.string(),
  vendor: z.string(),
  product: z.string(),
  display: z.string().describe('Name the user recognizes, in plain language'),
  cves: z.array(Vuln.pick({ cve: true, date_added: true, ransomware: true, epss: true, has_template: true })),
  max_epss: z.number().nullable(),
  max_epss_delta: z.number().nullable(),
  has_template: z.boolean(),
  ransomware: z.boolean(),
  you_have: YouHave.nullable().describe('null when the inventory module is off'),
  matched_assets: z.array(z.string()),
})

export const FeedStatus = z.object({
  generated_at: z.iso.datetime(),
  kev_catalog_version: z.string(),
  sources: z.array(z.object({ name: z.string(), url: z.url().describe('The address the data came from: for the CISA list, the copy the newest catalog came from'), license: z.string(), fetched_at: z.iso.datetime() })),
  inventory_on: z.boolean(),
  kev: z.object({
    state: z.enum(['loaded', 'never_loaded', 'off']).describe('The CISA list (cisa-kev) for the Home count: "off" when an admin turned it off, else "loaded" once a pull has ever succeeded (even if a later pull failed), else "never_loaded"'),
    error: z.string().nullable().describe('One line, cleaned: why the last pull failed (also when an earlier pull had loaded the list); null when the last pull worked, has not been tried, or the list is off'),
    interval_hours: z.number().int().describe('How often the box pulls the CISA list (Home says "checked every hour")'),
    checked_at: z.iso.datetime().nullable().describe('When the box last asked for the CISA list, whether the pull worked or not; null before the first pull'),
    last_success: z.iso.datetime().nullable().describe('When a pull of the CISA list last worked; null when none ever did'),
    answered_by: z.string().nullable().describe('Newest from: the copy the catalog on the box came from, "CISA" (cisa.gov) or "CISA GitHub mirror" (both are asked every check and the newer catalog is kept); null before the first good pull'),
    copies: z.array(z.object({
      name: z.enum(['CISA', 'CISA GitHub mirror']),
      url: z.url(),
      checked_at: z.iso.datetime().describe('When the box last asked this copy'),
      error: z.string().nullable().describe('Why the last ask failed, one clause naming the copy ("cisa.gov refused this box (HTTP 403)"); null when it answered'),
      catalog_version: z.string().nullable().describe('The catalogVersion this copy last gave; null when not known yet'),
    })).describe('What each copy of the CISA list said at its last check; empty for a list at an admin\'s own address or before the first check'),
  }),
})

export const WeeklyItem = z.object({ id: z.string(), key: z.string(), text: z.string(), date_added: isoDate, cve: cveId, answer: z.enum(['have', 'not_relevant']).nullable() })
export const MatchedAsset = z.object({ id: z.string(), hostname: z.string().nullable().describe('The device\'s name: the name a person gave it in Vedette, else its host name; null when neither'), ip: z.string(), display: z.string(), how: YouHave })
// ---- One CVE: the brief (feeds.Brief), the one read model of a CVE that the CVE page, the finding's summary card, the AI context,
// notices and reports read. Every value comes from the catalogue on the box; nothing here is worked out in the browser.
const day = isoDate
const level = z.enum(['none', 'low', 'high'])
export const CveImpact = z.object({ confidentiality: level, integrity: level, availability: level })
export const CvssReading = CveImpact.extend({
  attack_vector: z.enum(['network', 'adjacent', 'local', 'physical']),
  attack_complexity: z.enum(['low', 'medium', 'high']).describe('medium only for CVSS 2.0'),
  attack_requirements: z.enum(['none', 'present']).nullable().describe('CVSS 4.0 only'),
  privileges_required: z.enum(['none', 'low', 'high']).describe('For CVSS 2.0, its Authentication read the same way (none, single = low, multiple = high)'),
  user_interaction: z.enum(['none', 'required', 'passive', 'active']).nullable().describe('null for CVSS 2.0, which has no such metric'),
  scope: z.enum(['unchanged', 'changed']).nullable().describe('CVSS 3.x only'),
  subsequent: CveImpact.nullable().describe('CVSS 4.0 only: the impact on systems beyond the vulnerable one'),
  summary: z.string().describe('The reading in one sentence, for example "Attacker needs local access, low complexity, high privileges needed, no user action; high impact on confidentiality, integrity and availability; can reach beyond the vulnerable component."'),
}).describe('The CVSS vector read into words (confidentiality, integrity, availability: the impact on the vulnerable system; CVSS 2.0 partial = low, complete = high)')
export const CveScore = z.object({
  source: z.enum(['nvd', 'cna', 'adp']).describe('Who scored it: NVD, the CVE Numbering Authority (most often the vendor), or CISA (ADP)'),
  version: z.enum(['4.0', '3.1', '3.0', '2.0']),
  score: z.number().min(0).max(10),
  vector: z.string(),
})
export const CveListEntry = z.object({
  list: z.string().describe('"cisa", "vulncheck", or "custom:" followed by the id of a custom feed'),
  source: z.string().describe('The feed that holds the entry: "cisa-kev", "vulncheck-kev" or a custom feed id'),
  source_name: z.string().describe('That feed\'s name, as Settings -> Feeds shows it'),
  vendor: z.string(), product: z.string(), display: z.string(), name: z.string(),
  description: z.string().describe('The list\'s own words'),
  required_action: z.string(),
  links: z.array(z.string().regex(/^https?:\/\//)).describe('http(s) addresses only'),
  date_added: day, due_date: day.nullable(), ransomware: z.boolean(),
})
export const CveSignal = z.object({
  kind: z.string().describe('Why the CVE is urgent: "exploited" (an exploited list or a vendor says so), "public_exploit" (a public exploit or a scan template exists), and kinds new sources add'),
  source: z.string().describe('The feed that saw it ("cisa-kev", "metasploit", "nuclei-templates" …)'),
  source_name: z.string().describe('That feed\'s name'),
  first_seen: z.iso.datetime().describe('When the source says it (its publication date), else when this box first saw it'),
  last_seen: z.iso.datetime(),
  qualifies: z.boolean().describe('Passes the quality rule of its kind; a signal that does not is kept for its date only'),
  url: z.string().regex(/^https?:\/\//).nullable(),
  detail: z.record(z.string(), z.union([z.string(), z.number(), z.boolean()])).nullable().describe('Small facts for display ({"stars": 244, "authors": 3})'),
})
export const CveRange = z.object({
  origin: z.enum(['nvd', 'cna', 'adp']).describe('Who stated it: NVD, the CVE record\'s CNA (most often the vendor), or an ADP of the record'),
  counts: z.boolean().describe('The row the matcher reads: NVD\'s rows when NVD gives any, else the CVE record\'s'),
  part: z.string().describe('CPE part: a, o, h; "" for a CVE record row without a CPE'),
  vendor: z.string(), product: z.string(),
  cpe: z.string().describe('The CPE match criteria when the origin gave one, else ""'),
  start_including: z.string(), start_excluding: z.string(), end_including: z.string(), end_excluding: z.string(),
  fixed: z.string().describe('The release that fixes the range when the origin states one, else ""'),
  version_type: z.string().describe('The CVE record\'s versionType ("semver", "custom" …), else ""; "vendor:" and that word for a row kept in the vendor\'s own notation, which only the product\'s version scheme reads (it never counts)'),
  default_status: z.enum(['', 'affected', 'unaffected', 'unknown']).describe('A CVE record row\'s defaultStatus; "" for NVD\'s rows'),
  platforms: z.array(z.string()).describe('NVD\'s "running on" operating systems ("microsoft:windows")'),
  versions: z.string().describe('The versions in words: "from 2.0 before 2.4.58", "up to 3.1", "7.0 update_1", "every version"; in the version scheme\'s words when the product has one: "from 8.0 before 8.0 U3d (build 24585383)"'),
  train: z.string().describe('The release train the row\'s end belongs to, as the product\'s version scheme reads it ("8.0 U3"); "" when no scheme reads the row'),
  fixed_release: z.string().describe('The fixed release, as the product\'s version scheme reads it ("8.0 U3d (build 24585383)"); "" when none or no scheme reads the row'),
})
export const CveFix = z.object({
  vendor: z.string(), product: z.string(),
  origin: z.enum(['nvd', 'cna', 'adp']).describe('Who stated it'),
  train: z.string().describe('The release train ("8.0 U3")'),
  release: z.string().describe('Its fixed release ("8.0 U3d (build 24585383)")'),
})
export const CveRefGroup = z.enum(['vendor-advisory', 'patch', 'mitigation', 'release-notes', 'exploit', 'government-resource', 'third-party-advisory',
  'technical-description', 'issue-tracking', 'mailing-list', 'vdb-entry', 'media-coverage', 'other'])
export const CveReference = z.object({
  url: z.string().regex(/^https?:\/\//),
  tags: z.array(z.string()).describe('The CVE record\'s tag words (NVD\'s are read into them: "Vendor Advisory" is vendor-advisory)'),
  source: z.enum(['nvd', 'cna', 'adp']).describe('Who listed it: NVD, which tags every reference once it analyses the CVE, else the CVE record'),
  group: CveRefGroup.describe('The one group it is shown under: the first of the groups, in this order, that one of its tags names'),
})
export const CveBrief = z.object({
  cve: cveId,
  title: z.string().nullable().describe('The CNA\'s title'),
  description: z.string().describe('NVD\'s English description, else the CNA\'s'),
  display: z.string().nullable().describe('The product in plain words: the exploited-list entry\'s, else the first of products'),
  products: z.array(z.string()).max(20).describe('Vendor and product of the ranges that count ("vmware esxi"), sorted'),
  published: day.nullable(), modified: day.nullable(),
  nvd_status: z.string().nullable().describe('NVD\'s vulnStatus ("Analyzed", "Deferred" …); null until NVD answered'),
  nvd_checked_at: z.iso.datetime().nullable(), record_read_at: z.iso.datetime().nullable().describe('When the CVE record was last read'),
  cwe: z.array(z.object({ id: z.string().regex(/^CWE-\d+$/), name: z.string().nullable().describe('MITRE\'s name; null for an id the CWE List does not hold') })),
  cvss: CveScore.extend({
    severity: z.enum(['critical', 'high', 'medium', 'low', 'none']),
    reading: CvssReading.nullable(),
  }).nullable().describe('The one picked score: the newest CVSS version, NVD before the CNA before CISA; null when the CVE has no score'),
  scores: z.array(CveScore).describe('Every stored score, in the order the pick prefers them'),
  lists: z.array(CveListEntry).describe('Its exploited-list entries, the one pages name first (CISA, VulnCheck, then custom lists)'),
  signals: z.array(CveSignal).describe('Every signal, oldest first'),
  ranges: z.array(CveRange).describe('Every affected-versions row, the ones that count first'),
  fixes: z.array(CveFix).describe('The fixed release of each product\'s release train, as its version scheme reads the ranges: the vendor\'s first, one per product and train; empty for a product without a scheme'),
  ranges_from: z.enum(['nvd', 'cna', 'adp']).nullable().describe('The origin of the rows that count; null when there are none'),
  ranges_complete: z.boolean().describe('CVE record rows only: every product\'s list says what an unlisted version is'),
  references: z.array(CveReference).describe('Grouped: ordered by group, then by address'),
  solution: z.string().nullable().describe('The CNA\'s solution text; null when the record has none'),
  workaround: z.string().nullable().describe('The CNA\'s workaround text; null when the record has none'),
  ssvc: z.object({ exploitation: z.string().nullable(), automatable: z.string().nullable(), technical_impact: z.string().nullable() }).describe('CISA\'s SSVC decision points (Vulnrichment)'),
  epss: z.object({
    score: z.number().min(0).max(1), percentile: z.number().min(0).max(1), day: day.nullable(),
    week_ago: z.number().min(0).max(1).nullable(),
    history: z.array(z.object({ day, score: z.number().min(0).max(1) })).describe('The days the box kept (CVEs on a list or with a signal), oldest first'),
  }).nullable(),
  nvd_url: z.string().regex(/^https:\/\//), record_url: z.string().regex(/^https:\/\//),
})
export const CveDetail = CveBrief.extend({
  matched: z.array(MatchedAsset).nullable().describe('Devices whose product matches the exploited-list entry; null when the inventory is off or the CVE is on no exploited list'),
  not_affected: z.number().int().min(0).describe('devices that run the product but that the platform rules of the findings prove are not affected; left out of matched'),
})
// S-TIER-1: a CVE that is on no exploited list, from the tier data (feeds epss-all and nvd-recent).
export const TierCve = z.object({
  cve: cveId,
  tier: z.enum(['likely', 'recent']).nullable().describe('likely = EPSS 10 % or more and published in the last 12 months; recent = published in the last 12 months; null = older, or no published date in the data (only a scan engine that finds it lists it)'),
  published: isoDate.nullable().describe('NVD `published`; null when nvd-recent does not hold it (older than 12 months, or the feed is off)'),
  last_modified: isoDate.nullable(),
  nvd_status: z.string().nullable().describe('NVD\'s vulnStatus ("Analyzed", "Awaiting Analysis", "Deferred"…)'),
  severity: z.enum(['critical', 'high', 'medium', 'low', 'none']).nullable().describe('NVD\'s CVSS severity'),
  score: z.number().min(0).max(10).nullable(),
  epss: z.number().min(0).max(1).nullable(),
  percentile: z.number().min(0).max(1).nullable(),
  epss_date: isoDate.nullable().describe('The day of the EPSS score'),
  products: z.array(z.string()).max(10).describe('Vendor and product of NVD\'s affected entries, at most 10'),
  ranges: z.boolean().describe('NVD gives affected versions, so a device\'s exact version can be compared'),
})
export const IocHit = z.object({
  value: z.string(), type: z.enum(['ip', 'domain']), category: z.string(), sources: z.array(z.string()), score: z.number().min(0).max(1),
  first_seen: isoDate, last_seen: isoDate, verdict: z.enum(['block', 'alert']),
})
export const SearchResult = z.discriminatedUnion('kind', [
  z.object({ kind: z.literal('cve'), cve: cveId, found: z.boolean() }),
  z.object({ kind: z.literal('ioc'), value: z.string(), type: z.enum(['ip', 'domain']), hit: IocHit.nullable() }),
  z.object({ kind: z.literal('text'), q: z.string(), vulns: z.array(Vuln.extend({ display: z.string() })) }),
])
export const HotResponse = z.object({ window: z.enum(['24h', '7d']), rows: z.array(HotRow), latest: z.object({ cve: cveId, date_added: isoDate, display: z.string() }).nullable() })
export const WeeklyResponse = z.object({ items: z.array(WeeklyItem) })

// ---------- Feed sources and custom parsing (S-FEED-4, S-FEED-5)
export const FeedKind = z.enum(['vulnerabilities', 'ioc'])
export const FeedFormat = z.enum(['json', 'csv', 'rss', 'stix', 'lines'])
export const DateFormat = z.enum(['auto', 'dmy', 'mdy', 'epoch'])
export const FieldMap = z.object({
  source: z.string().max(200).describe('JSONPath (json), column name or 1-based number (csv), item field (rss); empty = not mapped'),
  regex: z.string().max(200).describe('Optional regex; the first capture group (or the whole match) is kept'),
  trim: z.boolean(),
  lowercase: z.boolean(),
  date_format: DateFormat.describe('Only used by date fields'),
})
export const Parser = z.object({
  format: FeedFormat,
  records_path: z.string().max(200).describe('JSON only: JSONPath of the records, for example $.vulnerabilities[*]'),
  delimiter: z.string().max(1).describe('CSV only'),
  has_header: z.boolean().describe('CSV only'),
  fields: z.record(z.string(), FieldMap),
})
export const FeedAuthType = z.enum(['none', 'header', 'bearer', 'basic'])
export const FeedAuth = z.object({
  type: FeedAuthType,
  header_name: z.string().nullable(),
  username: z.string().nullable(),
  secret_last4: z.string().nullable().describe('Last 4 characters of the saved secret; the secret is never returned'),
})
export const Feed = z.object({
  id: z.string(),
  builtin: z.boolean(),
  name: z.string(),
  kind: FeedKind,
  format: FeedFormat,
  url: z.string(),
  default_url: z.string().nullable().describe('Built-in feeds only; used by "Reset to default"'),
  enabled: z.boolean(),
  interval_hours: z.number().int().min(1).max(168).describe('Read only: how often the feed\'s schedule pulls it, in whole hours (the schedule is feeds.source:<id>, changed with PUT /schedules/{owner_key})'),
  auth: FeedAuth,
  parser: Parser.nullable().describe('null for built-in feeds'),
  last_fetch: z.iso.datetime().nullable(),
  records: z.number().int().nullable(),
  status: z.enum(['ok', 'error', 'never']),
  error: z.string().nullable(),
  license: z.string().nullable(),
  answered_by: z.string().nullable().describe('The CISA list only: the copy the catalog on the box came from (newest from), "CISA" or "CISA GitHub mirror"; both copies are asked every check; null for every other feed and before the first good pull'),
})
export const FeedList = z.object({ items: z.array(Feed) })
export const FeedPatch = z.object({
  enabled: z.boolean().optional(),
  url: z.string().max(500).optional().describe('Built-in: a mirror address. Empty string resets it to the default'),
  api_key: z.string().max(500).optional().describe('VulnCheck KEV only, write-only: the customer\'s own API key (8 to 500 characters, no spaces). Saving it turns the feed on; an empty string removes the key, turns the feed off and deletes what it loaded'),
})
export const FeedInput = z.object({
  name: z.string().min(1).max(60),
  kind: FeedKind,
  url: z.string().max(500),
  enabled: z.boolean(),
  auth: z.object({ type: FeedAuthType, header_name: z.string().max(80).nullable(), username: z.string().max(80).nullable(), secret: z.string().max(500).optional().describe('Write-only; omit on edit to keep the saved secret') }),
  parser: Parser,
})
export const ParseTestInput = z.object({
  kind: FeedKind,
  parser: Parser,
  sample: z.string().max(5_000_000).optional().describe('Your own sample text; omit to use the built-in sample for this format'),
})
export const ParseRecord = z.record(z.string(), z.union([z.string(), z.number(), z.null()]))
export const ParseResult = z.object({
  sample: z.string(),
  sample_label: z.string(),
  columns: z.array(z.string()),
  records: z.array(ParseRecord).describe('Preview: the first normalised records'),
  accepted: z.number().int(),
  rejected: z.number().int(),
  reasons: z.array(z.object({ reason: z.string(), count: z.number().int() })),
  rejects: z.array(z.object({ row: z.number().int(), reason: z.string() })).describe('The first rejected rows: row is the line of the sample for a plain list or CSV, otherwise the record number; reason shows the value, cut and quoted'),
  truncated: z.boolean().describe('True when the row limit stopped parsing'),
})

export const endpoints = defineEndpoints([
  { method: 'get', path: '/feeds/status', summary: 'Timestamps and sources of the vulnerability data on the box', stories: ['S-FEED-1'], role: 'viewer', response: FeedStatus },
  { method: 'get', path: '/feeds/hot', summary: 'Newly exploited vulnerabilities, grouped by product, with "Do you have it?"', stories: ['S-FEED-1'], role: 'viewer',
    query: z.object({ window: z.enum(['24h', '7d']) }), response: HotResponse, example: { query: { window: '7d' } } },
  { method: 'get', path: '/feeds/weekly', summary: '"This week, in short": plain-language sentences about products under attack', stories: ['S-FEED-2'], role: 'viewer', response: WeeklyResponse },
  { method: 'post', path: '/feeds/weekly/{id}', summary: 'Answer "I have it" (adds a manually declared device) or "Not relevant"', stories: ['S-FEED-2', 'S-INV-2'], role: 'operator',
    params: z.object({ id: z.string() }), body: z.object({ answer: z.enum(['have', 'not_relevant']) }), response: WeeklyResponse },
  { method: 'get', path: '/feeds/cve/{id}', summary: 'Everything the box knows about a CVE (its brief) and your devices that match its exploited-list entry (404 not_in_data when the vulnerability data does not hold it)', stories: ['S-FEED-1', 'S-FEED-3'], role: 'viewer',
    params: z.object({ id: cveId }), response: CveDetail, example: { params: { id: 'CVE-2025-22225' } } },
  { method: 'get', path: '/feeds/cve/{id}/tier', summary: 'A CVE that is on no exploited list: EPSS, NVD dates and severity from the tier data (404 not_in_data when neither feed holds it)', stories: ['S-TIER-1'], role: 'viewer',
    params: z.object({ id: cveId }), response: TierCve, example: { params: { id: 'CVE-2026-31001' } } },
  { method: 'get', path: '/feeds/search', summary: 'Search CVEs, products, IPs or domains in the data on the box', stories: ['S-FEED-3'], role: 'viewer',
    query: z.object({ q: z.string().min(1).max(200) }), response: SearchResult, example: { query: { q: '185.220.101.47' } } },
  { method: 'get', path: '/feeds/sources', summary: 'Built-in and custom feeds with schedule, last fetch, record count and errors', stories: ['S-FEED-4'], role: 'viewer', response: FeedList },
  { method: 'put', path: '/feeds/sources/{id}', summary: 'Turn a feed on or off, change its schedule, or set a mirror address (built-in feeds cannot be deleted)', stories: ['S-FEED-4'], role: 'admin',
    params: z.object({ id: z.string() }), body: FeedPatch, response: Feed },
  { method: 'post', path: '/feeds/sources/{id}/fetch', summary: 'Fetch a feed now, directly from its source', stories: ['S-FEED-4'], role: 'admin', params: z.object({ id: z.string() }), response: Feed },
  { method: 'post', path: '/feeds/custom', status: 201, summary: 'Add your own feed (vulnerabilities or IOC) with its parsing rules', stories: ['S-FEED-4', 'S-FEED-5'], role: 'admin', body: FeedInput, response: Feed },
  { method: 'put', path: '/feeds/custom/{id}', summary: 'Edit your own feed and its parsing rules', stories: ['S-FEED-4', 'S-FEED-5'], role: 'admin', params: z.object({ id: z.string() }), body: FeedInput, response: Feed },
  { method: 'delete', path: '/feeds/custom/{id}', summary: 'Delete your own feed; records already fetched are removed', stories: ['S-FEED-4'], role: 'admin', params: z.object({ id: z.string() }), response: null },
  { method: 'post', path: '/feeds/parse-test', summary: 'Try parsing rules on a sample and preview the normalised records, accepted and rejected rows', stories: ['S-FEED-5'], role: 'admin', body: ParseTestInput, response: ParseResult },
])
