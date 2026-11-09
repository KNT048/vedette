// Hợp đồng API module feeds (D-18). Kiểu UI suy ra từ schema ở đây (types.ts), nên UI ↔ mock ↔ OpenAPI không lệch.
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
  sources: z.array(z.object({ name: z.string(), url: z.url(), license: z.string(), fetched_at: z.iso.datetime() })),
  inventory_on: z.boolean(),
})

export const WeeklyItem = z.object({ id: z.string(), key: z.string(), text: z.string(), date_added: isoDate, cve: cveId, answer: z.enum(['have', 'not_relevant']).nullable() })
export const MatchedAsset = z.object({ id: z.string(), hostname: z.string().nullable(), ip: z.string(), display: z.string(), how: YouHave })
export const CveDetail = Vuln.extend({ display: z.string(), matched: z.array(MatchedAsset).nullable() })
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

// ---------- Feed sources and custom parsing (S-FEED-4, S-FEED-5; D-36, D-37)
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
  interval_hours: z.number().int().min(1).max(168),
  auth: FeedAuth,
  parser: Parser.nullable().describe('null for built-in feeds'),
  last_fetch: z.iso.datetime().nullable(),
  records: z.number().int().nullable(),
  status: z.enum(['ok', 'error', 'never']),
  error: z.string().nullable(),
  license: z.string().nullable(),
})
export const FeedList = z.object({ items: z.array(Feed) })
export const FeedPatch = z.object({
  enabled: z.boolean().optional(),
  interval_hours: z.number().int().min(1).max(168).optional(),
  url: z.string().max(500).optional().describe('Built-in: a mirror address. Empty string resets it to the default'),
})
export const FeedInput = z.object({
  name: z.string().min(1).max(60),
  kind: FeedKind,
  url: z.string().max(500),
  enabled: z.boolean(),
  interval_hours: z.number().int().min(1).max(168),
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
  rejects: z.array(z.object({ row: z.number().int(), reason: z.string() })).describe('The first rejected rows'),
  truncated: z.boolean().describe('True when the row limit stopped parsing'),
})

export const endpoints = defineEndpoints([
  { method: 'get', path: '/feeds/status', summary: 'Timestamps and sources of the vulnerability data on the box', stories: ['S-FEED-1'], role: 'viewer', response: FeedStatus },
  { method: 'get', path: '/feeds/hot', summary: 'Newly exploited vulnerabilities, grouped by product, with "Do you have it?"', stories: ['S-FEED-1'], role: 'viewer',
    query: z.object({ window: z.enum(['24h', '7d']) }), response: HotResponse, example: { query: { window: '7d' } } },
  { method: 'get', path: '/feeds/weekly', summary: '"This week, in short": plain-language sentences about products under attack', stories: ['S-FEED-2'], role: 'viewer', response: WeeklyResponse },
  { method: 'post', path: '/feeds/weekly/{id}', summary: 'Answer "I have it" (adds a manually declared device) or "Not relevant"', stories: ['S-FEED-2', 'S-INV-2'], role: 'operator',
    params: z.object({ id: z.string() }), body: z.object({ answer: z.enum(['have', 'not_relevant']) }), response: WeeklyResponse },
  { method: 'get', path: '/feeds/cve/{id}', summary: 'Details of an exploited CVE and your matching devices', stories: ['S-FEED-1', 'S-FEED-3'], role: 'viewer',
    params: z.object({ id: cveId }), response: CveDetail, example: { params: { id: 'CVE-2022-27593' } } },
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
