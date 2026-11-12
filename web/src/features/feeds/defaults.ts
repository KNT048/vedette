// Shared by the parsing editor (UI) and the mock parser: which fields each feed kind has, which formats fit it, sensible starting rules.
import type { TFunction } from 'i18next'
import type { FeedFormat, FeedKind, FieldMap, Parser } from './types'

export const FIELDS: Record<FeedKind, { id: string; required: boolean; date?: boolean }[]> = {
  vulnerabilities: [
    { id: 'cve', required: true }, { id: 'vendor', required: false }, { id: 'product', required: false },
    { id: 'date', required: false, date: true }, { id: 'description', required: false }, { id: 'link', required: false },
  ],
  ioc: [
    { id: 'indicator', required: true }, { id: 'kind', required: false }, { id: 'confidence', required: false }, { id: 'first_seen', required: false, date: true },
  ],
}
export const FORMATS: Record<FeedKind, FeedFormat[]> = { vulnerabilities: ['json', 'csv', 'rss'], ioc: ['json', 'csv', 'rss', 'stix', 'lines'] }
export const SIZE_LIMIT = 5_000_000
export const ROW_LIMIT = 50_000
export const PREVIEW_ROWS = 20

const f = (source = '', extra: Partial<FieldMap> = {}): FieldMap => ({ source, regex: '', trim: true, lowercase: false, date_format: 'auto', ...extra })

// Starting rules per kind and format; they match the built-in sample of that format.
const SOURCES: Record<FeedKind, Partial<Record<FeedFormat, { records_path?: string; fields: Record<string, FieldMap> }>>> = {
  vulnerabilities: {
    json: { records_path: '$.vulnerabilities[*]', fields: { cve: f('$.cveID'), vendor: f('$.vendorProject'), product: f('$.product'), date: f('$.dateAdded'), description: f('$.shortDescription'), link: f('$.notes') } },
    csv: { fields: { cve: f('cve'), vendor: f('vendor'), product: f('product'), date: f('published', { date_format: 'dmy' }), description: f('summary'), link: f('url') } },
    rss: { fields: { cve: f('title', { regex: '(CVE-\\d{4}-\\d{4,})' }), vendor: f(), product: f('category'), date: f('pubDate'), description: f('description'), link: f('link') } },
  },
  ioc: {
    json: { records_path: '$.data[*]', fields: { indicator: f('$.ioc'), kind: f('$.type', { lowercase: true }), confidence: f('$.score'), first_seen: f('$.first_seen') } },
    csv: { fields: { indicator: f('dst_ip'), kind: f(), confidence: f(), first_seen: f('first_seen_utc') } },
    rss: { fields: { indicator: f('title'), kind: f(), confidence: f(), first_seen: f('published') } },
    stix: { fields: {} },
    lines: { fields: { indicator: f('') } },
  },
}

export function defaultParser(kind: FeedKind, format: FeedFormat): Parser {
  const d = SOURCES[kind][format] ?? { fields: {} }
  const fields: Record<string, FieldMap> = {}
  for (const { id } of FIELDS[kind]) fields[id] = { ...(d.fields[id] ?? f()) }
  return { format, records_path: d.records_path ?? '', delimiter: ',', has_header: true, fields }
}

/** URL rule: https only, except internal addresses (private ranges, localhost, .local/.lan/.internal names). */
export function isInternalHost(host: string): boolean {
  const h = host.toLowerCase().replace(/^\[|\]$/g, '')
  if (h === 'localhost' || h === '::1' || /\.(local|lan|internal|localhost)$/.test(h)) return true
  const m = /^(\d+)\.(\d+)\.\d+\.\d+$/.exec(h)
  if (!m) return false
  const a = Number(m[1]), b = Number(m[2])
  return a === 10 || a === 127 || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168)
}
export function checkFeedUrl(raw: string): 'ok' | 'url' | 'https' {
  let u: URL
  try { u = new URL(raw.trim()) } catch { return 'url' }
  if (u.protocol === 'https:') return 'ok'
  if (u.protocol === 'http:' && isInternalHost(u.hostname)) return 'ok'
  return u.protocol === 'http:' ? 'https' : 'url'
}

/** The pull's sentence for an address Vedette never pulls from (modules/feeds blockedText, D-208, D-229). */
export const BLOCKED_TEXT = 'Vedette does not pull feeds from itself or from loopback, link-local or cloud metadata addresses.'

const v4Blocked = (a: number, b: number, c: number, d: number) =>
  a === 127 || (a === 0 && b === 0 && c === 0 && d === 0) || (a === 169 && b === 254) || (a >= 224 && a <= 239) ||
  (a === 100 && b === 100 && c === 100 && d === 200) || (a === 192 && b === 0 && c === 0 && d === 192)

/** The 8 hextets of an IPv6 literal as URL writes it (compressed, no zone); null when it is not one. */
function hextets(h: string): number[] | null {
  const parts = h.split('::')
  if (parts.length > 2) return null
  const side = (x: string) => (x ? x.split(':').map((p) => (/^[0-9a-f]{1,4}$/.test(p) ? parseInt(p, 16) : NaN)) : [])
  const head = side(parts[0]!), tail = parts.length === 2 ? side(parts[1]!) : []
  const fill = 8 - head.length - tail.length
  if (head.concat(tail).some(Number.isNaN) || (parts.length === 1 ? fill !== 0 : fill < 1)) return null
  return [...head, ...Array<number>(Math.max(fill, 0)).fill(0), ...tail]
}

/**
 * The save-time half of the pull's address rule (modules/feeds CheckDest, D-229 (1)): a literal IP that is loopback, link-local,
 * cloud metadata, unspecified or multicast (also inside an IPv4-mapped, NAT64, 6to4 or IPv4-compatible IPv6 address) and the names
 * localhost and *.localhost. Other names are not resolved: the box judges what they resolve to at every pull.
 */
export function blockedFeedHost(raw: string): boolean {
  let host: string
  try { host = new URL(raw.trim()).hostname.toLowerCase().replace(/\.$/, '') } catch { return false }
  if (host === 'localhost' || host.endsWith('.localhost')) return true
  const v4 = /^(\d+)\.(\d+)\.(\d+)\.(\d+)$/.exec(host)
  if (v4) return v4Blocked(Number(v4[1]), Number(v4[2]), Number(v4[3]), Number(v4[4]))
  if (!host.startsWith('[')) return false
  const x = hextets(host.slice(1, -1))
  if (!x) return false
  const embedded = (hi: number, lo: number) => v4Blocked(hi >> 8, hi & 255, lo >> 8, lo & 255)
  const zero = (n: number) => x.slice(0, n).every((v) => v === 0)
  if (zero(8) || (zero(7) && x[7] === 1)) return true // :: and ::1
  if ((x[0]! & 0xffc0) === 0xfe80 || x[0]! >> 8 === 0xff) return true // link-local, multicast
  if (x[0] === 0xfd00 && x[1] === 0xec2 && x.slice(2, 7).every((v) => v === 0) && x[7] === 0x254) return true // AWS metadata over IPv6
  if (zero(5) && x[5] === 0xffff) return embedded(x[6]!, x[7]!) // IPv4-mapped
  if (zero(6)) return embedded(x[6]!, x[7]!) // IPv4-compatible
  if (x[0] === 0x64 && x[1] === 0xff9b && x.slice(2, 6).every((v) => v === 0)) return embedded(x[6]!, x[7]!) // NAT64
  if (x[0] === 0x2002) return embedded(x[1]!, x[2]!) // 6to4
  return false
}

/** Two feed addresses that fetch the same document (modules/feeds sameAddress): URL already lowercases the scheme and host and drops a default port. */
export const sameFeedAddress = (a: string, b: string) => {
  try { const x = new URL(a.trim()), y = new URL(b.trim()); return `${x.protocol}//${x.host}${x.pathname}${x.search}` === `${y.protocol}//${y.host}${y.pathname}${y.search}` } catch { return false }
}

/** "Every 3 days" and "Every week" read better than 72 and 168 hours; the value stays in hours. */
export const everyLabel = (t: TFunction<'feeds'>, h: number) =>
  h === 168 ? t('row.everyWeek') : h > 24 && h % 24 === 0 ? t('row.everyDays', { count: h / 24 }) : t('row.every', { count: h })
