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

/** "Every 3 days" and "Every week" read better than 72 and 168 hours; the value stays in hours. */
export const everyLabel = (t: TFunction<'feeds'>, h: number) =>
  h === 168 ? t('row.everyWeek') : h > 24 && h % 24 === 0 ? t('row.everyDays', { count: h / 24 }) : t('row.every', { count: h })
