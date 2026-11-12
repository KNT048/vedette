// Feed parsers (S-FEED-5, D-37). Run inside the mock so the preview is real; the Go box later implements the same rules.
// Fail closed: size and row limits, bad rows are counted with a reason (never crash), regexes are length-limited and compile-checked.
import { IPV4_RE } from '@/mocks/http'
import { FIELDS, ROW_LIMIT, SIZE_LIMIT } from './defaults'
import type { FeedKind, FieldMap, ParseRecord, Parser } from './types'

export class ParserConfigError extends Error {
  code: 'too_large' | 'bad_config' | 'bad_sample'
  constructor(code: 'too_large' | 'bad_config' | 'bad_sample', message: string) { super(message); this.code = code }
}
export interface ParseOutput { records: ParseRecord[]; accepted: number; rejected: number; reasons: { reason: string; count: number }[]; rejects: { row: number; reason: string }[]; truncated: boolean }

const MAX_REJECT_LIST = 200
type Raw = Record<string, string | null>
/** Raw key holding the line of a plain-list row, so a rejection names the line of the sample (comments and blank lines counted). */
const LINE = '\u0001'
type Rejection = { reject: string }

// ---------- JSONPath subset: $ .key ['key'] [n] [*] .*  (no filters, no recursive descent)
type Tok = string | number | '*'
export function compilePath(path: string): Tok[] {
  const p = path.trim()
  if (!p.startsWith('$')) throw new ParserConfigError('bad_config', `JSONPath must start with $ (got "${p.slice(0, 40)}").`)
  const toks: Tok[] = []
  let i = 1
  while (i < p.length) {
    if (p[i] === '.') {
      if (p[i + 1] === '.') throw new ParserConfigError('bad_config', 'Recursive descent (..) is not supported.')
      const m = /^\.(\*|[A-Za-z_][\w-]*)/.exec(p.slice(i))
      if (!m) throw new ParserConfigError('bad_config', `Bad JSONPath near "${p.slice(i, i + 12)}".`)
      toks.push(m[1] === '*' ? '*' : m[1]!); i += m[0].length
    } else if (p[i] === '[') {
      const m = /^\[(\*|\d+|'([^']*)'|"([^"]*)")\]/.exec(p.slice(i))
      if (!m) throw new ParserConfigError('bad_config', `Bad JSONPath near "${p.slice(i, i + 12)}".`)
      toks.push(m[1] === '*' ? '*' : /^\d+$/.test(m[1]!) ? Number(m[1]) : (m[2] ?? m[3])!); i += m[0].length
    } else throw new ParserConfigError('bad_config', `Bad JSONPath near "${p.slice(i, i + 12)}".`)
  }
  return toks
}
export function jsonPath(root: unknown, path: string | Tok[]): unknown[] {
  let cur: unknown[] = [root]
  for (const t of typeof path === 'string' ? compilePath(path) : path) {
    const next: unknown[] = []
    for (const v of cur) {
      if (t === '*') { if (Array.isArray(v)) next.push(...v); else if (v && typeof v === 'object') next.push(...Object.values(v)) }
      else if (typeof t === 'number') { if (Array.isArray(v) && t < v.length) next.push(v[t]) }
      else if (v && typeof v === 'object' && !Array.isArray(v) && Object.hasOwn(v, t)) next.push((v as Record<string, unknown>)[t])
    }
    cur = next
  }
  return cur
}
const scalar = (v: unknown): string | null | Rejection => {
  if (v === null || v === undefined) return null
  if (typeof v === 'string') return v
  if (typeof v === 'number' || typeof v === 'boolean') return String(v)
  if (Array.isArray(v) && v.every((x) => typeof x !== 'object' || x === null)) return v.join(', ')
  return { reject: 'value is an object, not text' }
}

// ---------- CSV (RFC 4180 quotes, CRLF, # comment lines)
export function parseCsv(text: string, delimiter: string): string[][] {
  return parseCsvLines(text, delimiter).map((r) => r.cells)
}
/**
 * parseCsv with, for each record, the 1-based line of the text where it starts (quoted fields can span lines). A quote still open at the end of
 * the text does not swallow the rows after it: that record is flagged (`bad`) and the text from its start is read again with quotes taken
 * literally, so every physical row is accounted for (the Go parser, modules/feeds parseCSV, does the same).
 */
function parseCsvLines(text: string, delimiter: string, quotes = true, line0 = 1): { cells: string[]; line: number; bad?: string }[] {
  const rows: { cells: string[]; line: number; bad?: string }[] = []
  let row: string[] = [], cell = '', q = false, line = line0, rowLine = line0, rowStart = 0, startLine = line0
  const t = line0 === 1 && quotes ? text.replace(/^\uFEFF/, '') : text
  for (let i = 0; i < t.length; i++) {
    const c = t[i]!
    if (q) { if (c === '"') { if (t[i + 1] === '"') { cell += '"'; i++ } else q = false } else { if (c === '\n' || (c === '\r' && t[i + 1] !== '\n')) line++; cell += c } }
    else if (quotes && c === '"' && cell === '') q = true
    else if (c === delimiter) { row.push(cell); cell = '' }
    else if (c === '\n' || c === '\r') { if (c === '\r' && t[i + 1] === '\n') i++; row.push(cell); cell = ''; if (!(row.length === 1 && row[0] === '') && !row[0]!.startsWith('#')) rows.push({ cells: row, line: rowLine }); row = []; line++; rowLine = line; rowStart = i + 1; startLine = line }
    else cell += c
    if (rows.length > ROW_LIMIT + 1) return rows
  }
  if (q) {
    const rest = parseCsvLines(t.slice(rowStart), delimiter, false, startLine)
    if (rest.length && rest[0]!.line === startLine) rest[0]!.bad = CSV_OPEN_QUOTE // not when the row that opened the quote was a comment
    return rows.concat(rest)
  }
  if (cell !== '' || row.length) { row.push(cell); if (!row[0]!.startsWith('#')) rows.push({ cells: row, line: rowLine }) }
  return rows
}
const CSV_OPEN_QUOTE = 'a quote is opened on this row and never closed'

// ---------- extraction by format: each returns raw string maps keyed by the field source
function extractJson(text: string, p: Parser): Raw[] {
  let root: unknown
  try { root = JSON.parse(text) } catch (e) { throw new ParserConfigError('bad_sample', `The sample is not valid JSON (${(e as Error).message.slice(0, 80)}).`) }
  const nodes = jsonPath(root, p.records_path || '$[*]')
  const compiled = Object.fromEntries(Object.entries(p.fields).filter(([, f]) => f.source.trim()).map(([k, f]) => [k, compilePath(f.source)]))
  return nodes.slice(0, ROW_LIMIT + 1).map((n) => {
    const r: Raw = {}
    for (const [k, path] of Object.entries(compiled)) {
      const v = jsonPath(n, path)[0]
      const s = scalar(v)
      r[k] = typeof s === 'object' && s !== null ? `\u0000${s.reject}` : s
    }
    return r
  })
}
function extractCsv(text: string, p: Parser): Raw[] {
  const rows = parseCsvLines(text, p.delimiter || ',')
  if (p.has_header && rows[0]?.bad) throw new ParserConfigError('bad_sample', `The header row is not usable: ${rows[0].bad}.`)
  const header = p.has_header ? (rows.shift()?.cells ?? []).map((h) => h.trim().toLowerCase()) : []
  return rows.slice(0, ROW_LIMIT + 1).map(({ cells, line, bad }) => {
    const r: Raw = { [LINE]: String(line) }
    if (bad) { r['\u0000'] = bad; return r }
    for (const [k, f] of Object.entries(p.fields)) {
      const s = f.source.trim()
      if (!s) continue
      let idx = header.indexOf(s.toLowerCase())
      if (idx < 0 && /^\d+$/.test(s)) idx = Number(s) - 1
      r[k] = idx >= 0 && idx < cells.length ? cells[idx]! : null
    }
    return r
  })
}
function extractRss(text: string, p: Parser): Raw[] {
  const doc = new DOMParser().parseFromString(text, 'text/xml')
  if (doc.querySelector('parsererror')) throw new ParserConfigError('bad_sample', 'The sample is not valid XML.')
  const items = [...doc.querySelectorAll('item, entry')].slice(0, ROW_LIMIT + 1)
  const get = (el: Element, name: string): string | null => {
    const n = name.toLowerCase()
    const alias: Record<string, string[]> = { description: ['description', 'summary', 'content'], pubdate: ['pubDate', 'published', 'updated'], published: ['published', 'pubDate', 'updated'], link: ['link'], id: ['guid', 'id'], guid: ['guid', 'id'] }
    for (const tag of alias[n] ?? [name]) {
      const c = [...el.children].find((x) => x.localName.toLowerCase() === tag.toLowerCase())
      if (!c) continue
      if (tag === 'link') return c.getAttribute('href') ?? c.textContent
      if (tag === 'category') return c.getAttribute('term') ?? c.textContent
      return c.textContent
    }
    return null
  }
  return items.map((el) => Object.fromEntries(Object.entries(p.fields).filter(([, f]) => f.source.trim()).map(([k, f]) => [k, get(el, f.source.trim())])))
}
const STIX_OBJ: Record<string, string> = { 'ipv4-addr': 'ip', 'ipv6-addr': 'ip', 'domain-name': 'domain', url: 'url', file: 'hash' }
/** STIX 2.1 bundle or TAXII 2.1 envelope: one record per `object:path = 'value'` comparison inside an indicator pattern. */
function extractStix(text: string): Raw[] {
  let root: unknown
  try { root = JSON.parse(text) } catch { throw new ParserConfigError('bad_sample', 'The sample is not valid JSON.') }
  const objects = (root as { objects?: unknown }).objects
  if (!Array.isArray(objects)) throw new ParserConfigError('bad_sample', 'No "objects" array: expected a STIX 2.1 bundle or a TAXII 2.1 envelope.')
  const out: Raw[] = []
  for (const o of objects) {
    if (!o || typeof o !== 'object' || (o as { type?: string }).type !== 'indicator') continue
    const ind = o as { pattern?: unknown; confidence?: unknown; valid_from?: unknown }
    const base = { confidence: ind.confidence !== undefined ? String(ind.confidence) : null, first_seen: typeof ind.valid_from === 'string' ? ind.valid_from : null }
    if (typeof ind.pattern !== 'string' || ind.pattern.length > 2000) { out.push({ ...base, indicator: null, kind: null, '\u0000': 'indicator has no usable pattern' }); continue }
    const re = /([a-z0-9-]+):([A-Za-z0-9_.'-]+)\s*=\s*'((?:[^'\\]|\\.)*)'/g
    let m: RegExpExecArray | null, n = 0
    while ((m = re.exec(ind.pattern))) {
      n++
      const kind = STIX_OBJ[m[1]!]
      if (!kind || (m[1] === 'file' && !/hashes/i.test(m[2]!))) { out.push({ ...base, indicator: null, kind: null, '\u0000': `unsupported pattern object "${m[1]}:${m[2]}"` }); continue }
      out.push({ ...base, indicator: m[3]!.replace(/\\(.)/g, '$1'), kind })
    }
    if (!n) out.push({ ...base, indicator: null, kind: null, '\u0000': 'pattern has no comparison this parser understands' })
  }
  return out.slice(0, ROW_LIMIT + 1)
}
function extractLines(text: string): Raw[] {
  return text.split(/\r?\n/).map((l, i) => [l.trim(), i + 1] as const).filter(([l]) => l && !l.startsWith('#')).slice(0, ROW_LIMIT + 1).map(([l, n]) => ({ indicator: l.split(/\s+/)[0]!, [LINE]: String(n) }))
}

// ---------- normalisation and validation
function pad(n: number) { return String(n).padStart(2, '0') }
export function normDate(raw: string, fmt: FieldMap['date_format']): string | null {
  const s = raw.trim()
  let d: Date | null = null
  const ymd = (y: number, m: number, day: number) => { const x = new Date(Date.UTC(y, m - 1, day)); return x.getUTCFullYear() === y && x.getUTCMonth() === m - 1 && x.getUTCDate() === day ? x : null }
  if (fmt === 'epoch') { if (/^\d{9,13}$/.test(s)) { const n = Number(s); d = new Date(s.length > 10 ? n : n * 1000) } }
  else if (fmt === 'dmy' || fmt === 'mdy') {
    const m = /^(\d{1,2})[/.-](\d{1,2})[/.-](\d{4})/.exec(s)
    if (m) d = fmt === 'dmy' ? ymd(+m[3]!, +m[2]!, +m[1]!) : ymd(+m[3]!, +m[1]!, +m[2]!)
  } else {
    const iso = /^(\d{4})-(\d{2})-(\d{2})/.exec(s)
    if (iso) d = ymd(+iso[1]!, +iso[2]!, +iso[3]!)
    else { const t = Date.parse(s); if (!Number.isNaN(t) && /[A-Za-z]/.test(s)) d = new Date(t) }
  }
  return d && !Number.isNaN(d.getTime()) ? `${d.getUTCFullYear()}-${pad(d.getUTCMonth() + 1)}-${pad(d.getUTCDate())}` : null
}
const KIND_ALIAS: Record<string, string> = { ip: 'ip', ipv4: 'ip', ip_address: 'ip', 'ipv4-addr': 'ip', 'ip:port': 'ip', domain: 'domain', fqdn: 'domain', hostname: 'domain', 'domain-name': 'domain', url: 'url', hash: 'hash', md5: 'hash', sha1: 'hash', sha256: 'hash', md5_hash: 'hash', sha256_hash: 'hash' }
const HASH_RE = /^([a-f0-9]{32}|[a-f0-9]{40}|[a-f0-9]{64})$/i
/** A feed's domain (Go validDomain): the last label is letters, or an IDN top-level domain in ASCII form (`xn--p1ai`, hagezi TIF lists such names). */
export const FEED_DOMAIN_RE = /^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+([a-z]{2,63}|xn--[a-z0-9-]{0,58}[a-z0-9])$/i
const IPV6_RE = /^[0-9a-f:]{3,39}$/i
function detectKind(v: string): string | null {
  if (IPV4_RE.test(v) || (v.includes(':') && IPV6_RE.test(v))) return 'ip'
  if (/^https?:\/\//i.test(v)) return 'url'
  if (HASH_RE.test(v)) return 'hash'
  return FEED_DOMAIN_RE.test(v) ? 'domain' : null
}

function applyField(id: string, raw: string | null, f: FieldMap | undefined, dateField: boolean): string | null | Rejection {
  if (raw === null || raw === undefined) return null
  if (raw.startsWith('\u0000')) return { reject: `${id}: ${raw.slice(1)}` }
  let v = raw
  if (f?.regex) {
    let re: RegExp
    try { re = new RegExp(f.regex) } catch { throw new ParserConfigError('bad_config', `Invalid regular expression for ${id}.`) }
    const m = re.exec(v)
    if (!m) return { reject: `${id}: regex did not match` }
    v = m[1] ?? m[0]
  }
  if (f?.trim !== false) v = v.trim()
  if (f?.lowercase) v = v.toLowerCase()
  if (v === '') return null
  if (dateField) { const d = normDate(v, f?.date_format ?? 'auto'); return d ?? { reject: `${id}: unrecognised date "${v.slice(0, 30)}"` } }
  return v
}

function build(kind: FeedKind, raw: Raw, p: Parser): ParseRecord | Rejection {
  if (raw['\u0000']) return { reject: raw['\u0000'] }
  const out: ParseRecord = {}
  for (const { id, required, date } of FIELDS[kind]) {
    const r = applyField(id, raw[id] ?? null, p.fields[id], !!date)
    if (r && typeof r === 'object') return r
    if (r === null && required) return { reject: `${id}: missing` }
    out[id] = r
  }
  if (kind === 'vulnerabilities') {
    out.cve = String(out.cve).toUpperCase()
    if (!/^CVE-\d{4}-\d{4,}$/.test(out.cve)) return { reject: `cve: "${out.cve.slice(0, 30)}" is not a CVE ID` }
    if (typeof out.link === 'string' && !/^https?:\/\/\S+$/i.test(out.link)) return { reject: 'link: not an http(s) address' }
    if (typeof out.description === 'string') out.description = out.description.slice(0, 500)
  } else {
    const ind = String(out.indicator)
    const given = out.kind === null || out.kind === undefined ? null : (KIND_ALIAS[String(out.kind).toLowerCase()] ?? undefined)
    if (given === undefined) return { reject: `kind: unknown value "${String(out.kind).slice(0, 20)}"` }
    // "ip:port" style indicators: keep the address.
    let value = ind
    if (given === 'ip' && /^\d+\.\d+\.\d+\.\d+:\d+$/.test(ind)) value = ind.replace(/:\d+$/, '')
    const kindOut = given ?? detectKind(value)
    const ok = kindOut === 'ip' ? (IPV4_RE.test(value) || (value.includes(':') && IPV6_RE.test(value))) : kindOut === 'domain' ? FEED_DOMAIN_RE.test(value) : kindOut === 'url' ? /^https?:\/\/[^\s/]+/i.test(value) && value.length <= 2000 : kindOut === 'hash' ? HASH_RE.test(value) : false
    if (!kindOut || !ok) return { reject: `indicator: "${ind.slice(0, 40)}" is not a valid ${kindOut ?? 'indicator'}` }
    out.indicator = value; out.kind = kindOut
    if (out.confidence !== null && out.confidence !== undefined) {
      const c = Number(out.confidence)
      if (!Number.isFinite(c) || c < 0 || c > 100) return { reject: `confidence: "${String(out.confidence).slice(0, 20)}" is not a number from 0 to 100` }
      out.confidence = Math.round((c > 1 ? c / 100 : c) * 100) / 100
    }
  }
  return out
}

export function parseFeed(text: string, kind: FeedKind, p: Parser): ParseOutput {
  if (text.length > SIZE_LIMIT) throw new ParserConfigError('too_large', `The sample is larger than ${SIZE_LIMIT / 1_000_000} MB; Vedette would skip it.`)
  const raws = p.format === 'json' ? extractJson(text, p) : p.format === 'csv' ? extractCsv(text, p) : p.format === 'rss' ? extractRss(text, p) : p.format === 'stix' ? extractStix(text) : extractLines(text)
  const truncated = raws.length > ROW_LIMIT
  const records: ParseRecord[] = []
  const rejects: { row: number; reason: string }[] = []
  const counts = new Map<string, number>()
  let accepted = 0, rejected = 0
  raws.slice(0, ROW_LIMIT).forEach((raw, i) => {
    const r = build(kind, raw, p)
    if ('reject' in r && typeof r.reject === 'string' && Object.keys(r).length === 1) {
      rejected++
      const key = r.reject.replace(/"[^"]*"/g, '"…"')
      counts.set(key, (counts.get(key) ?? 0) + 1)
      if (rejects.length < MAX_REJECT_LIST) rejects.push({ row: raw[LINE] ? Number(raw[LINE]) : i + 1, reason: r.reject })
    } else { accepted++; if (records.length < 20) records.push(r as ParseRecord) }
  })
  return { records, accepted, rejected, reasons: [...counts].map(([reason, count]) => ({ reason, count })).sort((a, b) => b.count - a.count), rejects: rejects.slice(0, 10), truncated }
}

/** Validates the rules before a run so a bad config is a clear error, not a crash. */
export function checkParser(kind: FeedKind, p: Parser) {
  if (p.format === 'json') { compilePath(p.records_path || '$[*]'); for (const f of Object.values(p.fields)) if (f.source.trim()) compilePath(f.source) }
  for (const [id, f] of Object.entries(p.fields)) {
    if (f.regex) { try { new RegExp(f.regex) } catch { throw new ParserConfigError('bad_config', `Invalid regular expression for ${id}.`) } }
  }
  const need = FIELDS[kind].find((x) => x.required)!
  if ((p.format === 'json' || p.format === 'csv' || p.format === 'rss') && !p.fields[need.id]?.source.trim()) throw new ParserConfigError('bad_config', `Map the required field "${need.id}".`)
}
