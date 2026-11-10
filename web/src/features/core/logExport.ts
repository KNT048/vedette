// Download all logs (S-CORE-6, D-48). Reads each log collection of the box with peek() (absent = empty), removes secrets,
// and returns one file. Hash-chained categories keep their `prev_hash`/`hash` fields so they can be verified offline.
import { http, HttpResponse } from 'msw'
import { API, audit, fail, guard } from '@/mocks/http'
import { peek } from '@/mocks/db'
import { auditStore } from '@/mocks/stores'
import { LOG_CATEGORIES, type LogCategory } from './logCategories'

export const CHAIN_NOTE = 'Chained categories (audit, response, ai_activity): hash = lowercase hex SHA-256(prev_hash + "\\n" + canonical JSON of the entry without hash and seq, keys sorted; prev_hash is part of the entry). Rows are exported as stored; chains says where each chain starts (anchor) and ends (head_hash, count).'
const GENESIS = '0'.repeat(64)

// A key is secret when, lower-cased and without - or _, it contains one of these words (or is `key`). Hash fields and the
// names below are not secrets. Chained categories are not scrubbed at all: that would break their hashes, so their owners keep
// secrets out of the rows when they write them.
const SECRET_WORDS = ['password', 'passwd', 'secret', 'token', 'apikey', 'privatekey', 'passphrase', 'credential', 'authorization', 'cookie', 'session', 'bearer', 'jwt', 'dsn', 'connectionstring', 'webhook']
const NOT_SECRET = ['key_last4', 'tokens_in', 'tokens_out', 'token_id']
export function isSecretKey(k: string): boolean {
  const l = k.toLowerCase()
  if (NOT_SECRET.includes(l)) return false
  const n = l.replace(/[-_]/g, '')
  if (n.endsWith('hash')) return false
  return n === 'key' || SECRET_WORDS.some((w) => n.includes(w))
}
/** Drop every secret-looking field at any depth, also inside a string that holds a JSON object or array. `key_last4` and `tokens_in` stay. */
export function scrub(v: unknown): unknown {
  if (Array.isArray(v)) return v.map(scrub)
  if (v && typeof v === 'object') return Object.fromEntries(Object.entries(v as Record<string, unknown>).filter(([k]) => !isSecretKey(k)).map(([k, x]) => [k, scrub(x)]))
  if (typeof v === 'string' && /^\s*[{[]/.test(v)) {
    try { const p: unknown = JSON.parse(v); if (p && typeof p === 'object') return JSON.stringify(scrub(p)) } catch { /* not JSON: keep the text */ }
  }
  return v
}

const tsOf = (r: unknown): string | null => {
  const o = r as Record<string, unknown>
  const v = o.ts ?? o.at ?? o.time ?? o.created_at ?? o.last_seen ?? o.seen_at
  return typeof v === 'string' ? v : null
}
const raw = (id: LogCategory): unknown => {
  const c = LOG_CATEGORIES.find((x) => x.id === id)!
  return id === 'audit' ? auditStore.get() : peek<unknown>(c.key)
}
const rows = (id: LogCategory): unknown[] => { const v = raw(id); return Array.isArray(v) ? v : [] }
/** Categories whose module keeps no log (the backend has no registered source for them): they export as empty and are listed as missing. */
export const missing = (ids: LogCategory[]): LogCategory[] => ids.filter((id) => !Array.isArray(raw(id)))
/** `to` as a bare day is inclusive: the whole day counts. */
const endOf = (to: string | null) => (to && /^\d{4}-\d{2}-\d{2}$/.test(to) ? `${to}T23:59:59.999Z` : to)
const isChained = (id: string) => LOG_CATEGORIES.some((c) => c.id === id && 'chained' in c)
const inRange = (r: unknown, from: string | null, end: string | null) => { const t = tsOf(r); return !t || ((!from || t >= from) && (!end || t <= end)) }
/** A chained category is the run of rows from the first one at or after `from` to the last one at or before `to`, so it still links. */
function window(id: LogCategory, from: string | null, end: string | null): unknown[] {
  const all = rows(id)
  if (!isChained(id)) return all.filter((r) => inRange(r, from, end))
  const first = from ? all.findIndex((r) => (tsOf(r) ?? '') >= from) : 0
  let last = -1
  all.forEach((r, i) => { if (!end || (tsOf(r) ?? '') <= end) last = i })
  return first < 0 || last < first ? [] : all.slice(first, last + 1)
}
export function collect(ids: LogCategory[], from: string | null, to: string | null): Record<string, unknown[]> {
  const end = endOf(to)
  return Object.fromEntries(ids.map((id) => [id, isChained(id) ? window(id, from, end) : (scrub(window(id, from, end)) as unknown[])]))
}
export interface ChainInfo { anchor: string | null; anchor_kind: 'genesis' | 'pruned' | 'row' | 'none'; head_hash: string | null; count: number; complete: boolean }
/** Where the exported rows of each chained category sit in their chain (the backend reads this in the transaction of the rows). */
export function chainsOf(ids: LogCategory[], data: Record<string, unknown[]>): Record<string, ChainInfo> {
  const f = (r: unknown, k: string) => ((r as Record<string, unknown>)[k] as string | undefined) ?? null
  return Object.fromEntries(ids.filter((id) => isChained(id) && Array.isArray(raw(id))).map((id) => {
    const all = rows(id), got = data[id] ?? []
    const first = got[0], head = all.length ? f(all[all.length - 1], 'hash') : null
    const anchor = first ? f(first, 'prev_hash') : null
    const complete = got.length === all.length && (all.length === 0 || anchor === GENESIS)
    return [id, { anchor, anchor_kind: !first ? 'none' : anchor === GENESIS ? 'genesis' : 'row', head_hash: head, count: all.length, complete }]
  }))
}

// A text that starts with = + - @ tab or CR would run as a formula in a spreadsheet: it gets a leading apostrophe (logs hold text an attacker chose).
const cell = (v: unknown) => {
  let s = v === null || v === undefined ? '' : typeof v === 'object' ? JSON.stringify(v) : String(v)
  if (typeof v === 'string' && /^[=+\-@\t\r]/.test(s)) s = `'${s}`
  return /[",\n\r]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s
}
export function toCsv(data: Record<string, unknown[]>, gaps: string[] = []): string {
  return Object.entries(data).map(([id, list]) => {
    const cols = [...new Set(list.flatMap((r) => Object.keys(r as object)))]
    return [`# ${id}${gaps.includes(id) ? ' (no source)' : ''}`, cols.map((c) => cell(c)).join(','), ...list.map((r) => cols.map((c) => cell((r as Record<string, unknown>)[c])).join(','))].join('\n')
  }).join('\n\n') + '\n'
}

export const logExportHandlers = [
  http.get(`${API}/core/logs/export`, ({ request }) => {
    const denied = guard('admin'); if (denied) return denied
    const q = new URL(request.url).searchParams
    const ids = (q.get('categories') ?? '').split(',').filter(Boolean)
    const bad = ids.find((i) => !LOG_CATEGORIES.some((c) => c.id === i))
    if (ids.length === 0 || bad) return fail(400, 'invalid_categories', bad ? `Unknown log category "${bad}".` : 'Pick at least one log category to download.')
    const format = q.get('format') ?? 'json'
    if (format !== 'json' && format !== 'csv') return fail(400, 'invalid_format', 'Choose JSON or CSV.')
    const from = q.get('from') || null, to = q.get('to') || null
    const badDay = [from, to].find((d) => d && (!/^\d{4}-\d{2}-\d{2}$/.test(d) || +d.slice(0, 4) < 2000 || +d.slice(0, 4) > 2100 || Number.isNaN(Date.parse(d))))
    if (badDay) return fail(400, 'invalid_range', 'Dates are written YYYY-MM-DD, for example 2026-11-09, between 2000 and 2100.')
    if (from && to && from > to) return fail(400, 'invalid_range', 'The start date is after the end date.')
    const data = collect(ids as LogCategory[], from, to)
    const gaps = missing(ids as LogCategory[])
    audit('logs.export', ids.join(','), `${format}; ${Object.values(data).reduce((n, l) => n + l.length, 0)} rows${from ? `; from ${from}` : ''}${to ? `; to ${to}` : ''}`)
    const stamp = new Date().toISOString().slice(0, 10)
    const counts = Object.fromEntries(Object.entries(data).map(([id, l]) => [id, l.length]))
    const out = format === 'csv' ? `\ufeff${toCsv(data, gaps)}` : JSON.stringify({ format: 'vedette-logs/1', exported_at: new Date().toISOString(), from, to, time_zone: 'UTC', verification: CHAIN_NOTE, missing: gaps, counts, chains: chainsOf(ids as LogCategory[], data), categories: data }, null, 2)
    return new HttpResponse(out, { headers: { 'Content-Type': format === 'csv' ? 'text/csv' : 'application/json', 'Content-Disposition': `attachment; filename=vedette-logs-${stamp}.${format}` } })
  }),
]
