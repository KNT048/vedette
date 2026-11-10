// Download all logs (S-CORE-6, D-48). Reads each log collection of the box with peek() (absent = empty), removes secrets,
// and returns one file. Hash-chained categories keep their `prev_hash`/`hash` fields so they can be verified offline.
import { http, HttpResponse } from 'msw'
import { API, audit, fail, guard } from '@/mocks/http'
import { peek } from '@/mocks/db'
import { auditStore } from '@/mocks/stores'
import { LOG_CATEGORIES, type LogCategory } from './logCategories'

export const CHAIN_NOTE = 'Hash-chained categories: hash = SHA-256(prev_hash + canonical JSON of the entry without hash, keys sorted). The first entry is the anchor.'

const SECRET_KEY = /^(password|passwd|secret|token|api_?key|key|private_?key|passphrase|credential|credentials|webhook|webhook_url|authorization)$|(_secret|_password|_token|_api_key|_webhook(_url)?|_credential)$/i
/** Drop every secret-looking field at any depth. `key_last4` and `tokens_in` stay: they are not secrets. */
export function scrub(v: unknown): unknown {
  if (Array.isArray(v)) return v.map(scrub)
  if (v && typeof v === 'object') return Object.fromEntries(Object.entries(v as Record<string, unknown>).filter(([k]) => !SECRET_KEY.test(k)).map(([k, x]) => [k, scrub(x)]))
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
export function collect(ids: LogCategory[], from: string | null, to: string | null): Record<string, unknown[]> {
  const end = endOf(to)
  return Object.fromEntries(ids.map((id) => [id, (scrub(rows(id)) as unknown[]).filter((r) => { const t = tsOf(r); return !t || ((!from || t >= from) && (!end || t <= end)) })]))
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
    return [`# ${id}${gaps.includes(id) ? ' (no source)' : ''}`, cols.join(','), ...list.map((r) => cols.map((c) => cell((r as Record<string, unknown>)[c])).join(','))].join('\n')
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
    if (from && to && from > to) return fail(400, 'invalid_range', 'The start date is after the end date.')
    const data = collect(ids as LogCategory[], from, to)
    const gaps = missing(ids as LogCategory[])
    audit('logs.export', ids.join(','), `${format}; ${Object.values(data).reduce((n, l) => n + l.length, 0)} rows${from ? `; from ${from}` : ''}${to ? `; to ${to}` : ''}`)
    const stamp = new Date().toISOString().slice(0, 10)
    const out = format === 'csv' ? toCsv(data, gaps) : JSON.stringify({ format: 'vedette-logs/1', exported_at: new Date().toISOString(), from, to, verification: CHAIN_NOTE, missing: gaps, categories: data }, null, 2)
    return new HttpResponse(out, { headers: { 'Content-Type': format === 'csv' ? 'text/csv' : 'application/json', 'Content-Disposition': `attachment; filename=vedette-logs-${stamp}.${format}` } })
  }),
]
