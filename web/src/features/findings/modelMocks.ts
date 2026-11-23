// Mock of the findings model API (contract.ts, "The findings model"): lists grouped by device and by fix, Needs your input,
// Handled, a finding's View, handling and Home. Rows live in fnd_finding_model and fnd_question, apart from findingsStore, which the
// finding page's detail (GET /findings/{id}) and the per-device list (GET /findings?asset=) read; a write on an id of findingsStore
// passes through to mocks.ts. Every string shown is English.
import { http, HttpResponse, type JsonBodyType } from 'msw'
import { API, audit, body, currentUser, fail, guard } from '@/mocks/http'
import { collection, newId, nowIso } from '@/mocks/db'
import { assetsStore, isOn } from '@/mocks/stores'
import { SAMPLE_SEVERITY, seedFindingRecords, seedQuestions, type FindingRecord, type QuestionRecord } from '@/mocks/seed/findings'
import type { Asset } from '@/lib/types'
import { displayName } from '@/features/inventory/nameOf'
import { metaStore } from '@/features/inventory/mocks'
import { openIncidents, sentSince } from '@/features/notify/mocks'
import { dayAfter, untilOk } from './accept'
import { OPEN_FINDING_STATUSES as OPEN_STATUSES, FINDING_RESOLUTIONS } from '@/lib/statusCodes'
import { FIRST_TOP, MAX_HANDLE, PAGE_DEFAULT, PAGE_MAX, TREND_DAYS } from './contract'
import type {
  CveRow, CveSeverity, DeviceCard, DeviceCards, DeviceRef, DeviceStatus, FixBlock, FixCard, FixCards, FixDevice, HandledList, HandledRow,
  InputItem, InputList, OpenStatus, Overview, Resolution, SeverityCounts, StatusCode, StatusCounts, View,
} from './types'

export const records = collection<FindingRecord[]>('fnd_finding_model', seedFindingRecords, () => [])
export const questions = collection<QuestionRecord[]>('fnd_question', seedQuestions, () => [])

/** CVEs the scan's safe checks cover (the sample ones). */
const SAFE_CHECKS = new Set(['CVE-2024-4577', 'CVE-2022-27593', 'CVE-2026-119977'])
const RESOLUTIONS: readonly Resolution[] = FINDING_RESOLUTIONS
const NOTE_NEEDED: Resolution[] = ['false_positive', 'not_relevant', 'accepted']

// ---- reading the rows

const assetOf = (id: string): Asset | undefined => assetsStore.get().find((a) => a.id === id)
const isIgnored = (id: string) => !!metaStore.get()[id]?.ignored_at
function deviceRef(a: Asset): DeviceRef {
  return { id: a.id, name: displayName(a) || a.software[0]?.display || a.ip || a.kind, ip: a.ip || null, kind: a.kind, added: a.approved, ignored: isIgnored(a.id) }
}
const severityOf = (cve: string): CveSeverity | null => SAMPLE_SEVERITY[cve] ?? null
const statusOf = (r: FindingRecord): StatusCode => (r.state === 'open' ? OPEN_STATUSES[r.layer - 1]! : r.resolution!)
const layerOf = (s: OpenStatus) => OPEN_STATUSES.indexOf(s) + 1
const SEV_RANK: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3, none: 4 }
const sevRank = (cve: string) => SEV_RANK[severityOf(cve)?.band ?? ''] ?? 5
/** Today on the calendar the last day of an accepted risk was chosen on (accept.ts). */
const today = () => dayAfter(new Date(), 0)

/** The box reopens an accepted risk the day after its last day. */
function expireAccepted() {
  const t = today()
  if (!records.get().some((r) => r.resolution === 'accepted' && r.accepted_until! < t)) return
  records.update((l) => l.map((r) => (r.resolution === 'accepted' && r.accepted_until! < t
    ? { ...r, ...unhandled, reopened: { why: 'acceptance_expired', at: nowIso() }, events: [...r.events, event('system', 'acceptance_expired')] } : r)))
}
const unhandled = { state: 'open' as const, resolution: null, via: null, resolved_by: null, resolved_at: null, note: null, accepted_until: null, from_version: null, to_version: null }
const event = (actor: string, kind: FindingRecord['events'][number]['kind'], extra: Partial<FindingRecord['events'][number]> = {}) =>
  ({ ts: nowIso(), actor, kind, layer: null, resolution: null, via: null, note: null, ...extra })

/** The rows on devices that still exist (a removed device takes its findings with it). */
function rows(): (FindingRecord & { asset: Asset })[] {
  expireAccepted()
  const byId = new Map(assetsStore.get().map((a) => [a.id, a]))
  return records.get().flatMap((r) => { const asset = byId.get(r.asset_id); return asset ? [{ ...r, asset }] : [] })
}
const openRows = (ignored = false) => rows().filter((r) => r.state === 'open' && isIgnored(r.asset_id) === ignored)

const cveRow = (r: FindingRecord): CveRow => ({ id: r.id, cve: r.cve, status: statusOf(r), severity: severityOf(r.cve), verified: r.verified, safe_check: SAFE_CHECKS.has(r.cve) })
const bySeverity = (a: FindingRecord, b: FindingRecord) => sevRank(a.cve) - sevRank(b.cve) || a.layer - b.layer || a.cve.localeCompare(b.cve)
function severityCounts(l: FindingRecord[]): SeverityCounts {
  const c: SeverityCounts = { critical: 0, high: 0, medium: 0, low: 0, none: 0, unscored: 0 }
  for (const r of l) c[severityOf(r.cve)?.band ?? 'unscored'] += 1
  return c
}
function statusCounts(l: FindingRecord[]): StatusCounts {
  const c = Object.fromEntries(OPEN_STATUSES.map((s) => [s, 0])) as StatusCounts
  for (const r of l) c[OPEN_STATUSES[r.layer - 1]!] += 1
  return c
}
const mostUrgent = (l: FindingRecord[]) => [...l].sort((a, b) => a.layer - b.layer || bySeverity(a, b))[0]!

function block(l: FindingRecord[]): FixBlock {
  const top = mostUrgent(l)
  return { fix: { ...top.fix }, software: top.software, status: OPEN_STATUSES[top.layer - 1]!, cause: top.cve, severity: severityCounts(l), findings: [...l].sort(bySeverity).map(cveRow) }
}
const groupBy = <T>(l: T[], key: (x: T) => string) => { const m = new Map<string, T[]>(); for (const x of l) m.set(key(x), [...(m.get(key(x)) ?? []), x]); return m }
/** Urgency first, then the most findings, then the name: the order of cards and blocks. */
const byUrgency = (a: { layer: number; n: number; name: string }, b: { layer: number; n: number; name: string }) => a.layer - b.layer || b.n - a.n || a.name.localeCompare(b.name)

/** The device badge: the most urgent open status with its distinct CVEs, else needs_input when only the queue has items for it. */
export function deviceStatus(assetId: string): DeviceStatus {
  const open = rows().filter((r) => r.asset_id === assetId && r.state === 'open')
  if (open.length) {
    const layer = Math.min(...open.map((r) => r.layer))
    return { code: OPEN_STATUSES[layer - 1]!, count: new Set(open.filter((r) => r.layer === layer).map((r) => r.cve)).size }
  }
  const n = inputItems().filter((i) => i.device.id === assetId).length
  return n ? { code: 'needs_input', count: n } : null
}

function card(asset: Asset, l: FindingRecord[]): DeviceCard {
  const blocks = [...groupBy(l, (r) => r.fix.key).values()].map(block)
    .sort((a, b) => byUrgency({ layer: layerOf(a.status), n: a.findings.length, name: a.fix.product }, { layer: layerOf(b.status), n: b.findings.length, name: b.fix.product }))
  return { device: deviceRef(asset), status: deviceStatus(asset.id), counts: statusCounts(l), findings: l.length, cves: new Set(l.map((r) => r.cve)).size, blocks }
}

function inputItems(): InputItem[] {
  const all = rows()
  const visible = (id: string) => !isIgnored(id)
  const notAdded = [...groupBy(all.filter((r) => r.state === 'open' && !r.asset.approved && visible(r.asset_id)), (r) => r.asset_id).values()]
    .map((l): InputItem => {
      const layer = Math.min(...l.map((r) => r.layer))
      return { kind: 'device_not_added', id: `device:${l[0]!.asset_id}`, device: deviceRef(l[0]!.asset), status: { code: OPEN_STATUSES[layer - 1]!, count: new Set(l.filter((r) => r.layer === layer).map((r) => r.cve)).size }, findings: l.length }
    })
  const unconfirmed = all.filter((r) => r.state === 'open' && r.layer <= 4 && r.verified === 'no' && visible(r.asset_id)).sort((a, b) => a.layer - b.layer || bySeverity(a, b))
    .map((r): InputItem => ({ kind: 'unconfirmed', id: r.id, cve: r.cve, device: deviceRef(r.asset), software: r.software, status: OPEN_STATUSES[r.layer - 1] as 'exploited',
      severity: severityOf(r.cve), basis: r.basis, safe_check: SAFE_CHECKS.has(r.cve) }))
  const assets = new Map(assetsStore.get().map((a) => [a.id, a]))
  const asked = questions.get().filter((x) => assets.has(x.asset_id) && visible(x.asset_id)).sort((a, b) => b.cves - a.cves || a.asked_at.localeCompare(b.asked_at))
    .map((x): InputItem => ({ kind: 'question', id: x.id, question: x.kind, device: deviceRef(assets.get(x.asset_id)!), software: x.software, cve: x.cve, cves: x.cves,
      asked_at: x.asked_at, url: x.url, command: x.command, choices: x.choices }))
  return [...notAdded, ...unconfirmed, ...asked]
}

function view(r: FindingRecord & { asset: Asset }): View {
  const same = rows().filter((x) => x.asset_id === r.asset_id && x.cve === r.cve && x.id !== r.id)
  return {
    id: r.id, cve: r.cve, device: deviceRef(r.asset), software: r.software, status: statusOf(r),
    urgency: { layer: r.layer, since: r.urgency_at, reasons: r.reasons, internet: r.internet },
    severity: severityOf(r.cve),
    verification: { verified: r.verified, basis: r.basis, by: r.verified_by, at: r.verified_at },
    handled: r.state === 'handled' ? { resolution: r.resolution!, via: r.via!, by: r.resolved_by!, at: r.resolved_at!, note: r.note, accepted_until: r.accepted_until, from_version: r.from_version, to_version: r.to_version } : null,
    reopened: r.state === 'open' ? r.reopened : null,
    fix: { ...r.fix },
    same_cve: same.map((x) => ({ id: x.id, software: x.software, status: statusOf(x) })),
    first_seen: r.first_seen, last_seen: r.last_seen, events: r.events,
  }
}

// ---- query parameters

class Bad { readonly res: Response; constructor(res: Response) { this.res = res } }
function page(p: URLSearchParams) {
  const o = p.get('offset'), l = p.get('limit')
  if (o !== null && !/^[0-9]{1,6}$/.test(o)) throw new Bad(fail(400, 'invalid', 'offset must be a whole number.'))
  if (l !== null && !/^[0-9]{1,3}$/.test(l)) throw new Bad(fail(400, 'invalid', 'limit must be a whole number.'))
  const limit = l === null ? PAGE_DEFAULT : Math.min(Math.max(Number(l), 1), PAGE_MAX)
  return <T>(items: T[]) => items.slice(Number(o ?? 0), Number(o ?? 0) + limit)
}
function list<T extends string>(p: URLSearchParams, name: string, allowed: readonly T[]): T[] | null {
  const v = p.get(name)
  if (v === null || v === '') return null
  const parts = v.split(',').map((x) => x.trim())
  const bad = parts.find((x) => !allowed.includes(x as T))
  if (bad !== undefined) throw new Bad(fail(400, 'bad_filter', `"${bad}" is not a ${name} Vedette knows.`))
  return parts as T[]
}
const matches = (r: FindingRecord & { asset: Asset }, q: string) => !q || [deviceRef(r.asset).name, r.asset.ip, r.software?.name, r.cve, r.fix.product].some((x) => x?.toLowerCase().includes(q))
const query = (req: Request) => new URL(req.url).searchParams
/** The open rows the By device and By fix lists group, after the search and the status filter: both lists and Home count the same rows. */
function filtered(p: URLSearchParams, ignored = false) {
  const q = (p.get('q') ?? '').trim().toLowerCase()
  const status = list(p, 'status', OPEN_STATUSES)
  return openRows(ignored).filter((r) => matches(r, q) && (!status || status.includes(OPEN_STATUSES[r.layer - 1]!)))
}
function read(fn: () => JsonBodyType) {
  const denied = guard('viewer'); if (denied) return denied
  try { return HttpResponse.json(fn()) } catch (e) { if (e instanceof Bad) return e.res; throw e }
}

export function deviceCards(p: URLSearchParams): DeviceCards {
  const slice = page(p)
  const device = p.get('device')
  const l = filtered(p, p.get('ignored') === 'true').filter((r) => !device || r.asset_id === device)
  const cards = [...groupBy(l, (r) => r.asset_id).values()].map((g) => card(g[0]!.asset, g))
    .sort((a, b) => byUrgency({ layer: Math.min(...a.blocks.map((x) => layerOf(x.status))), n: a.findings, name: a.device.name }, { layer: Math.min(...b.blocks.map((x) => layerOf(x.status))), n: b.findings, name: b.device.name }))
  return { items: slice(cards), total: cards.length, findings: l.length }
}

export function fixCards(p: URLSearchParams): FixCards {
  const slice = page(p)
  const l = filtered(p)
  const cards = [...groupBy(l, (r) => r.fix.key).values()].map((g): FixCard => {
    const top = mostUrgent(g)
    const items = [...groupBy(g, (r) => r.asset_id).values()].map((d): FixDevice => ({ device: deviceRef(d[0]!.asset), software: mostUrgent(d).software, status: OPEN_STATUSES[mostUrgent(d).layer - 1]!, severity: severityCounts(d), findings: d.length }))
      .sort((a, b) => byUrgency({ layer: layerOf(a.status), n: a.findings, name: a.device.name }, { layer: layerOf(b.status), n: b.findings, name: b.device.name }))
    return { fix: { ...top.fix }, status: OPEN_STATUSES[top.layer - 1]!, cause: top.cve, devices: items.length, findings: g.length, severity: severityCounts(g), items }
  }).sort((a, b) => byUrgency({ layer: layerOf(a.status), n: a.findings, name: a.fix.product }, { layer: layerOf(b.status), n: b.findings, name: b.fix.product }))
  return { items: slice(cards), total: cards.length, findings: l.length }
}

function handledList(p: URLSearchParams): HandledList {
  const slice = page(p)
  const q = (p.get('q') ?? '').trim().toLowerCase()
  const res = list(p, 'resolution', RESOLUTIONS)
  const device = p.get('device'), from = p.get('from'), to = p.get('to')
  const utc = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?Z$/
  if (from !== null && !utc.test(from)) throw new Bad(fail(400, 'bad_from', 'Give the start as a time in UTC, like 2026-11-20T00:00:00Z.'))
  if (to !== null && !utc.test(to)) throw new Bad(fail(400, 'bad_to', 'Give the end as a time in UTC, like 2026-11-20T23:59:59Z.'))
  const l = rows().filter((r) => r.state === 'handled' && !isIgnored(r.asset_id) && matches(r, q) && (!res || res.includes(r.resolution!)) && (!device || r.asset_id === device)
    && (!from || r.resolved_at! >= from) && (!to || r.resolved_at! <= to))
    .sort((a, b) => b.resolved_at!.localeCompare(a.resolved_at!) || a.id.localeCompare(b.id))
  return { items: slice(l.map((r): HandledRow => ({ id: r.id, cve: r.cve, device: deviceRef(r.asset), software: r.software, status: r.resolution!, severity: severityOf(r.cve), handled: view(r).handled! }))), total: l.length }
}

export function overview(): Overview {
  const open = openRows()
  const assets = assetsStore.get().filter((a) => !isIgnored(a.id))
  const byStatus = { under_attack: 0, exploited: 0, public_exploit: 0, critical_edge: 0, update_recommended: 0, needs_input: 0 }
  for (const a of assets) { const s = deviceStatus(a.id); if (s) byStatus[s.code] += 1 }
  const first = [...groupBy(open, (r) => `${r.asset_id}\n${r.fix.key}`).values()].map((g) => ({ device: deviceRef(g[0]!.asset), block: block(g) }))
    .sort((a, b) => byUrgency({ layer: layerOf(a.block.status), n: a.block.findings.length, name: a.device.name }, { layer: layerOf(b.block.status), n: b.block.findings.length, name: b.device.name }))
    .slice(0, FIRST_TOP)
  // Open at the end of each day: opened by then and not handled by then (the sample keeps no older reopenings).
  const all = rows().filter((r) => !isIgnored(r.asset_id))
  const trend = Array.from({ length: TREND_DAYS }, (_, i) => {
    if (i === TREND_DAYS - 1) return open.length
    const end = new Date(Date.now() - (TREND_DAYS - 1 - i) * 864e5).toISOString()
    return all.filter((r) => r.first_seen <= end && (r.state === 'open' || r.resolved_at! > end)).length
  })
  const notifyOn = isOn('notify')
  return {
    open: { findings: open.length, by_status: statusCounts(open) },
    devices: { total: assets.length, not_added: assets.filter((a) => !a.approved).length, by_status: byStatus },
    input: inputItems().length,
    first, trend,
    alerts: notifyOn ? { ...sentSince(new Date(Date.now() - 7 * 864e5).toISOString()), days: 7 } : null,
    incidents: notifyOn ? openIncidents() : null,
    generated_at: nowIso(),
  }
}

// ---- writes

const who = () => currentUser()!.email
function patch(ids: string[], fn: (r: FindingRecord) => FindingRecord) {
  records.update((l) => l.map((r) => (ids.includes(r.id) ? fn(r) : r)))
}
const one = (id: string) => rows().find((r) => r.id === id)

interface HandleBody { ids: string[]; device: string; fix: string; software?: string; resolution: Resolution; note: string; until: string }

/** Handlers of the findings model; listed before the older /findings/:id routes so that /findings/devices and the rest are not read as ids. */
export const modelHandlers = [
  http.get(`${API}/findings/devices`, ({ request }) => read(() => deviceCards(query(request)))),
  http.get(`${API}/findings/fixes`, ({ request }) => read(() => fixCards(query(request)))),
  http.get(`${API}/findings/input`, ({ request }) => read(() => {
    const p = query(request)
    const slice = page(p)
    const device = p.get('device')
    const items = inputItems().filter((i) => !device || i.device.id === device)
    return { items: slice(items), total: items.length } satisfies InputList
  })),
  http.get(`${API}/findings/handled`, ({ request }) => read(() => handledList(query(request)))),
  http.get(`${API}/findings/overview`, () => read(overview)),
  http.get(`${API}/findings/:id/view`, ({ params }) => {
    const denied = guard('viewer'); if (denied) return denied
    const r = one(String(params.id))
    return r ? HttpResponse.json(view(r)) : fail(404, 'not_found', 'This finding does not exist.')
  }),

  http.post(`${API}/findings/handle`, async ({ request }) => {
    const denied = guard('operator'); if (denied) return denied
    const b = await body<HandleBody>(request.clone())
    if (Array.isArray(b.ids) && b.ids.length && !b.ids.some((id) => records.get().some((r) => r.id === id))) return undefined // the finding page's older ids: mocks.ts
    if (!RESOLUTIONS.includes(b.resolution as Resolution) || (b.note !== undefined && (typeof b.note !== 'string' || b.note.length > 500))) return fail(400, 'invalid', 'The request is not valid.')
    const byIds = b.ids !== undefined, byFix = b.device !== undefined || b.fix !== undefined
    if (byIds === byFix || (byFix && (!b.device || !b.fix)) || (byIds && (!Array.isArray(b.ids) || b.ids.length < 1 || b.ids.length > MAX_HANDLE)))
      return fail(400, 'bad_target', `Choose the findings: up to ${MAX_HANDLE} ids, or a device and one of its fixes.`)
    const all = rows()
    const target = byIds ? b.ids!.map((id) => all.find((r) => r.id === id)) : all.filter((r) => r.asset_id === b.device && r.fix.key === b.fix && (r.software?.id ?? undefined) === (b.software || undefined) && r.state === 'open')
    if (!target.length || target.some((r) => !r)) return fail(404, 'not_found', byIds ? 'A finding in the list does not exist.' : 'This device has no open finding for this fix.')
    const found = target as (FindingRecord & { asset: Asset })[]
    if (new Set(found.map((r) => r.asset_id)).size > 1) return fail(400, 'many_devices', 'Mark findings of one device at a time.')
    const note = (b.note ?? '').trim()
    const resolution = b.resolution!
    if (NOTE_NEEDED.includes(resolution) && note.length < 3) return fail(400, 'note_required', 'Write why this is a false positive, not relevant or an accepted risk (at least 3 characters) so the next person understands.')
    if (resolution === 'accepted' ? !untilOk(String(b.until ?? '')) : b.until !== undefined) return fail(400, 'bad_until', 'Accept the risk until a date from tomorrow up to one year from today.')
    const until = resolution === 'accepted' ? b.until! : null
    const change = found.filter((r) => !(r.state === 'handled' && r.resolution === resolution && r.accepted_until === until))
    const user = who(), at = nowIso()
    patch(change.map((r) => r.id), (r) => ({ ...r, state: 'handled', resolution, via: 'person', resolved_by: user, resolved_at: at, note: note || null, accepted_until: until,
      from_version: null, to_version: null, reopened: null, events: [...r.events, event(user, 'handled', { resolution, via: 'person', note: note || null })] }))
    for (const r of change) audit('findings.handle', r.id, `${r.cve} ${resolution}${until ? ` until ${until}` : ''}${note ? `: ${note}` : ''}`)
    return HttpResponse.json({ handled: change.length, skipped: found.length - change.length })
  }),

  http.post(`${API}/findings/:id/reopen`, async ({ params, request }) => {
    const denied = guard('operator'); if (denied) return denied
    const r = one(String(params.id))
    if (!r) return undefined // not a row of this store: mocks.ts answers (the finding page's older ids, or 404)
    const b = await body<{ note: string }>(request)
    if (b.note !== undefined && (typeof b.note !== 'string' || b.note.length > 500)) return fail(400, 'invalid', 'The request is not valid.')
    if (r.state === 'open') return fail(409, 'already_open', 'This finding is already open.')
    const note = (b.note ?? '').trim() || null
    patch([r.id], (x) => ({ ...x, ...unhandled, reopened: null, events: [...x.events, event(who(), 'reopened', { note })] }))
    audit('findings.reopen', r.id, `${r.cve}${note ? `: ${note}` : ''}`)
    return HttpResponse.json(view(one(r.id)!))
  }),

  http.post(`${API}/findings/:id/verify`, async ({ params, request }) => {
    const denied = guard('admin'); if (denied) return denied
    const r = one(String(params.id))
    if (!r) return undefined // not a row of this store: mocks.ts answers (the finding page's older ids, or 404)
    const b = await body<{ note: string }>(request)
    if (typeof b.note !== 'string' || b.note.length > 500) return fail(400, 'invalid', 'The request is not valid.')
    const note = b.note.trim()
    if (note.length < 3) return fail(400, 'confirm_note_required', 'Write what makes you sure (at least 3 characters) so the next person understands.')
    if (r.verified !== 'no') return fail(409, 'already_verified', 'This finding is already confirmed.')
    const user = who()
    patch([r.id], (x) => ({ ...x, verified: 'person', verified_by: user, verified_at: nowIso(), events: [...x.events, event(user, 'confirmed', { note })] }))
    audit('findings.verify', r.id, `${r.cve}: ${note}`)
    return HttpResponse.json(view(one(r.id)!))
  }),

  http.post(`${API}/findings/:id/unverify`, ({ params }) => {
    const denied = guard('admin'); if (denied) return denied
    const r = one(String(params.id))
    if (!r) return undefined // not a row of this store: mocks.ts answers (the finding page's older ids, or 404)
    if (r.verified !== 'person') return fail(409, 'not_confirmed_by_person', 'Only a confirmation a person made can be undone; a scan or the device itself confirmed this one.')
    const user = who()
    patch([r.id], (x) => ({ ...x, verified: 'no', verified_by: null, verified_at: null, events: [...x.events, event(user, 'unconfirmed')] }))
    audit('findings.unconfirm', r.id, `${r.cve}: confirmation undone by ${user}`)
    return HttpResponse.json(view(one(r.id)!))
  }),

  http.post(`${API}/findings/questions/:id/answer`, async ({ params, request }) => {
    const denied = guard('operator'); if (denied) return denied
    const x = questions.get().find((q) => q.id === String(params.id))
    const asset = x && assetOf(x.asset_id)
    if (!x || !asset) return fail(404, 'not_found', 'This question does not exist or was already answered.')
    const b = await body<{ answer: string; note: string }>(request)
    if ((b.answer !== 'affected' && b.answer !== 'not_affected') || typeof b.note !== 'string' || b.note.length > 500) return fail(400, 'invalid', 'The request is not valid.')
    // affected records a finding confirmed by a person: the same role as Confirm vulnerability
    if (b.answer === 'affected') { const admin = guard('admin'); if (admin) return admin }
    if (!x.cve) return fail(409, 'not_one_cve', 'This question decides several CVEs: correct the software on the device (its version) instead.')
    const note = b.note.trim()
    if (b.answer === 'not_affected' && note.length < 3) return fail(400, 'note_required', 'Write why this device is not affected (at least 3 characters) so the next person understands.')
    const user = who(), at = nowIso()
    let finding: string | null = null
    if (b.answer === 'affected') {
      finding = newId('fv')
      const id = finding
      records.update((l) => [...l, {
        id, asset_id: x.asset_id, cve: x.cve!, software: x.software, verified: 'person', basis: 'person', verified_by: user, verified_at: at,
        fix: { key: `${x.software?.name.toLowerCase() ?? 'unknown'}|unknown|`, kind: 'unknown', product: x.software?.name ?? x.cve!, version: null, ref: null, url: x.url },
        ...unhandled, layer: 5, urgency_at: at, reasons: [], internet: null, first_seen: at, last_seen: at, reopened: null,
        events: [event(user, 'created', { note: note || null }), event(user, 'confirmed', { note: note || null })],
      }])
    }
    questions.update((l) => l.filter((q) => q.id !== x.id))
    audit('findings.answer', x.id, `${x.cve} ${b.answer}${note ? `: ${note}` : ''}`)
    return HttpResponse.json({ finding })
  }),
]
