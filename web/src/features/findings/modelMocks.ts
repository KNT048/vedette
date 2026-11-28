// Mock of the findings model API (contract.ts, "The findings model"): lists grouped by device and by fix, the possible findings
// (possibleMocks.ts), the older Needs your input queue,
// Handled, a finding's View, handling and Home. Rows live in fnd_finding_model and fnd_question, apart from findingsStore, which the
// finding page's detail (GET /findings/{id}) and the per-device list (GET /findings?asset=) read; a write on an id of findingsStore
// passes through to mocks.ts. Every string shown is English.
import { http, HttpResponse, type JsonBodyType } from 'msw'
import { API, audit, body, currentUser, fail, guard } from '@/mocks/http'
import { collection, newId, nowIso } from '@/mocks/db'
import { dayOf } from '@/lib/format'
import { assetsStore, isOn } from '@/mocks/stores'
import { SAMPLE_SEVERITY, seedFindingRecords, seedQuestions, type FindingRecord, type QuestionRecord } from '@/mocks/seed/findings'
import type { Asset } from '@/lib/types'
import { displayName } from '@/features/inventory/nameOf'
import { BOX_ID, isQuiet, metaStore, stateOf } from '@/features/inventory/mocks'
import { openIncidents, sentSince } from '@/features/notify/mocks'
import { dayAfter, untilOk } from './accept'
import { checkOfQuestion, possibleCounts } from './possibleMocks'
import { OPEN_FINDING_STATUSES as OPEN_STATUSES, FINDING_RESOLUTIONS } from '@/lib/statusCodes'
import { FIRST_TOP, MAX_HANDLE, PAGE_DEFAULT, PAGE_MAX, TREND_DAYS } from './contract'
import type {
  Coverage, CveRow, CveSeverity, DeviceCard, DeviceCards, DeviceRef, DeviceStatus, FixBlock, FixCard, FixCards, FixDevice, HandledList, HandledRow,
  AnsweredList, AnsweredQuestion, InputGroupItem, InputItem, InputList, InputQuestionItem, InputUncheckedItem, InputUnconfirmedItem, OpenStatus, Overview, Resolution, SeverityCounts, StatusCode, StatusCounts, View, PossibleCheckState, PossibleList,
} from './types'

export const records = collection<FindingRecord[]>('fnd_finding_model', seedFindingRecords, () => [])
export const questions = collection<QuestionRecord[]>('fnd_question', seedQuestions, () => [])

/** CVEs the scan's safe checks cover (the sample ones). */
const SAFE_CHECKS = new Set(['CVE-2024-4577', 'CVE-2022-27593', 'CVE-2026-119977'])
/** What a vulnerability check of the device can do (the box's scan checkCount, read by GET /scans/targets): its open findings not
 *  confirmed yet (distinct CVEs), how many of those have a safe check, and how many confirmed ones have one to run again. */
export function checkCounts(assetId: string): { suspected: number; checkable: number; again: number } {
  const seen = new Set<string>()
  const c = { suspected: 0, checkable: 0, again: 0 }
  for (const r of records.get()) {
    if (r.asset_id !== assetId || r.state !== 'open' || seen.has(r.cve)) continue
    seen.add(r.cve)
    const safe = SAFE_CHECKS.has(r.cve)
    if (r.verified === 'no') { c.suspected++; if (safe) c.checkable++ } else if (safe) c.again++
  }
  return c
}
const RESOLUTIONS: readonly Resolution[] = FINDING_RESOLUTIONS
const NOTE_NEEDED: Resolution[] = ['false_positive', 'not_relevant', 'accepted']

// ---- reading the rows

export const assetOf = (id: string): Asset | undefined => assetsStore.get().find((a) => a.id === id)
export const isIgnored = (id: string) => !!metaStore.get()[id]?.ignored_at
export function deviceRef(a: Asset): DeviceRef {
  return { id: a.id, name: displayName(a) || a.software[0]?.display || a.ip || a.kind, ip: a.ip || null, kind: a.kind, added: a.approved, ignored: isIgnored(a.id) }
}
export const severityOf = (cve: string): CveSeverity | null => SAMPLE_SEVERITY[cve] ?? null
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
    ? { ...r, ...unhandled, reopened: { why: 'acceptance_expired', at: nowIso(), by: null }, events: [...r.events, event('system', 'acceptance_expired')] } : r)))
}
export const unhandled = { state: 'open' as const, resolution: null, via: null, resolved_by: null, resolved_at: null, note: null, accepted_until: null, from_version: null, to_version: null }
export const event = (actor: string, kind: FindingRecord['events'][number]['kind'], extra: Partial<FindingRecord['events'][number]> = {}) =>
  ({ ts: nowIso(), actor, kind, layer: null, resolution: null, via: null, note: null, ...extra })

/** The rows on devices that still exist (a removed device takes its findings with it). */
function rows(): (FindingRecord & { asset: Asset })[] {
  expireAccepted()
  const byId = new Map(assetsStore.get().map((a) => [a.id, a]))
  return records.get().flatMap((r) => { const asset = byId.get(r.asset_id); return asset ? [{ ...r, asset }] : [] })
}
const openRows = (ignored = false) => rows().filter((r) => r.state === 'open' && isIgnored(r.asset_id) === ignored)

const cveRow = (r: FindingRecord): CveRow => ({ id: r.id, cve: r.cve, status: statusOf(r), severity: severityOf(r.cve), verified: r.verified, safe_check: SAFE_CHECKS.has(r.cve),
  urgency: { layer: r.layer, since: r.urgency_at, reasons: r.reasons, internet: r.internet },
  verification: { verified: r.verified, basis: r.basis, by: r.verified_by, at: r.verified_at } })
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
  return { fix: { channel: 'public' as const, ...top.fix }, software: top.software, status: OPEN_STATUSES[top.layer - 1]!, cause: top.cve, severity: severityCounts(l), findings: [...l].sort(bySeverity).map(cveRow) }
}
const groupBy = <T>(l: T[], key: (x: T) => string) => { const m = new Map<string, T[]>(); for (const x of l) m.set(key(x), [...(m.get(key(x)) ?? []), x]); return m }
/** Urgency first, then the most findings, then the name: the order of cards and blocks. */
const byUrgency = (a: { layer: number; n: number; name: string }, b: { layer: number; n: number; name: string }) => a.layer - b.layer || b.n - a.n || a.name.localeCompare(b.name)

/** The device badge: the most urgent open status with its distinct CVEs, else possible with its possible CVEs. */
export function deviceStatus(assetId: string): DeviceStatus {
  const open = rows().filter((r) => r.asset_id === assetId && r.state === 'open')
  if (open.length) {
    const layer = Math.min(...open.map((r) => r.layer))
    return { code: OPEN_STATUSES[layer - 1]!, count: new Set(open.filter((r) => r.layer === layer).map((r) => r.cve)).size }
  }
  const n = possibleCounts(assetId).possible
  return n ? { code: 'possible', count: n } : null
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
  // the devices of To review with no open finding: one card for all of them, last, as the server lists it
  const withFindings = new Set(all.filter((r) => r.state === 'open').map((r) => r.asset_id))
  const rest = assetsStore.get().filter((a) => !a.approved && a.id !== BOX_ID && visible(a.id) && !isQuiet(a) && !withFindings.has(a.id)).length
  const group: InputItem[] = rest > 0 ? [{ kind: 'devices_not_added', id: 'devices_not_added', count: rest }] : []
  const unconfirmed = all.filter((r) => r.state === 'open' && r.layer <= 4 && r.verified === 'no' && visible(r.asset_id)).sort((a, b) => a.layer - b.layer || bySeverity(a, b))
    .map((r): InputUnconfirmedItem => ({ kind: 'unconfirmed', id: r.id, cve: r.cve, device: deviceRef(r.asset), software: r.software, status: OPEN_STATUSES[r.layer - 1] as 'exploited',
      severity: severityOf(r.cve), basis: r.basis, safe_check: SAFE_CHECKS.has(r.cve) }))
  const assets = new Map(assetsStore.get().map((a) => [a.id, a]))
  const asked = questions.get().filter((x) => !x.answered && assets.has(x.asset_id) && visible(x.asset_id)).sort((a, b) => b.cves - a.cves || a.asked_at.localeCompare(b.asked_at))
    .map((x): InputQuestionItem => ({ kind: 'question', id: x.id, question: x.kind, device: deviceRef(assets.get(x.asset_id)!), software: x.software, cve: x.cve, cves: x.cves,
      asked_at: x.asked_at, url: x.url, command: x.command, choices: x.choices, cve_list: x.cve_list ?? [], fixes: x.fixes ?? [], line: x.line ?? null,
      versions_listed: x.versions_listed ?? false, attribute: x.attribute ?? null }))
  // a device a person added that Vedette knows nothing to check by: no installed software line and no OS beyond a scan's fingerprint guess
  const unchecked = assetsStore.get().filter((a) => a.approved && a.id !== BOX_ID && visible(a.id) && !(a.origin === 'manual' && !a.hostname && !a.ip) &&
    !a.software.some((s) => !s.not_installed) && (!a.os || (a.os.source === 'nmap' && !a.os.value.includes('(build '))))
    .map((a): InputUncheckedItem => ({ kind: 'device_unchecked', id: `unchecked:${a.id}`, device: deviceRef(a) }))
  return [...notAdded, ...groupNeeds([...unchecked, ...unconfirmed, ...asked]), ...group]
}

/** One card per device: its questions grouped by software line (the CVEs of a line counted once), with its unconfirmed findings and its
 *  "cannot check" item, as the server groups the queue. */
function groupNeeds(items: (InputQuestionItem | InputUnconfirmedItem | InputUncheckedItem)[]): InputItem[] {
  const cards = new Map<string, Extract<InputItem, { kind: 'device_needs' }>>()
  const lines = new Map<string, { g: InputGroupItem; cves: Set<string> }>()
  const card = (d: DeviceRef) => {
    let c = cards.get(d.id)
    if (!c) { c = { kind: 'device_needs', id: `needs:${d.id}`, device: d, entries: [] }; cards.set(d.id, c) }
    return c
  }
  for (const it of items) {
    const c = card(it.device)
    if (it.kind !== 'question') { c.entries.push(it); continue }
    const key = it.software ? `${it.device.id}|${it.software.id}` : it.id
    let l = lines.get(key)
    if (!l) {
      l = { g: { kind: 'software_group', id: `sw:${it.software?.id ?? it.id}`, software: it.software, cves: 0, questions: [] }, cves: new Set() }
      lines.set(key, l)
      c.entries.push(l.g)
    }
    if (it.cve) l.cves.add(it.cve)
    for (const v of it.cve_list) l.cves.add(v)
    if (!it.cve && !it.cve_list.length) l.g.cves += Math.max(it.cves, 1)
    l.g.questions.push(it)
  }
  for (const l of lines.values()) l.g.cves = Math.max(l.g.cves + l.cves.size, 1)
  const order = ['version_needed', 'not_comparable', 'platform', 'package_release', 'older_line', 'no_range_data']
  for (const l of lines.values()) l.g.questions.sort((a, b) => order.indexOf(a.question) - order.indexOf(b.question) || b.cves - a.cves)
  return [...cards.values()]
}

function view(r: FindingRecord & { asset: Asset }): View {
  const same = rows().filter((x) => x.asset_id === r.asset_id && x.cve === r.cve && x.id !== r.id)
  return {
    id: r.id, cve: r.cve, device: deviceRef(r.asset), software: r.software, status: statusOf(r),
    urgency: { layer: r.layer, since: r.urgency_at, reasons: r.reasons, internet: r.internet },
    severity: severityOf(r.cve),
    verification: { verified: r.verified, basis: r.basis, by: r.verified_by, at: r.verified_at },
    handled: r.state === 'handled' ? { resolution: r.resolution!, via: r.via!, by: r.resolved_by!, at: r.resolved_at!, note: r.note, accepted_until: r.accepted_until, from_version: r.from_version, to_version: r.to_version } : null,
    reopened: r.state === 'open' && r.reopened ? { by: null, ...r.reopened } : null,
    fix: { channel: 'public' as const, ...r.fix },
    same_cve: same.map((x) => ({ id: x.id, software: x.software, status: statusOf(x) })),
    first_seen: r.first_seen, last_seen: r.last_seen, events: r.events, ai_check: r.ai_check ?? null, identity: r.identity ?? null,
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
  const device = p.get('device'), cve = p.get('cve'), devices = p.get('devices')?.split(',')
  if (devices && devices.length > PAGE_MAX) throw new Bad(fail(400, 'bad_filter', 'The filter has a value the list does not know.'))
  const l = filtered(p, p.get('ignored') === 'true').filter((r) => (!device || r.asset_id === device) && (!cve || r.cve === cve) && (!devices || devices.includes(r.asset_id)))
  const cards = [...groupBy(l, (r) => r.asset_id).values()].map((g) => card(g[0]!.asset, g))
    .sort((a, b) => byUrgency({ layer: Math.min(...a.blocks.map((x) => layerOf(x.status))), n: a.findings, name: a.device.name }, { layer: Math.min(...b.blocks.map((x) => layerOf(x.status))), n: b.findings, name: b.device.name }))
  return { items: slice(cards), total: cards.length, findings: l.length }
}

export function fixCards(p: URLSearchParams): FixCards {
  const slice = page(p)
  const l = filtered(p)
  const cards = [...groupBy(l, (r) => r.fix.key).values()].map((g): FixCard => {
    const top = mostUrgent(g)
    const others = (d: typeof g) => { // the line's other steps, the most findings first, as the backend's otherSteps
      const sw = mostUrgent(d).software?.id
      const rest = sw ? l.filter((r) => r.asset_id === d[0]!.asset_id && r.software?.id === sw && r.fix.key !== top.fix.key) : []
      return [...groupBy(rest, (r) => r.fix.key).values()].sort((a, b) => b.length - a.length || a[0]!.fix.key.localeCompare(b[0]!.fix.key)).map((x) => ({ channel: 'public' as const, ...x[0]!.fix }))
    }
    const items = [...groupBy(g, (r) => r.asset_id).values()].map((d): FixDevice => ({ device: deviceRef(d[0]!.asset), software: mostUrgent(d).software, status: OPEN_STATUSES[mostUrgent(d).layer - 1]!, severity: severityCounts(d), findings: d.length, others: others(d) }))
      .sort((a, b) => byUrgency({ layer: layerOf(a.status), n: a.findings, name: a.device.name }, { layer: layerOf(b.status), n: b.findings, name: b.device.name }))
    return { fix: { channel: 'public' as const, ...top.fix }, status: OPEN_STATUSES[top.layer - 1]!, cause: top.cve, devices: items.length, findings: g.length, severity: severityCounts(g), items }
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
  // Vedette's corrections of its own match are left out unless asked for, and counted either way (the backend's HandledFilter.Corrections)
  const correction = (r: (typeof l)[number]) => r.via === 'data_corrected' && r.resolved_by === 'system'
  const corrections = l.filter(correction).length
  const shown = p.get('corrections') === 'true' ? l : l.filter((r) => !correction(r))
  return { items: slice(shown.map((r): HandledRow => ({ id: r.id, cve: r.cve, device: deviceRef(r.asset), software: r.software, status: r.resolution!, severity: severityOf(r.cve), handled: view(r).handled! }))), total: shown.length, corrections }
}

export function overview(): Overview {
  const open = openRows()
  const assets = assetsStore.get().filter((a) => !isIgnored(a.id))
  const byStatus = { under_attack: 0, exploited: 0, public_exploit: 0, critical_edge: 0, update_recommended: 0, possible: 0 }
  for (const a of assets) { const s = deviceStatus(a.id); if (s) byStatus[s.code] += 1 }
  // devices with open findings by their most urgent status, the box included (it carries no badge on the real box)
  const affected = statusCounts([...groupBy(open, (r) => r.asset_id).values()].map(mostUrgent))
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
    // the state rule (inventory DeviceCounts): the added devices the Devices list holds, and the To review count
    devices: { total: assets.filter((a) => stateOf(a) === 'added').length, not_added: assets.filter((a) => stateOf(a) === 'review').length, by_status: byStatus, affected },
    input: inputItems().filter((i) => i.kind !== 'devices_not_added').length,
    possible: possibleCounts(),
    first, trend, trend_start: dayOf(new Date(Date.now() - (TREND_DAYS - 1) * 864e5).toISOString()),
    alerts: notifyOn ? { ...sentSince(new Date(Date.now() - 7 * 864e5).toISOString()), days: 7 } : null,
    incidents: notifyOn ? openIncidents() : null,
    first_run_summary: null, // the sample box has sent no first-run summary
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
    const q = (p.get('q') ?? '').trim().toLowerCase()
    // the server's search: the device's name or address, the software's name or the CVE id contains q
    const has = (v?: string | null) => !!v && v.toLowerCase().includes(q)
    // the grouped card names no device: not in a queue of one device or a search
    const inside = (item: object): boolean => {
      const e = item as { software?: { name: string } | null; cve?: string | null; questions?: object[]; entries?: object[] }
      return has(e.software?.name) || has(e.cve) || !!e.questions?.some(inside) || !!e.entries?.some(inside)
    }
    const items = inputItems().filter((i) => i.kind === 'devices_not_added' ? !device && !q : (!device || i.device.id === device)
      && (!q || has(i.device.name) || has(i.device.ip) || inside(i)))
    return { items: slice(items), total: items.length } satisfies InputList
  })),
  http.get(`${API}/findings/handled`, ({ request }) => read(() => handledList(query(request)))),
  http.get(`${API}/findings/overview`, () => read(overview)),
  // possible findings: the sample box has none yet, and no AI profile to check them with
  http.get(`${API}/findings/possible`, () => read(() => ({ items: [], total: 0, counts: { possible: 0, older_build: 0, proposals: 0, unchecked: 0, settled: 0, causes: { vendor_silent: 0, page_unreadable: 0, needs_reading: 0, ai_unsure: 0, ai_budget: 0, identity_unproven: 0, version_needed: 0, pending_nvd: 0, needs_person: 0 } } }) satisfies PossibleList)),
  http.get(`${API}/findings/possible/audit`, () => read(() => ({ groups: [] }))),
  // Settings → Diagnostics: the coverage of the sample box's last match pass (illustrative counts)
  http.get(`${API}/findings/coverage`, () => guard('admin') ?? HttpResponse.json({
    at: nowIso(), devices: 12, lines: 2140, pairs: 47940, outside_window: 3,
    decided: [{ by: 'distro', affected: 412, not_affected: 39870 }, { by: 'nvd', affected: 96, not_affected: 5310 }, { by: 'cna', affected: 21, not_affected: 1288 },
      { by: 'vendor_line', affected: 6, not_affected: 64 }, { by: 'person', affected: 2, not_affected: 11 }, { by: 'platform_list', affected: 0, not_affected: 9 }],
    possible: [
      { cause: 'version_needed', count: 418, details: [{ detail: 'no_version', count: 402 }, { detail: 'platform_unknown', count: 16 }] },
      { cause: 'needs_reading', count: 402, details: [{ detail: 'version_scheme_mismatch', count: 211 }, { detail: 'exact_releases_only', count: 117 }, { detail: 'product_not_named', count: 74 }] },
      { cause: 'other_distro_silent', count: 31, details: [] },
    ],
    identity: [{ method: 'stated', lines: 1795 }, { method: 'catalogue', lines: 61 }, { method: 'record', lines: 23 }, { method: 'ai', lines: 49 }, { method: 'ai_family', lines: 5 }, { method: 'none', lines: 207 }],
  } satisfies Coverage)),
  http.get(`${API}/findings/possible/check`, () => read(() => ({ ready: false, reason: 'The preview has no AI profile to check possible findings with.', run: null }) satisfies PossibleCheckState)),
  http.post(`${API}/findings/possible/check`, () => guard('operator') ?? fail(409, 'ai_unavailable', 'The preview has no AI profile to check possible findings with.')),
  http.post(`${API}/findings/possible/confirm`, () => guard('operator') ?? HttpResponse.json({ confirmed: 0 })),
  http.post(`${API}/findings/possible/:id/confirm`, () => guard('operator') ?? fail(404, 'not_found', 'No such proposal: it was answered, rejected or the evidence changed.')),
  http.post(`${API}/findings/possible/checks/:key/reject`, () => guard('operator') ?? fail(404, 'not_found', 'No such proposal: it was answered, rejected or the evidence changed.')),
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

  // Not this product: every open finding resting on the same AI identification of the same software closes as the person's correction
  http.post(`${API}/findings/:id/identity/reject`, ({ params }) => {
    const denied = guard('operator'); if (denied) return denied
    const r = one(String(params.id))
    if (!r?.identity) return fail(404, 'not_found', 'This finding does not rest on the AI\'s identification of its software.')
    const same = (x: FindingRecord) => x.state === 'open' && x.identity?.product === r.identity!.product && x.identity.vendor === r.identity!.vendor && x.software?.name === r.software?.name
    const ids = rows().filter(same).map((x) => x.id)
    const user = who(), at = nowIso()
    patch(ids, (x) => ({ ...x, state: 'handled', resolution: 'not_relevant', via: 'data_corrected', resolved_by: user, resolved_at: at,
      events: [...x.events, event(user, 'handled', { note: `A person said this software is not ${r.identity!.title}.` })] }))
    if (ids.length) audit('findings.ai_identity_rejected', r.id, `${r.cve}: the software "${r.software?.name ?? ''}" is not ${r.identity.title} (${r.identity.vendor}:${r.identity.product}), as the AI chose; applies to every device with it`)
    return HttpResponse.json({ ok: true })
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
    if (!x.cve && (b.answer === 'affected' || x.kind !== 'older_line')) return fail(409, 'not_one_cve', 'This question decides several CVEs: correct the software on the device (its version) instead.')
    const note = b.note.trim()
    if (b.answer === 'not_affected' && note.length < 3) return fail(400, 'note_required', 'Write why this device is not affected (at least 3 characters) so the next person understands.')
    const user = who(), at = nowIso()
    let finding: string | null = null
    if (b.answer === 'affected') {
      finding = newId('fv')
      const id = finding
      records.update((l) => [...l, {
        id, asset_id: x.asset_id, cve: x.cve!, software: x.software, verified: 'person', basis: 'person', verified_by: user, verified_at: at,
        fix: { key: `${x.software?.name.toLowerCase() ?? 'unknown'}|unknown|`, kind: 'unknown', product: x.software?.name ?? x.cve!, version: null, ref: null, channel: 'public', url: x.url },
        ...unhandled, layer: 5 as const, urgency_at: at, reasons: [], internet: null, first_seen: at, last_seen: at, reopened: null,
        events: [event(user, 'created', { note: note || null }), event(user, 'confirmed', { note: note || null })],
      }])
    }
    // a "not affected" answer is kept so it can be taken back; an "affected" one made a finding
    questions.update((l) => b.answer === 'not_affected' ? l.map((q) => (q.id === x.id ? { ...q, answered: { by: user, at } } : q)) : l.filter((q) => q.id !== x.id))
    audit('findings.question_answered', x.id, `${x.cve ?? x.software?.name ?? ''} ${b.answer}${note ? `: ${note}` : ''}`)
    return HttpResponse.json({ finding })
  }),

  http.get(`${API}/findings/answered`, ({ request }) => read(() => {
    const p = query(request)
    const device = p.get('device') ?? ''
    const assets = new Map(assetsStore.get().map((a) => [a.id, a]))
    const l = questions.get().filter((x) => x.answered && assets.has(x.asset_id) && !isIgnored(x.asset_id) && (!device || x.asset_id === device))
      .sort((a, b) => b.answered!.at.localeCompare(a.answered!.at))
    const items: AnsweredQuestion[] = page(p)(l).map((x) => ({ id: x.id, question: x.kind, device: deviceRef(assets.get(x.asset_id)!), software: x.software,
      cve: x.cve, cves: x.cves, answer: 'not_affected', by: x.answered!.by, at: x.answered!.at, check: checkOfQuestion(x) }))
    return { items, total: l.length } satisfies AnsweredList
  })),

  http.post(`${API}/findings/questions/ignore`, async ({ request }) => {
    const denied = guard('operator'); if (denied) return denied
    const b = await body<{ device: string; software?: string; note: string }>(request)
    if (typeof b.device !== 'string' || !b.device || typeof b.note !== 'string' || b.note.length > 500) return fail(400, 'invalid', 'The request is not valid.')
    const user = who(), at = nowIso()
    const hit = (q: { id: string; asset_id: string; answered?: unknown; kind: string; software: { id: string } | null }) =>
      !q.answered && q.kind !== 'nothing_to_check' && q.asset_id === b.device && (!b.software || q.software?.id === b.software)
    const n = questions.get().filter(hit).length
    if (!n) return fail(404, 'not_found', 'This device has no open question to ignore.')
    questions.update((l) => l.map((q) => (hit(q) ? { ...q, answered: { by: user, at } } : q)))
    audit('findings.questions_ignored', b.software ?? b.device, `${n} questions on ${b.device} answered not affected${b.note.trim() ? `: ${b.note.trim()}` : ''}`)
    return HttpResponse.json({ answered: n })
  }),

  http.post(`${API}/findings/questions/accept-risk`, async ({ request }) => {
    const denied = guard('admin'); if (denied) return denied
    const b = await body<{ device: string; software?: string; question?: string; note: string; until: string }>(request)
    if (typeof b.device !== 'string' || !b.device || typeof b.note !== 'string' || b.note.length > 500) return fail(400, 'invalid', 'The request is not valid.')
    const note = b.note.trim()
    if (note.length < 3) return fail(400, 'note_required', 'Write why this is a false positive, not relevant or an accepted risk (at least 3 characters) so the next person understands.')
    if (!untilOk(String(b.until ?? ''))) return fail(400, 'bad_until', 'Accept the risk until a date from tomorrow up to one year from today.')
    const user = who(), at = nowIso()
    const hit = (q: { id: string; asset_id: string; answered?: unknown; kind: string; software: { id: string } | null }) =>
      !q.answered && q.kind !== 'nothing_to_check' && q.asset_id === b.device && (!b.software || q.software?.id === b.software) && (!b.question || q.id === b.question)
    const qs = questions.get().filter(hit)
    if (!qs.length) return fail(404, 'not_found', 'Nothing is open on this device or software to accept the risk of.')
    const made = qs.filter((q) => q.cve).map((q) => ({
      id: newId('fv'), asset_id: q.asset_id, cve: q.cve!, software: q.software, verified: 'person' as const, basis: 'person' as const, verified_by: user, verified_at: at,
      fix: { key: `${q.software?.name.toLowerCase() ?? 'unknown'}|unknown|`, kind: 'unknown' as const, product: q.software?.name ?? q.cve!, version: null, ref: null, channel: 'public' as const, url: q.url },
      ...unhandled, layer: 5 as const, urgency_at: at, reasons: [], internet: null, first_seen: at, last_seen: at, reopened: null,
      state: 'handled' as const, resolution: 'accepted' as const, via: 'person' as const, resolved_by: user, resolved_at: at, note, accepted_until: b.until as string,
      events: [event(user, 'created', { note }), event(user, 'confirmed', { note }), event(user, 'handled', { resolution: 'accepted', via: 'person', note })],
    }))
    // a device or line scope also takes the open findings already there, confirmed or suspected
    const swept = (r: { state: string; asset_id: string; software: { id: string } | null }) =>
      !b.question && r.state === 'open' && r.asset_id === b.device && (!b.software || r.software?.id === b.software)
    const nSwept = records.get().filter(swept).length
    records.update((l) => [...l.map((r) => (swept(r)
      ? { ...r, state: 'handled' as const, resolution: 'accepted' as const, via: 'person' as const, resolved_by: user, resolved_at: at, note, accepted_until: b.until as string,
        events: [...r.events, event(user, 'handled', { resolution: 'accepted', via: 'person', note })] } : r)), ...made])
    questions.update((l) => l.filter((q) => !hit(q)))
    const total = made.length + nSwept
    audit('findings.risk_accepted_in_bulk', b.software ?? b.device, `risk accepted on ${b.device} until ${b.until}: ${qs.length} questions answered affected, ${total} findings accepted: ${note}`)
    return HttpResponse.json({ questions: qs.length, findings: total })
  }),

  http.post(`${API}/findings/questions/:id/unanswer`, ({ params }) => {
    const denied = guard('operator'); if (denied) return denied
    const x = questions.get().find((q) => q.id === String(params.id))
    if (!x) return fail(404, 'not_found', 'No such question.')
    if (!x.answered) return fail(409, 'not_answered', 'This question has no "not affected" answer to take back. An "affected" answer is changed on its finding\'s page.')
    questions.update((l) => l.map((q) => (q.id === x.id ? { ...q, answered: undefined } : q)))
    audit('findings.question_unanswered', x.id, `${x.cve ?? x.kind}: asked again`)
    return HttpResponse.json({ id: x.id })
  }),
]
