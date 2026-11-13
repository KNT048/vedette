// Dựng báo cáo tuần từ kho dùng chung (assetsStore, findingsStore) và KEV thật. `asOf` cho phép dựng lại số liệu của các tuần trước.
// Số lần chạm bẫy và log bất thường KHÔNG đưa vào: dữ liệu đó nằm trong module honeypot/logs, chưa có store dùng chung; không bịa số.
import kev from '@/mocks/fixtures/kev.json'
import { assetsStore, findingsStore } from '@/mocks/stores'
import type { Finding } from '@/lib/types'
import { hotRows } from '@/features/feeds/mocks'
import { displayOf } from '@/features/feeds/slug'
import type { ActionItem, FindingRow, TopRisk, WeeklyReport } from './types'

interface Kev { cve: string; vendor: string; product: string; date_added: string }
const data = kev as { generated_at: string; vulns: Kev[] }
const DAY = 864e5

export const vulnOf = (cve: string) => data.vulns.find((v) => v.cve === cve)

export function rowOf(f: Finding): FindingRow {
  const a = assetsStore.get().find((x) => x.id === f.asset_id)
  const v = vulnOf(f.cve)
  return { id: f.id, cve: f.cve, device: a?.hostname ?? a?.ip ?? f.asset_id, asset_id: f.asset_id, product: v ? displayOf(v.vendor, v.product) : f.cve, status: f.status, severity: f.severity, since: f.first_seen }
}

const SEV = { critical: 0, high: 1, medium: 2, low: 3, info: 4 } as const

/** The three biggest open risks by product, as weekly.go topRisks: confirmed first, then worst severity, then most findings, then name. */
export function topRisks(open: FindingRow[]): TopRisk[] {
  const by = new Map<string, TopRisk & { names: string[]; ids: Set<string> }>()
  for (const f of open) {
    let g = by.get(f.product)
    if (!g) { g = { product: f.product, device: '', devices: 0, open: 0, confirmed: 0, severity: f.severity, cve: f.cve, finding_id: f.id, names: [], ids: new Set() }; by.set(f.product, g) }
    g.open++
    if (f.status === 'confirmed') { if (!g.confirmed) Object.assign(g, { cve: f.cve, finding_id: f.id }); g.confirmed++ // severity stays the worst of the group }
    if (SEV[f.severity] < SEV[g.severity]) g.severity = f.severity
    if (!g.ids.has(f.asset_id)) { g.ids.add(f.asset_id); g.names.push(f.device) }
  }
  return [...by.values()]
    .sort((a, b) => Number(b.confirmed > 0) - Number(a.confirmed > 0) || SEV[a.severity] - SEV[b.severity] || b.open - a.open || a.product.localeCompare(b.product))
    .slice(0, 3)
    .map(({ names, ids: _ids, ...r }) => ({ ...r, devices: names.length, device: names.length === 2 ? `${names[0]} and ${names[1]}` : names.length > 2 ? `${names[0]} and ${names.length - 1} more` : names[0]! }))
}

export const EOL_OS = /windows 10|server 2016/i

export function buildWeekly(asOf = Date.now()): WeeklyReport {
  const from = asOf - 7 * DAY
  const t = (iso: string | null) => (iso ? new Date(iso).getTime() : null)
  const assets = assetsStore.get().filter((a) => new Date(a.first_seen).getTime() <= asOf)
  const findings = findingsStore.get().filter((f) => new Date(f.first_seen).getTime() <= asOf)
  const isOpenAt = (f: Finding) => { const r = t(f.resolved_at); return r === null || r > asOf }
  const inWeek = (ms: number | null) => ms !== null && ms > from && ms <= asOf
  const open = findings.filter((f) => isOpenAt(f) && (f.status === 'confirmed' || f.status === 'suspected' || t(f.resolved_at) !== null))
  const openRows = open.map((f) => ({ ...rowOf(f), status: f.status === 'confirmed' ? ('confirmed' as const) : ('suspected' as const) }))
  const newRows = findings.filter((f) => inWeek(t(f.first_seen))).map(rowOf)
  const resolvedRows = findingsStore.get().filter((f) => inWeek(t(f.resolved_at))).map((f) => ({ ...rowOf(f), ...(f.resolved_by ? { by: f.resolved_by } : {}) }))
  const order = (rows: FindingRow[]) => rows.slice().sort((a, b) => SEV[a.severity] - SEV[b.severity] || b.since.localeCompare(a.since) || a.id.localeCompare(b.id))

  // The same board as Home (feeds hotRows, 7 days), moved back for an older week (D-485).
  const shift = Date.now() - asOf
  const hot = hotRows(24 * 7, new Date(data.generated_at).getTime() - shift)
  const kevNew = hot.reduce((n, r) => n + r.cves.length, 0)
  const kevInUse = hot.filter((r) => r.you_have === 'yes').length

  const unapproved = assets.filter((a) => !a.approved).length
  const eol = assets.filter((a) => EOL_OS.test(a.os?.value ?? '')).length
  const risks = topRisks(order(openRows))
  const actions: ActionItem[] = [
    ...risks.map((r): ActionItem => ({ kind: r.confirmed ? 'fix' : 'verify', cve: r.cve, device: r.device, finding_id: r.finding_id, product: r.product, count: r.open })),
    ...(unapproved ? [{ kind: 'review_devices', count: unapproved } as ActionItem] : []),
    ...(eol ? [{ kind: 'plan_os', count: eol } as ActionItem] : []),
  ]

  const at = new Date(asOf).toISOString()
  return {
    period: { from: new Date(from).toISOString(), to: at },
    generated_at: at,
    counts: {
      new_findings: newRows.length, resolved: resolvedRows.length,
      open_confirmed: openRows.filter((r) => r.status === 'confirmed').length, open_suspected: openRows.filter((r) => r.status === 'suspected').length,
      devices: assets.length, devices_unapproved: unapproved, devices_new: assets.filter((a) => new Date(a.first_seen).getTime() > from).length,
      kev_new: kevNew, kev_matched: kevInUse,
    },
    top_risks: risks,
    new_findings: newRows, resolved: resolvedRows, open: openRows, actions,
    sources: [{ id: 'inventory', at }, { id: 'findings', at }, { id: 'kev', at: data.generated_at }],
    ai_summary: null,
  }
}
