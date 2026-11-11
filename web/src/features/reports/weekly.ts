// Dựng báo cáo tuần từ kho dùng chung (assetsStore, findingsStore) và KEV thật. `asOf` cho phép dựng lại số liệu của các tuần trước.
// Số lần chạm bẫy và log bất thường KHÔNG đưa vào: dữ liệu đó nằm trong module honeypot/logs, chưa có store dùng chung; không bịa số.
import kev from '@/mocks/fixtures/kev.json'
import { assetsStore, findingsStore } from '@/mocks/stores'
import type { Finding } from '@/lib/types'
import type { ActionItem, FindingRow, WeeklyReport } from './types'

interface Kev { cve: string; vendor: string; product: string; date_added: string }
const data = kev as { generated_at: string; vulns: Kev[] }
const DAY = 864e5

export const vulnOf = (cve: string) => data.vulns.find((v) => v.cve === cve)
export const kevKey = (v: { vendor: string; product: string }) => `${v.vendor.toLowerCase()}|${v.product.toLowerCase()}`

export function rowOf(f: Finding): FindingRow {
  const a = assetsStore.get().find((x) => x.id === f.asset_id)
  const v = vulnOf(f.cve)
  return { id: f.id, cve: f.cve, device: a?.hostname ?? a?.ip ?? f.asset_id, asset_id: f.asset_id, product: v ? `${v.vendor} ${v.product}` : f.cve, status: f.status, severity: f.severity, since: f.first_seen }
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
  const resolvedRows = findingsStore.get().filter((f) => inWeek(t(f.resolved_at))).map(rowOf)

  const shift = Date.now() - asOf
  const end = new Date(data.generated_at).getTime() - shift
  // The last seven calendar days up to today, today included (D-239; the backend counts the same way).
  const startOfToday = Math.floor(end / DAY) * DAY
  const kevWeek = data.vulns.filter((v) => { const ms = new Date(`${v.date_added}T00:00:00Z`).getTime(); return ms > startOfToday - 7 * DAY && ms <= end })
  const kevMatched = kevWeek.filter((v) => assets.some((a) => a.software.some((s) => s.kev.includes(kevKey(v))))).length

  const unapproved = assets.filter((a) => !a.approved).length
  const eol = assets.filter((a) => EOL_OS.test(a.os?.value ?? '')).length
  const actions: ActionItem[] = [
    ...openRows.filter((r) => r.status === 'confirmed').map((r): ActionItem => ({ kind: 'fix', cve: r.cve, device: r.device, finding_id: r.id })),
    ...openRows.filter((r) => r.status === 'suspected').map((r): ActionItem => ({ kind: 'verify', cve: r.cve, device: r.device, finding_id: r.id })),
    ...(unapproved ? [{ kind: 'review_devices', count: unapproved } as ActionItem] : []),
    ...(eol ? [{ kind: 'plan_os', count: eol } as ActionItem] : []),
  ].slice(0, 6)

  const at = new Date(asOf).toISOString()
  return {
    period: { from: new Date(from).toISOString(), to: at },
    generated_at: at,
    counts: {
      new_findings: newRows.length, resolved: resolvedRows.length,
      open_confirmed: openRows.filter((r) => r.status === 'confirmed').length, open_suspected: openRows.filter((r) => r.status === 'suspected').length,
      devices: assets.length, devices_unapproved: unapproved, devices_new: assets.filter((a) => new Date(a.first_seen).getTime() > from).length,
      kev_new: kevWeek.length, kev_matched: kevMatched,
    },
    new_findings: newRows, resolved: resolvedRows, open: openRows, actions,
    sources: [{ id: 'inventory', at }, { id: 'findings', at }, { id: 'kev', at: data.generated_at }],
    ai_summary: null,
  }
}
