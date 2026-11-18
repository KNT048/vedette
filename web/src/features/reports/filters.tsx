import { useMemo, useSyncExternalStore } from 'react'
import { useTranslation } from 'react-i18next'
import { Label } from '@/components/ui/input'
import { Switch } from '@/components/ui/switch'
import { isNotRelevant } from '@/features/findings/notRelevant'
import type { FindingRow, PdplReport, WeeklyReport } from './types'

/**
 * What a report view includes, chosen by the viewer and kept per browser: the devices not in the Devices list yet (not approved,
 * "To review" in Devices; included by default) and the findings closed as not relevant (left out by default). The page, the print
 * view (Save as PDF) and a reopened sent report all follow the same choice, and each document says which one it used.
 */
export interface ReportFilters { unapproved: boolean; notRelevant: boolean }

export const DEFAULT_FILTERS: ReportFilters = { unapproved: true, notRelevant: false }
export const FILTERS_KEY = 'vedette.reports.include'

const listeners = new Set<() => void>()
// The choice when the browser will not store it (storage blocked or full): kept for as long as the page is open.
let memory: string | null = null
function readRaw(): string {
  if (memory !== null) return memory
  try { return localStorage.getItem(FILTERS_KEY) ?? '' } catch { return '' }
}
function writeRaw(v: string) {
  try { localStorage.setItem(FILTERS_KEY, v); memory = null } catch { memory = v }
}
function subscribe(fn: () => void) {
  listeners.add(fn)
  window.addEventListener('storage', fn)
  return () => { listeners.delete(fn); window.removeEventListener('storage', fn) }
}
function parse(raw: string): ReportFilters {
  if (!raw) return DEFAULT_FILTERS
  try {
    const v = JSON.parse(raw) as Partial<ReportFilters>
    return {
      unapproved: typeof v.unapproved === 'boolean' ? v.unapproved : DEFAULT_FILTERS.unapproved,
      notRelevant: typeof v.notRelevant === 'boolean' ? v.notRelevant : DEFAULT_FILTERS.notRelevant,
    }
  } catch { return DEFAULT_FILTERS }
}

export function useReportFilters(): [ReportFilters, (change: Partial<ReportFilters>) => void] {
  const raw = useSyncExternalStore(subscribe, readRaw, () => '')
  const f = useMemo(() => parse(raw), [raw])
  const set = (change: Partial<ReportFilters>) => {
    writeRaw(JSON.stringify({ ...parse(readRaw()), ...change }))
    for (const l of listeners) l()
  }
  return [f, set]
}

/**
 * What a view left out, for the line the document prints: a number is how many were left out, null means included (a report made
 * before the choice existed keeps its devices), and an absent notRelevant means the choice does not apply to that report.
 */
export interface LeftOut { devices: number | null; notRelevant?: number | null }

/** A report view lists this many rows of each list at most (modules/reports MaxRows); its counts are of everything. */
export const MAX_ROWS = 100

const approvedRow =(r: FindingRow) => r.device_approved !== false

/**
 * The weekly report as the filters show it. The counts, top risks and actions without the devices not approved yet come from the
 * box (approved_only); the lists are filtered by row. Not relevant findings are subtracted with the box's own counts; a report sent
 * before those counts falls back on its rows (a list cut at 100 rows may then keep a few in the totals).
 */
export function weeklyView(full: WeeklyReport, f: ReportFilters): { report: WeeklyReport; left: LeftOut } {
  let r = full
  let devices: number | null = null
  if (full.approved_only && !f.unapproved) {
    devices = full.counts.devices_unapproved
    const a = full.approved_only
    r = { ...full, counts: a.counts, top_risks: full.top_risks ? a.top_risks : undefined, actions: a.actions,
      new_findings: full.new_findings.filter(approvedRow), resolved: full.resolved.filter(approvedRow), open: full.open.filter(approvedRow) }
  }
  let notRelevant: number | null = null // included
  if (!f.notRelevant) {
    const c = r.counts
    const nrNew = c.not_relevant_new ?? r.new_findings.filter(isNotRelevant).length
    const nrDone = c.not_relevant_resolved ?? r.resolved.filter(isNotRelevant).length
    notRelevant = c.not_relevant ?? new Set([...r.new_findings, ...r.resolved].filter(isNotRelevant).map((x) => x.id)).size
    r = { ...r, counts: { ...c, new_findings: c.new_findings - nrNew, resolved: c.resolved - nrDone },
      new_findings: r.new_findings.filter((x) => !isNotRelevant(x)), resolved: r.resolved.filter((x) => !isNotRelevant(x)) }
  }
  // The box sends the first MAX_ROWS rows of each view (weekly.go capViews), so a filtered list is never short; cut to the view.
  r = { ...r, new_findings: r.new_findings.slice(0, MAX_ROWS), resolved: r.resolved.slice(0, MAX_ROWS), open: r.open.slice(0, MAX_ROWS) }
  return { report: r, left: { devices, notRelevant } }
}

/**
 * The assessment as the filters show it. Its risks are open findings only, so the not relevant choice does not change it; the
 * devices not approved yet are left out with the box's approved_only view (inventory, measures, risks).
 */
export function pdplView(full: PdplReport, f: ReportFilters): { report: PdplReport; left: LeftOut } {
  if (!full.approved_only || f.unapproved) return { report: full, left: { devices: null } }
  const a = full.approved_only
  return { report: { ...full, inventory: a.inventory, measures: a.measures, risks: a.risks }, left: { devices: full.inventory.unapproved } }
}

/** The two switches over a report view. `notRelevant` is false where the choice changes nothing (the assessment lists open risks only). */
export function ReportFilterSwitches({ notRelevant = true, idPrefix }: { notRelevant?: boolean; idPrefix: string }) {
  const { t } = useTranslation('reports')
  const [f, set] = useReportFilters()
  return (
    <div className="flex flex-wrap items-center gap-x-6 gap-y-2" role="group" aria-label={t('filters.label')}>
      <div className="flex items-center gap-2">
        <Switch id={`${idPrefix}-unapproved`} checked={f.unapproved} onCheckedChange={(v) => set({ unapproved: v })} />
        <Label htmlFor={`${idPrefix}-unapproved`}>{t('filters.unapproved')}</Label>
      </div>
      {notRelevant ? (
        <div className="flex items-center gap-2">
          <Switch id={`${idPrefix}-nr`} checked={f.notRelevant} onCheckedChange={(v) => set({ notRelevant: v })} />
          <Label htmlFor={`${idPrefix}-nr`}>{t('filters.notRelevant')}</Label>
        </div>
      ) : null}
    </div>
  )
}

/** The line a document prints to say what its figures and lists include. */
export function FiltersUsed({ left }: { left: LeftOut }) {
  const { t } = useTranslation('reports')
  const say = (n: number | null | undefined, key: string) =>
    n === undefined ? null : n === null ? t(`filters.used.${key}In`) : n === 0 ? t(`filters.used.${key}OutNone`) : t(`filters.used.${key}Out`, { count: n })
  const parts = [say(left.devices, 'devices'), say(left.notRelevant, 'nr')].filter((s): s is string => !!s)
  return <p className="flex flex-wrap gap-x-1 text-meta text-muted">{parts.map((s) => <span key={s}>{s}</span>)}</p>
}
