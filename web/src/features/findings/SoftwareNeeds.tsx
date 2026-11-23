// The device's Software tab says, on each software row, what it needs: its exploited findings (count, worst, the update that
// fixes them) and/or the recommended update that fixes CVEs not exploited yet, from the same answer as To fix (GET /findings/to-fix
// for the device); nothing on a clean row.
import { Link } from 'react-router'
import { useTranslation } from 'react-i18next'
import { useModuleEnabled } from '@/lib/modules'
import { useToFix } from './api'
import { Worst, actionable, unproved } from './ToFix'
import { kbNote } from './fix'
import type { ToFixAction } from './types'

const SEV = ['info', 'low', 'medium', 'high', 'critical']
const rank = (s: string) => SEV.indexOf(s.toLowerCase())

/** The device's actions by software row id, or the state while there is none. */
type Needs = { exploited: ToFixAction[]; check: ToFixAction[]; planned: ToFixAction[] }

/** The device's actions by software row id, as To fix counts them (review r1 of #943): its actions to fix, what needs a person's check
 *  (Needs your input), its recommended updates; or the state while there is none. */
export function useSoftwareNeeds(assetId: string): Map<string, Needs> | 'off' | 'pending' | 'error' {
  const on = useModuleEnabled('findings')
  const q = useToFix(assetId, on === true)
  if (on === false) return 'off'
  if (q.isError) return 'error'
  if (on === undefined || q.isPending) return 'pending'
  const m = new Map<string, Needs>()
  for (const d of q.data.devices) {
    const add = (a: ToFixAction, k: keyof Needs) => {
      if (!a.software_id) return
      const e = m.get(a.software_id) ?? { exploited: [], check: [], planned: [] }
      e[k].push(a)
      m.set(a.software_id, e)
    }
    for (const a of actionable(d)) add(a, 'exploited')
    for (const a of unproved(d)) add(a, 'check')
    for (const a of d.planned) add(a, 'planned')
  }
  return m
}

/** The needs keyed by the row each software is shown as. An action names the software row its findings or plan item rest on, and
 *  that can be any row of the software: the device page shows one line per software (inventory's effective row) and lists the other
 *  rows under it (also_seen). `lineOf` maps every row id to the id of its line; the needs of all the rows of a line are merged. */
export function needsByLine(needs: ReturnType<typeof useSoftwareNeeds>, lineOf: ReadonlyMap<string, string>): ReturnType<typeof useSoftwareNeeds> {
  if (!(needs instanceof Map)) return needs
  const m = new Map<string, Needs>()
  for (const [id, n] of needs) {
    const line = lineOf.get(id) ?? id
    const e = m.get(line)
    m.set(line, e ? { exploited: [...e.exploited, ...n.exploited], check: [...e.check, ...n.check], planned: [...e.planned, ...n.planned] } : n)
  }
  return m
}

/** The order of a row by what it needs, for sorting the Software tab (higher first): exploited CVEs, then exploited matches to check,
 *  then recommended updates, each by its number of CVEs; 0 for a clean row and while the answer is not there. */
export function needsRank(needs: ReturnType<typeof useSoftwareNeeds>, softwareId: string): number {
  const n = needs instanceof Map ? needs.get(softwareId) : undefined
  if (!n) return 0
  const cves = (l: ToFixAction[]) => l.reduce((s, a) => s + a.cves.length, 0)
  const planned = n.planned.filter((a) => a.cves.length > 0 || a.windows)
  if (n.exploited.length) return 3_000_000 + Math.min(cves(n.exploited), 999_999)
  if (n.check.length) return 2_000_000 + Math.min(cves(n.check), 999_999)
  if (planned.length) return 1_000_000 + Math.min(cves(planned), 999_999)
  return 0
}

/** One software row's needs. */
export function SoftwareNeeds({ assetId, softwareId, needs }: { assetId: string; softwareId: string; needs: ReturnType<typeof useSoftwareNeeds> }) {
  const { t } = useTranslation('findings')
  if (needs === 'off') return <span className="text-meta text-muted">{t('needs.off')}</span>
  if (needs === 'pending') return <span className="text-meta text-muted">{t('needs.pending')}</span>
  if (needs === 'error') return <span className="text-meta text-muted">{t('needs.error')}</span>
  const n = needs.get(softwareId)
  if (!n) return null
  const cves = n.exploited.reduce((s, a) => s + a.cves.length, 0)
  const check = n.check.reduce((s, a) => s + a.cves.length, 0)
  const worst = n.exploited.reduce((w, a) => (rank(a.worst) > rank(w) ? a.worst : w), '')
  const to = `/findings?tab=open&device=${encodeURIComponent(assetId)}`
  return (
    <div className="grid gap-1 text-meta">
      {cves ? (
        <span className="flex flex-wrap items-center gap-x-2 gap-y-1">
          <Link to={to} className="font-medium text-accent underline-offset-4 hover:underline">{t('needs.exploited', { count: cves })}</Link>
          <Worst worst={worst} />
          {n.exploited.filter((a) => a.kind !== 'none').map((a) => <span key={a.group}>{a.action}</span>)}
        </span>
      ) : null}
      {check > 0 ? <Link to={`/findings?tab=input&device=${encodeURIComponent(assetId)}`} className="w-fit text-accent underline-offset-4 hover:underline">{t('needs.toCheck', { count: check })}</Link> : null}
      {n.planned.filter((a) => a.cves.length > 0 || a.windows).map((a) => (
        <Link key={a.group} to="/plan?tier=all" className="w-fit text-accent underline-offset-4 hover:underline">
          {a.cves.length === 0 ? t(a.nvd_lag ? 'needs.plannedNotAnalysed' : 'needs.plannedNoCves', { fixed: a.windows ? a.fixed.replace(/^10\.0\./, '') : a.fixed, kb: kbNote(a.kb) })
            : a.fixed ? t('needs.planned', { fixed: a.windows ? a.fixed.replace(/^10\.0\./, '') : a.fixed, count: a.cves.length }) : t('needs.plannedNoVersion', { count: a.cves.length })}
        </Link>
      ))}
    </div>
  )
}

/** The device's operating system has no row of its own on the Software tab when the OS comes from SNMP or what the device states
 *  (its actions are on "os:<device>"): one line above the table says what it needs (review r2 of #943); nothing when clean. */
export function OsNeeds({ assetId, needs }: { assetId: string; needs: ReturnType<typeof useSoftwareNeeds> }) {
  const { t } = useTranslation('findings')
  const id = `os:${assetId}`
  if (!(needs instanceof Map) || !needs.has(id)) return null
  return (
    <div className="mb-3 grid gap-1 rounded-md border border-rule bg-surface px-4 py-3 text-sm">
      <span className="font-medium">{t('needs.os')}</span>
      <SoftwareNeeds assetId={assetId} softwareId={id} needs={needs} />
    </div>
  )
}
