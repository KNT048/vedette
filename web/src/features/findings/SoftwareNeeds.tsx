// kien G8: the device's Software tab says, on each software row, what it needs: its exploited findings (count, worst, the update that
// fixes them) and/or the recommended update that fixes CVEs not exploited yet, from the same answer as To fix (GET /findings/to-fix
// for the device); nothing on a clean row.
import { Link } from 'react-router'
import { useTranslation } from 'react-i18next'
import { Chip } from '@/components/common/StatusChip'
import { useModuleEnabled } from '@/lib/modules'
import { useToFix } from './api'
import { actionable, unproved } from './ToFix'
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
  const to = `/findings?device=${encodeURIComponent(assetId)}`
  return (
    <div className="grid gap-1 text-meta">
      {cves ? (
        <span className="flex flex-wrap items-center gap-x-2 gap-y-1">
          <Link to={to} className="font-medium text-accent underline-offset-4 hover:underline">{t('needs.exploited', { count: cves })}</Link>
          {worst ? <Chip tone={rank(worst) >= 3 ? 'danger' : 'warn'}>{t(`common:severity.${worst.toLowerCase()}`)}</Chip> : null}
          {n.exploited.filter((a) => a.kind !== 'none').map((a) => <span key={a.group}>{a.action}</span>)}
        </span>
      ) : null}
      {check > 0 ? <Link to={`/findings?tab=input&device=${encodeURIComponent(assetId)}`} className="w-fit text-accent underline-offset-4 hover:underline">{t('needs.toCheck', { count: check })}</Link> : null}
      {n.planned.filter((a) => a.cves.length > 0).map((a) => (
        <Link key={a.group} to="/plan?tier=all" className="w-fit text-accent underline-offset-4 hover:underline">
          {a.fixed ? t('needs.planned', { fixed: a.windows ? a.fixed.replace(/^10\.0\./, '') : a.fixed, count: a.cves.length }) : t('needs.plannedNoVersion', { count: a.cves.length })}
        </Link>
      ))}
    </div>
  )
}
