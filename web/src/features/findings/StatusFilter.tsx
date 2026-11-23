// The status filter above By device and By fix: the five open statuses as toggles, none pressed = all of them. Kept in the URL
// (`status=exploited,public_exploit`), so a device badge's link ("2 exploited") opens the list already filtered.
import { useSearchParams } from 'react-router'
import { useTranslation } from 'react-i18next'
import { StatusBadge } from '@/components/common/status'
import { OPEN_FINDING_STATUSES, type OpenFindingStatus } from '@/lib/statusCodes'
import { cn } from '@/lib/utils'
import { useOverview } from './api'

/** The statuses of the URL's filter, unknown words left out. */
export function statusesOf(v: string | null): OpenFindingStatus[] {
  const asked = new Set((v ?? '').split(',').map((s) => s.trim()))
  return OPEN_FINDING_STATUSES.filter((s) => asked.has(s))
}

/** `counts`: the numbers beside the toggles when the list is one device's (its card's); else the whole box's, from the overview. */
export function StatusFilter({ counts: own }: { counts?: Record<OpenFindingStatus, number> } = {}) {
  const { t } = useTranslation('findings')
  const [params, setParams] = useSearchParams()
  const on = statusesOf(params.get('status'))
  const overview = useOverview(own === undefined).data?.open.by_status
  const counts = own ?? overview
  const toggle = (s: OpenFindingStatus) => {
    const next = on.includes(s) ? on.filter((x) => x !== s) : OPEN_FINDING_STATUSES.filter((x) => x === s || on.includes(x))
    setParams((prev) => {
      const p = new URLSearchParams(prev)
      if (next.length) p.set('status', next.join(',')); else p.delete('status')
      return p
    }, { replace: true, preventScrollReset: true })
  }
  return (
    <div role="group" aria-label={t('statusFilter.label')} className="flex max-w-full flex-wrap items-center gap-1.5">
      {/* one device's list offers only the statuses it has (and any pressed one) */}
      {OPEN_FINDING_STATUSES.filter((s) => !own || own[s] > 0 || on.includes(s)).map((s) => {
        const n = counts?.[s]
        const pressed = on.includes(s)
        return (
          <button key={s} type="button" aria-pressed={pressed} onClick={() => toggle(s)}
            className={cn('inline-flex items-center gap-1.5 rounded-md border px-1.5 py-1 text-meta tabular-nums hover:bg-sunken focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-accent',
              pressed ? 'border-accent bg-accent-soft' : 'border-transparent')}>
            {/* a status with nothing in it stays readable (a faded badge fails colour contrast); its 0 says it is empty */}
            <StatusBadge code={s} />
            {n !== undefined ? <span className="text-muted">{n}</span> : null}
          </button>
        )
      })}
      {on.length ? (
        <button type="button" onClick={() => setParams((prev) => { const p = new URLSearchParams(prev); p.delete('status'); return p }, { replace: true, preventScrollReset: true })}
          className="text-meta font-medium text-accent underline-offset-4 hover:underline">{t('statusFilter.all')}</button>
      ) : null}
    </div>
  )
}
