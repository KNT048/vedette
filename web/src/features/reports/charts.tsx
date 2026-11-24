// The report's few charts, drawn with the theme tokens (no chart library): they print on A4 in colour and stay readable without
// colour, because each bar sits next to its words and number.
import type { ReactNode } from 'react'
import { useTranslation } from 'react-i18next'
import { cn } from '@/lib/utils'

/** One labelled bar per row: what it counts (a badge or words), the bar, the number. */
export function BarList({ rows, label }: { rows: { key: string; label: ReactNode; n: number; bar: string }[]; label: string }) {
  const max = Math.max(1, ...rows.map((r) => r.n))
  return (
    <ul aria-label={label} className="grid gap-1.5">
      {rows.map((r) => (
        <li key={r.key} className="grid grid-cols-[minmax(0,13rem)_minmax(0,1fr)_2.5rem] items-center gap-3">
          <span className="min-w-0">{r.label}</span>
          <span aria-hidden className="h-2 overflow-hidden rounded-full bg-sunken">
            <span className={cn('block h-full rounded-full', r.bar)} style={{ width: `${(r.n / max) * 100}%` }} />
          </span>
          <span className="text-right text-sm font-semibold tabular-nums">{r.n}</span>
        </li>
      ))}
    </ul>
  )
}

type Step = { key: string; label: string; value: number; from: number; to: number; bar: string; sign?: '+' | '−' }

/**
 * How the open findings moved through the period, as a waterfall: open at the start, plus new, minus handled, any other change
 * (findings reopened in the period, then anything left out since the start), open now. The steps always add up, so a manager can check the figures.
 */
export function OpenFlow({ start, added, handled, reopened = 0, end }: { start: number; added: number; handled: number; reopened?: number; end: number }) {
  const { t } = useTranslation('reports')
  const other = end - (start + added - handled + reopened)
  const afterNew = start + added
  const afterHandled = afterNew - handled
  const afterReopened = afterHandled + reopened
  const steps: Step[] = [
    { key: 'start', label: t('sr.flow.start'), value: start, from: 0, to: start, bar: 'bg-off' },
    { key: 'new', label: t('sr.flow.new'), value: added, from: start, to: afterNew, bar: 'bg-danger/70', sign: '+' },
    { key: 'handled', label: t('sr.flow.handled'), value: handled, from: afterHandled, to: afterNew, bar: 'bg-ok', sign: '−' },
    ...(reopened > 0 ? [{ key: 'reopened', label: t('sr.flow.reopened'), value: reopened, from: afterHandled, to: afterReopened, bar: 'bg-warn/60', sign: '+' as const }] : []),
    ...(other !== 0 ? [{ key: 'other', label: t('sr.flow.other'), value: Math.abs(other), from: Math.min(afterReopened, end), to: Math.max(afterReopened, end), bar: 'bg-off/50', sign: (other > 0 ? '+' : '−') as '+' | '−' }] : []),
    { key: 'end', label: t('sr.flow.end'), value: end, from: 0, to: end, bar: 'bg-ink' },
  ]
  const top = Math.max(1, ...steps.map((s) => s.to))
  const aria = t('sr.flow.aria', { start, added, handled, end,
    other: (reopened > 0 ? t('sr.flow.reopenedAria', { n: reopened }) : '') + (other !== 0 ? t('sr.flow.otherAria', { n: other > 0 ? `+${other}` : `${other}` }) : '') })
  return (
    <figure className="grid gap-2">
      <figcaption className="text-meta font-medium text-muted">{t('sr.flow.title')}</figcaption>
      <div role="img" aria-label={aria} className="grid gap-1" style={{ gridTemplateColumns: `repeat(${steps.length}, minmax(0, 1fr))` }}>
        {steps.map((s) => (
          <div key={s.key} aria-hidden className="grid gap-1">
            <span className="text-center text-sm font-semibold tabular-nums">{s.sign ? `${s.sign}${s.value}` : s.value}</span>
            <div className="relative h-24 border-b border-rule">
              <span className={cn('absolute inset-x-2 rounded-sm', s.bar)}
                style={{ bottom: `${(s.from / top) * 100}%`, height: `max(2px, ${((s.to - s.from) / top) * 100}%)` }} />
            </div>
            <span className="text-center text-caption text-muted">{s.label}</span>
          </div>
        ))}
      </div>
    </figure>
  )
}
