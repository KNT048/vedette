import { Fragment, type ReactNode } from 'react'
import { useTranslation } from 'react-i18next'
import { fmtDate, fmtDayMonth } from '@/lib/format'
import { cn } from '@/lib/utils'
import { OPEN_FINDING_STATUSES } from '@/lib/statusCodes'
import type { Reason, Urgency } from '@/features/findings/types'
import { useStatusLabel } from './StatusBadge'

/**
 * Why a finding has its status: every urgency layer that applies, each with its sources, date and link, under the badge.
 * "Exploited in the wild: Rapid7, Mandiant (19 Nov); not yet in CISA KEV · Public exploit available: GitHub, 244 stars (18 Nov)".
 * Nothing for an update that is only recommended (no layer 1 to 4 applies).
 */
export function ReasonsLine({ urgency, className }: { urgency: Pick<Urgency, 'reasons' | 'internet'>; className?: string }) {
  const { t } = useTranslation()
  const label = useStatusLabel()
  const layers = [...new Set(urgency.reasons.map((r) => r.layer))].sort()
  const parts: ReactNode[] = layers.map((layer) => {
    const rs = urgency.reasons.filter((r) => r.layer === layer)
    const first = rs.map((r) => r.date).sort()[0]!
    const due = rs.map((r) => r.due).filter((d): d is string => !!d).sort()[0]
    const extra = [
      layer === 2 && !rs.some((r) => r.source === 'cisa-kev') ? t('reasons.notInKev') : null,
      due ? t('reasons.due', { date: fmtDate(due) }) : null,
    ].filter(Boolean).join('; ')
    return (
      <span key={layer} data-layer={layer}>
        {label(OPEN_FINDING_STATUSES[layer - 1]!)}{': '}
        {rs.map((r, i) => <Fragment key={`${r.source}-${i}`}>{i > 0 ? ', ' : null}<Source r={r} /></Fragment>)}
        {` (${fmtDayMonth(first)})`}{extra ? `; ${extra}` : null}
      </span>
    )
  })
  if (urgency.internet) parts.push(<span key="internet">{t('reasons.internet', { date: fmtDate(urgency.internet) })}</span>)
  if (!parts.length) return null
  return (
    <p className={cn('text-meta text-muted', className)}>
      {parts.map((p, i) => <Fragment key={i}>{i > 0 ? ' · ' : null}{p}</Fragment>)}
    </p>
  )
}

function Source({ r }: { r: Reason }) {
  const text = r.detail ? `${r.name}, ${r.detail}` : r.name
  if (!r.url) return <>{text}</>
  return <a href={r.url} target="_blank" rel="noopener noreferrer" className="text-accent underline-offset-4 hover:underline">{text}</a>
}
