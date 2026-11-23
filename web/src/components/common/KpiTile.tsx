import type { ReactNode } from 'react'
import { Link } from 'react-router'
import { cn } from '@/lib/utils'
import { useKeepListParams } from './listParams'
import { useIsHere } from './here'

/**
 * A row of stat tiles divided by rules, like one table row, not separate cards (docs/UI.md §3, §5; the KpiStrip look). Its `label` names
 * the list for screen readers. The grid columns are the caller's (`className`), so a page can give its lead tile two columns.
 */
export function KpiGrid({ label, children, className }: { label: string; children: ReactNode; className?: string }) {
  return <ul aria-label={label} className={cn('mb-5 grid grid-cols-2 gap-px overflow-hidden rounded-md border border-rule bg-rule', className)}>{children}</ul>
}

/**
 * One stat tile (#825): the number (`text-lg`, the KPI size of docs/UI.md §1) and what it counts; with `to`, number and label are one
 * link stretched over the whole tile, so the tile clicks through to the list it counts. `tone` colours the number only: `danger` when
 * it asks for action, `ok` when the answer is good news. `sub` is one short line under it: plain text, or links (they sit above the
 * stretched link and stay clickable on their own). `chart` is the sparkline slot, also above the stretched link so it can be read by
 * hover and keyboard.
 */
export function KpiTile({ value, label, to, tone, sub, chart, className }: {
  value: ReactNode
  label: string
  to?: string
  tone?: 'danger' | 'ok'
  sub?: ReactNode
  chart?: ReactNode
  className?: string
}) {
  const keep = useKeepListParams()
  const isHere = useIsHere()
  const link = to && !isHere(to) ? to : undefined // a tile of the list already shown is not a link to itself
  const body = (
    <>
      <span className={cn('block text-lg font-semibold tabular-nums', tone === 'danger' && 'text-danger', tone === 'ok' && 'text-ok')}>{value}</span>{' '}
      <span className="block text-meta text-muted underline-offset-4 group-hover:text-ink group-hover:underline">{label}</span>
    </>
  )
  return (
    <li className={cn('group relative grid min-w-0 content-start gap-1 bg-surface px-4 py-3', link && 'hover:bg-sunken', className)}>
      {link ? (
        // The ::after covers the tile; the focus ring is drawn on it, inside the tile (the grid clips anything outside).
        <Link to={keep(link)} className="no-underline outline-none after:absolute after:inset-0 focus-visible:after:outline-2 focus-visible:after:-outline-offset-2 focus-visible:after:outline-focus">{body}</Link>
      ) : <div>{body}</div>}
      {sub ? <div className="relative flex flex-wrap gap-x-3 gap-y-0.5 text-meta text-muted">{sub}</div> : null}
      {chart ? <div className="relative mt-1">{chart}</div> : null}
    </li>
  )
}
