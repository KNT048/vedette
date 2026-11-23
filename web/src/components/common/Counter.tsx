import { cn } from '@/lib/utils'

/** A count on a tab, a nav item or a KPI (docs/UI.md §7): `danger` (solid) only when work waits for the user, `off` for a plain count.
 *  `label` is read after the number by screen readers ("15 to review"), so the name carries the visible text plus its meaning. The count
 *  is exact ("196", not "99+"): a person who answers one item sees it go down; only a count past 9999 is cut. */
export function Counter({ count, label, tone = 'off', className }: { count: number; label?: string; tone?: 'danger' | 'off'; className?: string }) {
  if (count <= 0) return null
  return (
    <span className={cn('inline-flex h-4.5 min-w-4.5 shrink-0 items-center justify-center rounded-full px-1.5 text-caption font-semibold leading-none tabular-nums', tone === 'danger' ? 'bg-danger text-paper' : 'border border-rule bg-off-soft text-off', className)}>
      {count > 9999 ? '9999+' : count}
      {label ? <>{' '}<span className="sr-only">{label}</span></> : null}
    </span>
  )
}
