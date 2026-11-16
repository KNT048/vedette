import { useEffect, useRef } from 'react'
import { NavLink, useLocation } from 'react-router'
import { cn } from '@/lib/utils'
import { Counter } from './Counter'

/** `badge`: work waiting behind that link (red Counter; `label` is read after the number). */
export type UnderlineNavItem = { to: string; label: string; end?: boolean; badge?: { count: number; label: string } }

/** Links between pages in the look of PageTabs (docs/UI.md §4; Primer splits UnderlineNav and UnderlinePanels the same way): the open
 *  link has aria-current="page", the row scrolls sideways inside itself and the open link scrolls into view; it never wraps.
 *  `verticalFrom="lg"`: a vertical menu from lg (Settings, D-519/D-543), the underlined row below it. */
export function UnderlineNav({ items, label, verticalFrom }: { items: UnderlineNavItem[]; label: string; verticalFrom?: 'lg' }) {
  const { pathname } = useLocation()
  const row = useRef<HTMLElement>(null)
  useEffect(() => {
    const r = row.current
    const el = r?.querySelector<HTMLElement>('[aria-current="page"]')
    if (!r || !el || r.scrollWidth <= r.clientWidth) return
    const a = r.getBoundingClientRect()
    const b = el.getBoundingClientRect()
    if (b.left < a.left || b.right > a.right) r.scrollLeft += b.left - a.left - 16
  }, [pathname, items.length])
  const v = verticalFrom === 'lg'
  const link = ({ isActive }: { isActive: boolean }) => cn(
    'flex h-10 shrink-0 items-center whitespace-nowrap border-b-2 border-transparent px-3 text-sm text-muted hover:text-ink focus-visible:-outline-offset-2',
    v && 'lg:h-9 lg:rounded-md lg:border-b-0 lg:hover:bg-sunken',
    isActive && 'border-accent font-medium text-ink',
    isActive && v && 'lg:bg-accent-soft lg:nav-current',
  )
  return (
    // ui-guard: the rule under the row is an inset shadow: the scroll box clips anything drawn outside it (same as PageTabs).
    <nav ref={row} aria-label={label} className={cn('flex flex-nowrap overflow-x-auto overscroll-x-contain shadow-[inset_0_-1px_0_var(--color-rule)] [scrollbar-width:none] [&::-webkit-scrollbar]:hidden', v && 'lg:grid lg:gap-0.5 lg:overflow-visible lg:shadow-none')}>
      {items.map((x) => (
        <NavLink key={x.to} to={x.to} end={x.end} className={link}>
          <span className="inline-flex items-center gap-1.5">{x.label}{x.badge ? <>{' '}<Counter count={x.badge.count} label={x.badge.label} tone="danger" /></> : null}</span>
        </NavLink>
      ))}
    </nav>
  )
}
