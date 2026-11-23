import { useEffect, useRef, type ReactNode } from 'react'
import { Link, Navigate, useLocation, useSearchParams } from 'react-router'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs'
import { Counter } from './Counter'
import { useKeepListParams } from './listParams'

// Page frame (S-UI-1): PageHeader > KpiStrip (optional) > PageTabs. Settings keeps its vertical menu.

export type Kpi = { value: ReactNode; label: string; to: string }

const COLS = ['', 'sm:grid-cols-1', 'sm:grid-cols-2', 'sm:grid-cols-3', 'sm:grid-cols-4']

/** At most 4 numbers that answer the page's question (FRONTEND §3: a big number only when it is the answer), each leading to where the detail is.
 *  One frame divided by rules (like a table row), not 4 separate cards; 2 x 2 on a phone. */
const isZero = (v: ReactNode) => v === 0 || v === '0'

export function KpiStrip({ items: all, label }: { items: Kpi[]; label: string }) {
  // A programming error: reported during development, it does not break the user's page.
  if (all.length > 4 && import.meta.env.DEV) console.error(`KpiStrip "${label}": at most 4 items, got ${all.length}; the rest are dropped`)
  const items = all.slice(0, 4)
  const keep = useKeepListParams()
  return (
    <ul aria-label={label} className={`mb-5 grid grid-cols-2 gap-px overflow-hidden rounded-md border border-rule bg-rule ${COLS[items.length]}`}>
      {items.map((k) => (
        <li key={k.label} className="bg-surface [&:last-child:nth-child(odd)]:col-span-2 sm:[&:last-child:nth-child(odd)]:col-span-1">
          {/* The whole cell is a link (not text in a paragraph): no underline on the number or the label; hover gives a background and underlines the label.
              A 0 opens nothing (a link to an empty list is an action with nothing behind it), so it is plain text. */}
          {isZero(k.value) ? (
            <div className="grid h-full gap-0.5 px-3 py-2">
              <span className="text-lg font-semibold leading-tight tabular-nums">{k.value}</span>{' '}
              <span className="text-meta text-muted">{k.label}</span>
            </div>
          ) : (
            <Link to={keep(k.to)} className="group grid h-full gap-0.5 px-3 py-2 no-underline hover:bg-sunken focus-visible:-outline-offset-2">
              <span className="text-lg font-semibold leading-tight tabular-nums">{k.value}</span>{' '}
              <span className="text-meta text-muted underline-offset-4 group-hover:underline">{k.label}</span>
            </Link>
          )}
        </li>
      ))}
    </ul>
  )
}

/** `badge`: work waiting for the user in that tab (a red number). `label` is the part read after the number for a screen reader, for example "waiting for a decision"
 *  gives the tab name "Requests 3 waiting for a decision" (it contains exactly the visible text, WCAG 2.5.3). */
export type PageTab = { id: string; label: string; panel: ReactNode; badge?: { count: number; label: string; tone?: 'danger' | 'off' } }

/** The open tab is in `?tab=<id>`: reload and Back keep the tab; an unknown or not-allowed id → the first tab. */
export function PageTabs({ tabs, label }: { tabs: PageTab[]; label: string }) {
  const [params, setParams] = useSearchParams()
  const raw = params.get('tab')
  const open = tabs.find((x) => x.id === raw) ?? tabs[0]
  const list = useRef<HTMLDivElement>(null)
  // On a phone the open tab may sit outside the visible part of the tab row: scroll it into view (only the tab row, not the page).
  useEffect(() => {
    const row = list.current
    const el = row?.querySelector<HTMLElement>('[data-state="active"]')
    if (!el || !row) return
    const r = row.getBoundingClientRect()
    const e = el.getBoundingClientRect()
    if (e.left < r.left || e.right > r.right) row.scrollLeft += e.left - r.left - 16
  }, [open?.id])
  if (!open) return null
  if (tabs.length === 1) return <>{open.panel}</>
  return (
    <Tabs
      value={open.id}
      // replace: arrow keys change tab (WAI-ARIA automatic activation); push would make Back walk through every tab visited.
      onValueChange={(v) => { const p = new URLSearchParams(params); p.set('tab', v); setParams(p, { replace: true }) }}
    >
      {/* A horizontally scrolling (overflow) tab row clips everything drawn outside it, so: the line below is an inset shadow (not a border that a -mb-px underline overlaps),
          the focus ring is drawn inside the tab (-outline-offset-2), the scrollbar is hidden (a clipped tab edge shows there are more tabs; the left/right arrows scroll to the tab by themselves). ui-guard: the inset rule under the row. */}
      <TabsList ref={list} aria-label={label} className="flex-nowrap overflow-x-auto overscroll-x-contain border-b-0 shadow-[inset_0_-1px_0_var(--color-rule)] [scrollbar-width:none] [&::-webkit-scrollbar]:hidden">
        {tabs.map((x) => (
          // relative: the badge's screen-reader text is absolutely positioned; inside a positioned tab it is clipped with the row,
          // else it sits where the tab would be and widens the page on a phone when the tab is scrolled out of view.
          <TabsTrigger key={x.id} value={x.id} className="relative mb-0 inline-flex shrink-0 items-center gap-1.5 whitespace-nowrap focus-visible:-outline-offset-2">
            {x.label}{' '}
            {x.badge ? <Counter count={x.badge.count} label={x.badge.label} tone={x.badge.tone ?? 'danger'} /> : null}
          </TabsTrigger>
        ))}
      </TabsList>
      {tabs.map((x) => <TabsContent key={x.id} value={x.id}>{x.panel}</TabsContent>)}
    </Tabs>
  )
}

/** An old `#<part>` link of a page that moved to tabs → `?tab=<id>`, keeping the other parameters and dropping the hash.
 *  Only the names in `map`; any other hash (for example `#main` of "Skip to content") is left alone. Returns null when there is nothing to redirect. */
export function OldHashToTab({ map }: { map: Record<string, string> }) {
  const { hash, search } = useLocation()
  const tab = Object.hasOwn(map, hash.slice(1)) ? map[hash.slice(1)] : undefined
  if (!tab) return null
  const p = new URLSearchParams(search)
  p.set('tab', tab)
  return <Navigate replace to={{ search: `?${p}`, hash: '' }} />
}
