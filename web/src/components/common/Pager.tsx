import { useEffect, useId, useRef, useState, type ReactNode } from 'react'
import { useTranslation } from 'react-i18next'
import { ChevronLeft, ChevronRight, ChevronsLeft, ChevronsRight, Search } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { Input, Select } from '@/components/ui/input'
import { cn } from '@/lib/utils'

/** The page sizes a list offers; a list's own default is added when it is not one of them. */
export const PAGE_SIZES = [25, 50, 100, 200] as const

/** How long typing rests before a search filters the list. */
export const SEARCH_DEBOUNCE_MS = 250

/** The page buttons to show (0-based): the first, the last, the current one and its neighbours, and enough near either end that the
 *  row keeps the same length; null is a gap ("…"). Every page when there are 7 or fewer. */
export function pageItems(page: number, pages: number): (number | null)[] {
  if (pages <= 7) return Array.from({ length: pages }, (_, i) => i)
  const keep = new Set([0, pages - 1, page - 1, page, page + 1])
  if (page <= 3) for (let i = 1; i <= 4; i++) keep.add(i)
  if (page >= pages - 4) for (let i = pages - 5; i <= pages - 2; i++) keep.add(i)
  const sorted = [...keep].filter((p) => p >= 0 && p < pages).sort((a, b) => a - b)
  const out: (number | null)[] = []
  for (const p of sorted) {
    const prev = out.at(-1)
    if (typeof prev === 'number' && p - prev === 2) out.push(prev + 1) // a gap of one page shows that page, not "…"
    else if (typeof prev === 'number' && p - prev > 2) out.push(null)
    out.push(p)
  }
  return out
}

/** The sizes offered for a list whose default is `size`; `max`: the most rows the list's server sends in one page, so no size is offered
 *  that would show fewer rows than it says ("200" that shows "1–100 of 196"). */
export function pageSizes(size: number, max = Infinity): number[] {
  return [...new Set([...PAGE_SIZES, size])].filter((n) => Number.isFinite(n) && n > 0 && n <= max).sort((a, b) => a - b)
}

/**
 * The pages of a list: First, Previous, numbered pages with "…", Next, Last, "Go to page" (Enter jumps) and the page size. The same
 * control sits above and below a list; `label` tells the two apart for a screen reader. Page numbers are 0-based here, 1-based on
 * screen. Hidden when there is one page and the size is the list's default (`sizeChanged` false): nothing to move to or undo.
 */
export function Pager({ page, pages, onPage, label, size, onSize, sizeChanged, maxSize, className }: {
  page: number
  pages: number
  onPage: (p: number) => void
  label: string
  /** The rows per page and its setter; without them no size select is shown. */
  size?: number
  onSize?: (n: number) => void
  sizeChanged?: boolean
  /** The most rows the server sends in one page: larger sizes are not offered. */
  maxSize?: number
  className?: string
}) {
  const { t } = useTranslation()
  const id = useId()
  const [goTo, setGoTo] = useState('')
  if (pages <= 1 && !sizeChanged) return null
  const last = pages - 1
  const go = (p: number) => onPage(Math.min(Math.max(0, p), Math.max(0, last)))
  const jump = () => {
    const n = Number.parseInt(goTo, 10)
    if (!Number.isFinite(n)) return
    go(n - 1)
    setGoTo('')
  }
  return (
    <nav aria-label={label} className={cn('flex flex-wrap items-center justify-end gap-x-1 gap-y-2 text-meta text-muted', className)}>
      {pages > 1 ? (
        <>
          <Button size="sm" variant="ghost" onClick={() => go(0)} disabled={page === 0} aria-label={t('table.first')} title={t('table.first')}><ChevronsLeft /></Button>
          <Button size="sm" variant="ghost" onClick={() => go(page - 1)} disabled={page === 0}><ChevronLeft />{t('table.prev')}</Button>
          <span className="hidden items-center gap-1 sm:flex">
            {pageItems(page, pages).map((p, i) => p === null
              ? <span key={`gap-${i}`} aria-hidden className="px-1">…</span>
              : (
                <Button key={p} size="sm" variant={p === page ? 'secondary' : 'ghost'} className="min-w-8 px-2 tabular-nums" onClick={() => go(p)}
                  aria-current={p === page ? 'page' : undefined} aria-label={t('table.pageN', { page: p + 1 })}>{p + 1}</Button>
              ))}
          </span>
          <span className="px-1 tabular-nums sm:hidden">{t('table.page', { page: page + 1, pages })}</span>
          <Button size="sm" variant="ghost" onClick={() => go(page + 1)} disabled={page >= last}>{t('table.next')}<ChevronRight /></Button>
          <Button size="sm" variant="ghost" onClick={() => go(last)} disabled={page >= last} aria-label={t('table.last')} title={t('table.last')}><ChevronsRight /></Button>
          <form className="ml-1 flex items-center gap-1.5" onSubmit={(e) => { e.preventDefault(); jump() }}>
            <label htmlFor={`${id}-go`} className="whitespace-nowrap">{t('table.goTo')}</label>
            <Input id={`${id}-go`} type="number" inputMode="numeric" value={goTo} onChange={(e) => setGoTo(e.target.value)}
              placeholder={String(page + 1)} className="h-9 w-16 px-2 sm:h-8" />
            <Button size="sm" type="submit" disabled={goTo === ''}>{t('table.go')}</Button>
          </form>
        </>
      ) : null}
      {size !== undefined && onSize ? (
        <span className="ml-1 flex items-center gap-1.5">
          <label htmlFor={`${id}-size`} className="whitespace-nowrap">{t('table.size')}</label>
          <Select id={`${id}-size`} value={size} onChange={(e) => onSize(Number(e.target.value))} className="h-9 w-auto sm:h-8">
            {pageSizes(size, maxSize).map((n) => <option key={n} value={n}>{n}</option>)}
          </Select>
        </span>
      ) : null}
    </nav>
  )
}

/**
 * The search box of a list. It filters as the person types, once typing rests (SEARCH_DEBOUNCE_MS); Enter applies it at once.
 * `value` is the search in force (the list's, often in the URL); a change of it from outside (back, a link) shows in the box.
 */
export function ListSearch({ id, value, onChange, label, placeholder, className }: {
  id?: string
  value: string
  onChange: (q: string) => void
  label: string
  placeholder?: string
  className?: string
}) {
  const [text, setText] = useState(value)
  const [seen, setSeen] = useState(value)
  const timer = useRef<ReturnType<typeof setTimeout> | undefined>(undefined)
  const latest = useRef(onChange)
  useEffect(() => { latest.current = onChange })
  useEffect(() => () => clearTimeout(timer.current), [])
  // The search changed from outside (back, a link, Clear filters): the box shows it
  if (value !== seen) {
    setSeen(value)
    if (value !== text.trim()) setText(value)
  }
  const commit = (v: string) => { clearTimeout(timer.current); if (v.trim() !== value) latest.current(v.trim()) }
  return (
    <div className={cn('relative w-full sm:max-w-xs', className)}>
      <Search aria-hidden className="pointer-events-none absolute top-1/2 left-2.5 size-4 -translate-y-1/2 text-muted" />
      <Input id={id} type="search" value={text} aria-label={label} placeholder={placeholder ?? label} className="h-9 pl-8 sm:h-8"
        onChange={(e) => {
          const v = e.target.value
          setText(v)
          clearTimeout(timer.current)
          timer.current = setTimeout(() => commit(v), SEARCH_DEBOUNCE_MS)
        }}
        onKeyDown={(e) => { if (e.key === 'Enter') { e.preventDefault(); commit(text) } }} />
    </div>
  )
}

/** "1–50 of 290" (or "1–20 of 35 matching, 290 in all" while a search or a filter narrows the list). */
export function RangeText({ page, size, count, total, children }: { page: number; size: number; count: number; total?: number; children?: ReactNode }) {
  const { t } = useTranslation()
  const from = count === 0 ? 0 : page * size + 1
  const to = Math.min(count, (page + 1) * size)
  const narrowed = total !== undefined && total !== count
  return (
    <p role="status" className="text-meta whitespace-nowrap text-muted tabular-nums">
      {count === 0 && narrowed ? t('table.noneOf', { total })
        : narrowed ? t('table.rangeFiltered', { from, to, count, total })
          : t('table.range', { from, to, count })}
      {children}
    </p>
  )
}
