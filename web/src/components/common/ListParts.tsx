import { Children, isValidElement, type MouseEvent, type ReactNode } from 'react'
import { Link } from 'react-router'
import { ChevronDown } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { cn } from '@/lib/utils'
import { ListSearch } from './Pager'

// The parts every list shares (docs/UI.md §5), so a list reads the same on every page and tab:
//   ListToolbar  the one row above a list: search first, then the filters, then the list's actions on the right;
//   ListSummary  the one count line under it ("7 devices, 16 open findings"), the shape "<rows>, <qualifier>";
//   ListRow      one row of a list of cards: rank, toggle | title (RowTitle), note, badges + at most two meta lines | actions;
//   RowTitle     the name of a row's object in a list or a table: primary colour, medium, a link only by its hover underline;
//   RowList      the rows of a list of cards outside a DataTable, or inside an opened row;
//   ExpandToggle the chevron that opens a row, one size and one turn everywhere.
// DataTable draws its own toolbar and summary with these; a page that keeps the search above a server-paged list (so the box keeps
// its focus while the next page loads) builds the same row with ListToolbar. The layout guard (src/test/layoutGuard.test.ts) keeps
// pages on them.

export type ListSearchProps = { value: string; onChange: (q: string) => void; label: string; placeholder?: string }

/** The row above a list. `children` are the filters (Segmented, Select, toggles), after the search; `actions` sit at the right
 *  end (Export, Add …), the primary one last. Wraps on a narrow screen, the search on a row of its own. */
export function ListToolbar({ search, children, actions, label, className }: { search?: ListSearchProps; children?: ReactNode; actions?: ReactNode; label?: string; className?: string }) {
  if (!search && !children && !actions) return null
  return (
    // `label`: the row is a search landmark of that name (the filters of a list that has several)
    <div data-list-toolbar="" role={label ? 'search' : undefined} aria-label={label} className={cn('flex min-w-0 flex-wrap items-center gap-2', className)}>
      {search ? <ListSearch value={search.value} onChange={search.onChange} label={search.label} placeholder={search.placeholder} /> : null}
      {children}
      {actions ? <div className="ml-auto flex flex-wrap items-center justify-end gap-2">{actions}</div> : null}
    </div>
  )
}

/** The list's one count line, read out as it changes (WCAG 4.1.3). Text shape: "<count> <rows>" with an optional qualifier after a
 *  comma ("34 devices, 2 not added yet", "9 fixes, 16 open findings"). `id` names it for a page's tests (`data-count`); `actions`
 *  are the buttons that act on the whole list as it is shown (Add all, Export CSV), at the right end of the same line. */
export function ListSummary({ children, id, actions, className }: { children: ReactNode; id?: string; actions?: ReactNode; className?: string }) {
  // a div, not a p: the line may end with an ⓘ (InfoTip), whose popover is not phrasing content
  const line = <div role="status" aria-live="polite" data-count={id} className={cn('flex flex-wrap items-center gap-1 text-meta text-muted tabular-nums', !actions && className)}>{children}</div>
  if (!actions) return line
  return <div className={cn('flex flex-wrap items-center justify-between gap-x-4 gap-y-2', className)}>{line}<div className="flex flex-wrap items-center gap-2">{actions}</div></div>
}

/** Opens and closes one row's or block's detail: a chevron that points right when closed and down when open, everywhere. Without
 *  `children` it is the 32 px icon before a row's title (`label` names what opens: "Show FW-HQ's fixes"); with `children` it is a
 *  small text button ("Settings", "Details") that opens a part below it. `controls` is the id of the part it opens. */
export function ExpandToggle({ open, onToggle, label, controls, children }: { open: boolean; onToggle: () => void; label?: string; controls?: string; children?: ReactNode }) {
  const chevron = <ChevronDown aria-hidden className={cn('transition-transform', !open && '-rotate-90')} />
  if (children) {
    return <Button type="button" variant="ghost" size="sm" aria-expanded={open} aria-controls={controls} aria-label={label} onClick={onToggle} className="-ml-2 w-fit">{chevron}{children}</Button>
  }
  return (
    <Button type="button" variant="ghost" size="icon" aria-expanded={open} aria-controls={controls} aria-label={label} onClick={onToggle} className="size-8 shrink-0 sm:size-8">
      {chevron}
    </Button>
  )
}

/** The name of a row's object, as every list and table shows it (docs/UI.md §5): the primary text colour, weight medium. With `to`
 *  (a page of the app) or `href` (a page elsewhere) it is a link that says so by its underline on hover, never by another colour:
 *  the row is already the thing to click (GitHub's issue titles, Linear's and Tailscale's rows). A table's name cell uses it as is. */
export function RowTitle({ children, to, href, title, label, className }: { children: ReactNode; to?: string; href?: string; title?: string; label?: string; className?: string }) {
  const cls = cn('font-medium text-ink [overflow-wrap:anywhere]', className)
  // a row that opens on click keeps its own handler: the title's own click only follows the link
  const stop = (e: MouseEvent) => e.stopPropagation()
  const link = cn(cls, 'no-underline underline-offset-4 hover:underline')
  if (to) return <Link to={to} title={title} aria-label={label} onClick={stop} className={link}>{children}</Link>
  if (href) return <a href={href} title={title} aria-label={label} target="_blank" rel="noopener noreferrer" onClick={stop} className={link}>{children}</a>
  return <span title={title} className={cls}>{children}</span>
}

/** The toggle of a row that opens: `label` names what opens ("Show FW-HQ's fixes"), `controls` the id of the part it opens. */
export type RowToggle = { open: boolean; onToggle: () => void; label: string; controls?: string }

/**
 * One row of a list of cards (By device, By fix, a review queue, the rows inside an opened row): one anatomy everywhere, built from
 * props so no page styles its own row:
 *   rank     the row's place when the list is ordered by priority (the order to act in), before everything
 *   toggle   the ExpandToggle of a row that opens; `toggle={null}` holds its place in a list where only some rows open
 *   title    the row's object, drawn by RowTitle (a link with `to` or `href`), then `sub` (a short muted note: an address, a
 *            version) and `badges` on the same line
 *   meta     at most two short muted lines under it
 *   actions  the row's buttons, on the right, vertically centred on the title block
 *   children the opened part (or a row's details that are always shown), under the title block, indented to it
 *   off      a row that is turned off (a disabled connection): dimmed
 */
export function ListRow({ rank, toggle, title, to, href, sub, badges, meta, actions, children, label, testId, off = false }: {
  rank?: number; toggle?: RowToggle | null; title: ReactNode; to?: string; href?: string; sub?: ReactNode; badges?: ReactNode
  meta?: readonly [ReactNode?, ReactNode?]; actions?: ReactNode; children?: ReactNode; label?: string; testId?: string; off?: boolean
}) {
  const lines = (meta ?? []).filter((m) => m !== null && m !== undefined && m !== false && m !== '')
  const lead = rank !== undefined || toggle !== undefined
  // the opened part starts under the title: rank 20 px + toggle 32 px, each with its 4 px gap
  const indent = rank !== undefined ? (toggle !== undefined ? 'sm:pl-15' : 'sm:pl-6') : toggle !== undefined ? 'sm:pl-9' : undefined
  return (
    <article aria-label={label} data-testid={testId} className={cn('grid gap-2', off && 'opacity-70')}>
      <div className="flex flex-wrap items-center justify-between gap-x-4 gap-y-2">
        {/* basis-64: on a narrow row the actions wrap under the title block instead of squeezing it */}
        <div className="flex min-w-0 flex-1 basis-64 items-start gap-1">
          {lead ? (
            <div className="flex shrink-0 items-center gap-1">
              {rank !== undefined ? <span aria-hidden className="w-5 text-right text-sm leading-6 font-medium text-muted tabular-nums" data-rank={rank}>{rank}</span> : null}
              {toggle ? <ExpandToggle open={toggle.open} onToggle={toggle.onToggle} label={toggle.label} controls={toggle.controls} />
                : toggle === null ? <span aria-hidden className="size-8 shrink-0" /> : null}
            </div>
          ) : null}
          {/* the title line is one badge high (24 px): a rank lines up with it, a 32 px toggle centres on it */}
          <div className={cn('grid min-w-0 gap-0.5', toggle !== undefined && 'pt-1')}>
            <div className="flex min-h-6 flex-wrap items-center gap-x-2 gap-y-1 text-sm">
              <RowTitle to={to} href={href}>{title}</RowTitle>
              {sub ? <span className="text-meta text-muted [overflow-wrap:anywhere]">{sub}</span> : null}
              {badges}
            </div>
            {lines.map((m, i) => <div key={i} className="flex flex-wrap items-center gap-x-2 gap-y-1 text-meta text-muted">{m}</div>)}
          </div>
        </div>
        {actions ? <div className="flex shrink-0 flex-wrap items-center gap-2">{actions}</div> : null}
      </div>
      {Children.toArray(children).length ? <div className={cn('min-w-0', indent)}>{children}</div> : null}
    </article>
  )
}

/** The rows of a list of cards outside a DataTable, each a ListRow. `boxed`: a list of its own, drawn as DataTable draws one (rule
 *  border, rows px-4 py-3); `flush`: the same rows in a flush Card, which draws the border; neither: the rows inside an opened row,
 *  divided by a rule with the same row gap. `ordered`: the order is the point (ranked rows). */
export function RowList({ label, id, boxed = false, flush = false, ordered = false, children }: { label: string; id?: string; boxed?: boolean; flush?: boolean; ordered?: boolean; children: ReactNode }) {
  const L = ordered ? 'ol' : 'ul'
  return (
    <L id={id} aria-label={label} className={cn('grid divide-y divide-rule', boxed && 'rounded-md border border-rule bg-surface')}>
      {Children.toArray(children).map((c, i) => <li key={isValidElement(c) && c.key !== null ? c.key : i} className={boxed || flush ? 'px-4 py-3' : 'py-3 first:pt-0 last:pb-0'}>{c}</li>)}
    </L>
  )
}
