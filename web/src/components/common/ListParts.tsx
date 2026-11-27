import { Children, type ReactNode } from 'react'
import { ChevronDown } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { cn } from '@/lib/utils'
import { ListSearch } from './Pager'

// The parts every list shares (docs/UI.md §5), so a list reads the same on every page and tab:
//   ListToolbar  the one row above a list: search first, then the filters, then the list's actions on the right;
//   ListSummary  the one count line under it ("7 devices, 16 open findings"), the shape "<rows>, <qualifier>";
//   ListRow      one row of a list of cards: lead (ExpandToggle, a rank) | title line + meta lines | actions on the right;
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

/**
 * One row of a list of cards (By device, By fix, a review queue): one anatomy everywhere.
 *   lead     what stands before the title: an ExpandToggle, a rank number (both, in that order, when there are two)
 *   title    the row's name, a link when it has a page (font-semibold), with its badges after it on the same line
 *   meta     the lines under the title, each one short (text-meta, muted)
 *   actions  the row's buttons, on the right, vertically centred on the title block
 *   children the opened part (an ExpandToggle's panel), under the title block, indented to it
 */
export function ListRow({ lead, title, meta, actions, children, label, className }: {
  lead?: ReactNode; title: ReactNode; meta?: ReactNode[]; actions?: ReactNode; children?: ReactNode; label?: string; className?: string
}) {
  const lines = (meta ?? []).filter((m) => m !== null && m !== undefined && m !== false && m !== '')
  return (
    <article aria-label={label} className={cn('grid gap-2', className)}>
      <div className="flex flex-wrap items-center justify-between gap-x-4 gap-y-2">
        {/* basis-64: on a narrow row the actions wrap under the title block instead of squeezing it */}
        <div className="flex min-w-0 flex-1 basis-64 items-start gap-1">
          {lead ? <div className="flex shrink-0 items-center gap-1">{lead}</div> : null}
          <div className={cn('grid min-w-0 gap-0.5', lead && 'pt-1')}>
            <div className="flex flex-wrap items-center gap-x-2 gap-y-1 text-sm">{title}</div>
            {lines.map((m, i) => <div key={i} className="flex flex-wrap items-center gap-x-2 gap-y-1 text-meta text-muted">{m}</div>)}
          </div>
        </div>
        {actions ? <div className="flex shrink-0 flex-wrap items-center gap-2">{actions}</div> : null}
      </div>
      {Children.toArray(children).length ? <div className={cn('min-w-0', lead && 'sm:pl-9')}>{children}</div> : null}
    </article>
  )
}

/** Holds an ExpandToggle's place in a row that opens nothing, so its title lines up with the rows that do. */
export function LeadSpacer() {
  return <span aria-hidden className="size-8 shrink-0" />
}

/** The rank of a row in an ordered list (By fix: the order to do them in), before its title. */
export function RowRank({ n }: { n: number }) {
  return <span aria-hidden className="w-5 text-right text-sm font-semibold text-muted tabular-nums" data-rank={n}>{n}</span>
}
