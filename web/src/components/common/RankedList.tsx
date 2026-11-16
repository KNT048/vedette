import type { ReactNode } from 'react'

/**
 * A short ranked list (docs/UI.md §5: a divided list of rows, for a flush `Card`), e.g. Home's "Fix first" (#825). An ordered list: the
 * order is the point, so each row shows its rank. More than a handful of rows is a DataTable, not this.
 */
export function RankedList({ label, children }: { label: string; children: ReactNode }) {
  return <ol aria-label={label} className="divide-y divide-rule">{children}</ol>
}

/**
 * One row: rank, `title` (a real link to the item, for the keyboard), `meta` (one muted line under it) and `aside` (chips and the CVSS
 * line). From `md` the aside sits on the right of the row; on phones it goes under the meta line, aligned with the title.
 */
export function RankedRow({ rank, title, meta, aside }: { rank: number; title: ReactNode; meta?: ReactNode; aside?: ReactNode }) {
  return (
    <li className="grid grid-cols-[auto_minmax(0,1fr)] items-start gap-x-3 gap-y-2 px-4 py-3 md:grid-cols-[auto_minmax(0,1fr)_auto] md:items-center">
      <span aria-hidden className="w-4 pt-px text-right text-meta text-muted tabular-nums md:pt-0">{rank}</span>
      <div className="grid min-w-0 gap-0.5">
        <div className="min-w-0 text-sm font-medium [overflow-wrap:anywhere]">{title}</div>
        {meta ? <div className="flex min-w-0 flex-wrap gap-x-3 gap-y-0.5 text-meta text-muted">{meta}</div> : null}
      </div>
      {aside ? <div className="col-start-2 grid justify-items-start gap-1.5 md:col-start-3 md:justify-items-end">{aside}</div> : null}
    </li>
  )
}
