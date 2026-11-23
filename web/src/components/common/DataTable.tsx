import { useEffect, useRef, useSyncExternalStore, type ReactNode } from 'react'
import { useTranslation } from 'react-i18next'
import {
  flexRender, getCoreRowModel, getFilteredRowModel, getPaginationRowModel, getSortedRowModel, useReactTable,
  type ColumnDef, type SortingState, type Row,
} from '@tanstack/react-table'
import { ArrowDown, ArrowUp } from 'lucide-react'
import { Select } from '@/components/ui/input'
import { Button } from '@/components/ui/button'
import { cn } from '@/lib/utils'
import { ListSearch, Pager, RangeText } from './Pager'
import { decodeSort, encodeSort, listKey, useListParams, type ListParams } from './listParams'

export type { ColumnDef }

const NARROW = '(max-width: 767px)'
/** A row that needs a look carries a 3 px bar of its tone at the leading edge (docs/UI.md §5). */
const TONE_BAR = { danger: 'shadow-[inset_3px_0_0_var(--danger)]', warn: 'shadow-[inset_3px_0_0_var(--warn)]' } as const // ui-guard: an inset bar, not a shadow
function useNarrow() {
  return useSyncExternalStore(
    (l) => { if (typeof matchMedia === 'undefined') return () => {}; const m = matchMedia(NARROW); m.addEventListener('change', l); return () => m.removeEventListener('change', l) },
    () => typeof matchMedia !== 'undefined' && matchMedia(NARROW).matches,
    () => false,
  )
}

/**
 * The table is the main component (FRONTEND §3): 40px rows, sticky header, sorting, text filter, 50 per page.
 * `rowTone` paints a left border on rows that need attention (for example "You have it" + being exploited).
 * Every list with rows has a search box, and a list that pages has the same pager above and below it (First, Previous, numbered
 * pages, Next, Last, Go to page, rows per page); the search, the page and the size live in the URL under `urlKey`, so back, reload
 * and a shared link keep them. A list of cards (`list`) goes through the same search and pager: its columns name what the search reads.
 */
export function DataTable<T>({ data, columns, filterPlaceholder, onRowClick, rowTone, empty, emptyFiltered, filtered, onClearFilters, toolbar, pageSize = 50, initialSort, caption, mobileRow, list: listRow, sortSelect, hiddenColumns, fillColumn, search = true, urlKey, resetPageOn, server }: {
  data: T[]
  columns: ColumnDef<T, any>[] // eslint-disable-line @typescript-eslint/no-explicit-any
  filterPlaceholder?: string
  onRowClick?: (row: T) => void
  rowTone?: (row: T) => 'danger' | 'warn' | undefined
  empty?: ReactNode
  /** docs/UI.md §6: shown instead of `empty` when filters hide every row, the table's own text filter or the page's (`filtered`).
   *  Default: "No rows match these filters." and a "Clear filters" button. */
  emptyFiltered?: ReactNode
  /** The page filtered `data` itself (a segment, a select, its own search): an empty table then means "no match", not "nothing yet". */
  filtered?: boolean
  /** Clears the page's filters; the default empty-filtered state calls it from "Clear filters" (the table's own filter is cleared too). */
  onClearFilters?: () => void
  toolbar?: ReactNode
  pageSize?: number
  initialSort?: SortingState
  caption: string
  /** Narrow screen (< 768 px): show a list instead of the table. The content handles its own links/buttons; filtering, sorting and paging are shared. */
  mobileRow?: (row: T) => ReactNode
  /** Every width: show the rows as a list of these items instead of a table (a list of cards with their own buttons). The columns
   *  are then not drawn: they name the text the search reads (an `accessorFn` returning a string) and the sort. */
  list?: (row: T) => ReactNode
  /** "Sort by" select on the table (every width): sortable columns have a text heading, hidden columns included, each in the direction of its first click.
   *  A narrow screen has no column headers to click; a hidden column can only be sorted from here. Turned on per page (#825: the finding list sorts by CVSS). */
  sortSelect?: boolean
  /** A column only for sorting (through `sortSelect`), not shown: its value is already in the cell of another column (#825: CVSS under the risk level). */
  hiddenColumns?: string[]
  /** The column that takes the width the others leave and cuts its content to it (the cell must truncate or wrap), so a long value
   *  never widens the table past its container. */
  fillColumn?: string
  /** false: the page has a search of its own for this list (it filters `data` itself), so the table shows none. */
  search?: boolean
  /** The list's key in the URL query (`<key>.q`, `<key>.page`, `<key>.size`); default: from the caption. */
  urlKey?: string
  /** A value of the page's own filters: when it changes the list goes back to page 1. */
  resetPageOn?: unknown
  /** The server pages the list: `data` is one page, `total` the rows of every page, and `list` (the page's useListParams) the page
   *  and size the page asked for. No search, sort or filter of the table's own: they would act on one page only. */
  server?: { total: number; list: ListParams; max?: number }
}) {
  const { t } = useTranslation()
  const own = useListParams(urlKey ?? listKey(caption))
  const list = server?.list ?? own
  // The sort is the list's (URL) state too, so a list that is rebuilt (a refetch, a tab change, a reload) keeps its order
  const sorting: SortingState = list.sort ? decodeSort(list.sort) : (initialSort ?? [])
  const setSorting = (next: SortingState | ((o: SortingState) => SortingState)) => {
    const n = typeof next === 'function' ? next(sorting) : next
    const code = encodeSort(n)
    list.set({ sort: code === encodeSort(initialSort ?? []) ? '' : code, page: 0 })
  }
  const filter = server || !search ? '' : list.q
  // a size above what the server sends in one page (an old link) reads as the largest it sends
  const size = Math.min(list.size ?? pageSize, server?.max ?? Infinity)
  // The page and size are the list's (URL) state; the server's page is `data` itself (manualPagination)
  const pagination = (pageIndex: number) => ({ pageIndex, pageSize: size })
  const table = useReactTable({
    data, columns, state: { sorting, globalFilter: filter, pagination: pagination(list.page) },
    onSortingChange: setSorting, enableSorting: !server, manualPagination: !!server, autoResetPageIndex: false,
    getCoreRowModel: getCoreRowModel(), getSortedRowModel: getSortedRowModel(), getFilteredRowModel: getFilteredRowModel(), getPaginationRowModel: getPaginationRowModel(),
    initialState: { columnVisibility: Object.fromEntries((hiddenColumns ?? []).map((id) => [id, false])) },
  })
  const count = server ? server.total : table.getPrePaginationRowModel().rows.length
  const pages = Math.max(1, Math.ceil(count / size))
  // A page beyond the last (a shorter list after a filter, an old link) shows the last page; a column header that reads the shown
  // rows (table.getRowModel(), "Select all on this page") reads that page too
  const page = Math.min(list.page, pages - 1)
  if (page !== list.page) table.setOptions((o) => ({ ...o, state: { ...o.state, pagination: pagination(page) } }))
  const rows = table.getRowModel().rows
  // A server-paged list asked for a page past the last (an old link, rows that aged out): the server returned none, so ask for the
  // last page instead of showing an empty table under a pager that says otherwise
  // (a total of 0 is a list not loaded yet or emptied, not a page past the end: the page the URL names is kept)
  const pastEnd = !!server && server.total > 0 && list.page > pages - 1 && data.length === 0
  useEffect(() => { if (pastEnd) list.set({ page: pages - 1 }) }, [pastEnd, pages, list])
  // The page's own filters changed: back to page 1
  // (compared by value: a filter object or array rebuilt on every render is the same filter, not a change)
  const resetKey = JSON.stringify(resetPageOn) ?? ''
  const lastReset = useRef(resetKey)
  useEffect(() => {
    if (lastReset.current === resetKey) return
    lastReset.current = resetKey
    if (list.page !== 0) list.set({ page: 0 })
  }, [resetKey, list])
  const top = useRef<HTMLDivElement>(null)
  const setPage = (p: number, fromBottom = false) => {
    list.set({ page: p })
    if (fromBottom) top.current?.scrollIntoView?.({ block: 'start', behavior: 'smooth' })
  }
  const setSize = (n: number) => list.set({ size: n === pageSize ? undefined : n, page: 0 })
  const sizeChanged = list.size !== undefined && list.size !== pageSize
  const paged = pages > 1 || sizeChanged
  // Every list with rows has a search box (and keeps it while a search is on, also when nothing matches): a person finds the search
  // in the same place on every list, however long it is. A list the server pages searches on the server, with the page's own box.
  const showSearch = !server && search && (data.length > 0 || !!list.q)
  const noMatch = filtered || (data.length > 0 && !!filter)
  const clear = () => { list.set({ q: '', page: 0 }); onClearFilters?.() }
  const none = noMatch
    ? (emptyFiltered ?? (
      <span className="inline-flex flex-wrap items-center justify-center gap-x-2 gap-y-1">
        {t('table.emptyFiltered')}
        {filter || onClearFilters ? <Button size="sm" variant="link" onClick={clear}>{t('table.clearFilters')}</Button> : null}
      </span>
    ))
    : (empty ?? t('table.empty'))
  // Build only ONE layout (a list on a narrow screen, a table on a wide one): no duplicate buttons in the DOM.
  const narrow = useNarrow()
  const rowItem = listRow ?? mobileRow
  const asList = !!listRow || (!!mobileRow && narrow)
  const sortable = sortSelect ? table.getAllLeafColumns().filter((c) => c.getCanSort() && typeof c.columnDef.header === 'string') : []

  return (
    <div ref={top} className="grid scroll-mt-4 gap-3">
      {showSearch || toolbar || paged || filtered ? (
        <div className="flex min-w-0 flex-wrap items-center gap-2">
          {showSearch ? <ListSearch value={list.q} onChange={(q) => list.set({ q, page: 0 })} label={filterPlaceholder ?? t('table.searchIn', { caption })} placeholder={filterPlaceholder ?? t('table.search')} /> : null}
          {toolbar}
          {paged || filter || (filtered && count > 0) ? (
            <div className="ml-auto flex flex-wrap items-center justify-end gap-x-3 gap-y-2">
              <RangeText page={page} size={size} count={count} total={filter ? data.length : undefined} />
              <Pager page={page} pages={pages} onPage={(p) => setPage(p)} label={t('table.pagesTop', { caption })} size={size} onSize={setSize} sizeChanged={sizeChanged} maxSize={server?.max} />
            </div>
          ) : null}
        </div>
      ) : null}
      {sortable.length > 0 ? (
        <Select className="w-full sm:w-auto sm:max-w-64" aria-label={t('table.sortBy')} value={sorting[0]?.id ?? ''}
          onChange={(e) => { const c = table.getColumn(e.target.value); setSorting(c ? [{ id: c.id, desc: c.getFirstSortDir() === 'desc' }] : []) }}>
          {sorting.length === 0 ? <option value="">{t('table.sortBy')}</option> : null}
          {sortable.map((c) => <option key={c.id} value={c.id}>{t('table.sortOption', { column: c.columnDef.header as string })}</option>)}
        </Select>
      ) : null}
      {asList && rowItem ? (
        <ul aria-label={caption} className="grid divide-y divide-rule rounded-md border border-rule bg-surface">
          {rows.length === 0 ? <li className="px-4 py-6 text-center text-muted">{none}</li> : rows.map((r) => {
            const tone = rowTone?.(r.original)
            return <li key={r.id} className={cn('px-4 py-3', tone && TONE_BAR[tone])}>{rowItem(r.original)}</li>
          })}
        </ul>
      ) : (
      <div className="relative overflow-x-auto rounded-md border border-rule bg-surface">
        <table className="w-full border-collapse text-sm">
          <caption className="sr-only">{caption}</caption>
          <thead className="bg-sunken text-left">
            {table.getHeaderGroups().map((hg) => (
              <tr key={hg.id}>
                {hg.headers.map((h) => {
                  const sort = h.column.getIsSorted()
                  return (
                    <th key={h.id} scope="col" aria-sort={sort === 'asc' ? 'ascending' : sort === 'desc' ? 'descending' : undefined} className="h-9 whitespace-nowrap border-b border-rule px-3 text-caption font-medium text-muted">
                      {h.isPlaceholder ? null : h.column.getCanSort() ? (
                        <button type="button" className="-mx-1 inline-flex h-8 items-center gap-1 px-1 hover:text-ink" onClick={h.column.getToggleSortingHandler()}>
                          {flexRender(h.column.columnDef.header, h.getContext())}
                          {sort === 'asc' ? <ArrowUp className="size-3" /> : sort === 'desc' ? <ArrowDown className="size-3" /> : null}
                        </button>
                      ) : flexRender(h.column.columnDef.header, h.getContext())}
                    </th>
                  )
                })}
              </tr>
            ))}
          </thead>
          <tbody>
            {rows.length === 0 ? (
              <tr><td colSpan={columns.length} className="px-3 py-8 text-center text-muted">{none}</td></tr>
            ) : rows.map((r: Row<T>) => {
              const tone = rowTone?.(r.original)
              return (
                <tr
                  key={r.id}
                  onClick={onRowClick ? () => onRowClick(r.original) : undefined}
                  className={cn('h-10 border-b border-rule last:border-b-0', onRowClick && 'cursor-pointer hover:bg-sunken', tone && TONE_BAR[tone])}
                >
                  {r.getVisibleCells().map((c) => <td key={c.id} className={cn('px-3 py-2 align-middle', c.column.id === fillColumn && 'w-full max-w-0')}>{flexRender(c.column.columnDef.cell, c.getContext())}</td>)}
                </tr>
              )
            })}
          </tbody>
        </table>
      </div>
      )}
      {pages > 1 ? (
        <div className="flex flex-wrap items-center justify-end gap-x-3 gap-y-2">
          <RangeText page={page} size={size} count={count} total={filter ? data.length : undefined} />
          <Pager page={page} pages={pages} onPage={(p) => setPage(p, true)} label={t('table.pagesBottom', { caption })} />
        </div>
      ) : null}
    </div>
  )
}
