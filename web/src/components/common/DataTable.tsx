import { useState, useSyncExternalStore, type ReactNode } from 'react'
import { useTranslation } from 'react-i18next'
import {
  flexRender, getCoreRowModel, getFilteredRowModel, getPaginationRowModel, getSortedRowModel, useReactTable,
  type ColumnDef, type SortingState, type Row,
} from '@tanstack/react-table'
import { ArrowDown, ArrowUp } from 'lucide-react'
import { Input, Select } from '@/components/ui/input'
import { Button } from '@/components/ui/button'
import { cn } from '@/lib/utils'

export type { ColumnDef }

const NARROW = '(max-width: 767px)'
function useNarrow() {
  return useSyncExternalStore(
    (l) => { if (typeof matchMedia === 'undefined') return () => {}; const m = matchMedia(NARROW); m.addEventListener('change', l); return () => m.removeEventListener('change', l) },
    () => typeof matchMedia !== 'undefined' && matchMedia(NARROW).matches,
    () => false,
  )
}

/**
 * Bảng là thành phần chính (FRONTEND §3): 40px/dòng, header dính, sắp xếp, lọc chữ, phân trang 50.
 * `rowTone` tô viền trái cho dòng cần chú ý (ví dụ "Anh có" + đang bị khai thác).
 */
export function DataTable<T>({ data, columns, filterPlaceholder, onRowClick, rowTone, empty, emptyFiltered, filtered, onClearFilters, toolbar, pageSize = 50, initialSort, caption, mobileRow, sortSelect, hiddenColumns }: {
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
  /** Màn hẹp (< 768 px): hiện danh sách thay cho bảng. Nội dung tự lo link/nút; lọc, sắp xếp, phân trang dùng chung. */
  mobileRow?: (row: T) => ReactNode
  /** Ô chọn "Sort by" trên bảng (mọi độ rộng): các cột sắp xếp được có tiêu đề chữ, kể cả cột ẩn, mỗi cột theo chiều bấm đầu tiên của nó.
   *  Màn hẹp không có tiêu đề cột để bấm; cột ẩn chỉ sắp được từ đây. Bật theo trang (#825: danh sách finding sắp theo CVSS). */
  sortSelect?: boolean
  /** Cột chỉ để sắp xếp (qua `sortSelect`), không hiện: giá trị của nó đã nằm trong ô của cột khác (#825: CVSS dưới mức rủi ro). */
  hiddenColumns?: string[]
}) {
  const { t } = useTranslation()
  const [sorting, setSorting] = useState<SortingState>(initialSort ?? [])
  const [filter, setFilter] = useState('')
  const table = useReactTable({
    data, columns, state: { sorting, globalFilter: filter },
    onSortingChange: setSorting, onGlobalFilterChange: setFilter,
    getCoreRowModel: getCoreRowModel(), getSortedRowModel: getSortedRowModel(), getFilteredRowModel: getFilteredRowModel(),
    getPaginationRowModel: getPaginationRowModel(), initialState: { pagination: { pageSize }, columnVisibility: Object.fromEntries((hiddenColumns ?? []).map((id) => [id, false])) },
  })
  const rows = table.getRowModel().rows
  const noMatch = filtered || (data.length > 0 && !!filter)
  const clear = () => { setFilter(''); onClearFilters?.() }
  const none = noMatch
    ? (emptyFiltered ?? (
      <span className="inline-flex flex-wrap items-center justify-center gap-x-2 gap-y-1">
        {t('table.emptyFiltered')}
        {filter || onClearFilters ? <Button size="sm" variant="link" onClick={clear}>{t('table.clearFilters')}</Button> : null}
      </span>
    ))
    : (empty ?? t('table.empty'))
  // Chỉ dựng MỘT bố cục (danh sách trên màn hẹp, bảng trên màn rộng): không có nút trùng lặp trong DOM.
  const narrow = useNarrow()
  const asList = !!mobileRow && narrow
  const pages = table.getPageCount()
  const sortable = sortSelect ? table.getAllLeafColumns().filter((c) => c.getCanSort() && typeof c.columnDef.header === 'string') : []

  return (
    <div className="grid gap-3">
      {filterPlaceholder || toolbar ? (
        <div className="flex min-w-0 flex-wrap items-center gap-2">
          {filterPlaceholder ? <Input className="h-9 max-w-xs sm:h-8" value={filter} onChange={(e) => setFilter(e.target.value)} placeholder={filterPlaceholder} aria-label={filterPlaceholder} /> : null}
          {toolbar}
        </div>
      ) : null}
      {sortable.length > 0 ? (
        <Select className="w-full sm:w-auto sm:max-w-64" aria-label={t('table.sortBy')} value={sorting[0]?.id ?? ''}
          onChange={(e) => { const c = table.getColumn(e.target.value); setSorting(c ? [{ id: c.id, desc: c.getFirstSortDir() === 'desc' }] : []) }}>
          {sorting.length === 0 ? <option value="">{t('table.sortBy')}</option> : null}
          {sortable.map((c) => <option key={c.id} value={c.id}>{t('table.sortOption', { column: c.columnDef.header as string })}</option>)}
        </Select>
      ) : null}
      {asList && mobileRow ? (
        <ul aria-label={caption} className="grid divide-y divide-rule rounded-md border border-rule bg-surface">
          {rows.length === 0 ? <li className="px-4 py-6 text-center text-muted">{none}</li> : rows.map((r) => {
            const tone = rowTone?.(r.original)
            return <li key={r.id} className={cn('px-4 py-3', tone === 'danger' && 'shadow-[inset_3px_0_0_var(--danger)]', tone === 'warn' && 'shadow-[inset_3px_0_0_var(--warn)]')}>{mobileRow(r.original)}</li>
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
                  className={cn('h-10 border-b border-rule last:border-b-0', onRowClick && 'cursor-pointer hover:bg-sunken', tone === 'danger' && 'shadow-[inset_3px_0_0_var(--danger)]', tone === 'warn' && 'shadow-[inset_3px_0_0_var(--warn)]')}
                >
                  {r.getVisibleCells().map((c) => <td key={c.id} className="px-3 py-2 align-middle">{flexRender(c.column.columnDef.cell, c.getContext())}</td>)}
                </tr>
              )
            })}
          </tbody>
        </table>
      </div>
      )}
      {pages > 1 ? (
        <div className="flex items-center justify-end gap-2 text-meta text-muted">
          <span>{t('table.page', { page: table.getState().pagination.pageIndex + 1, pages })}</span>
          <Button size="sm" onClick={() => table.previousPage()} disabled={!table.getCanPreviousPage()}>{t('table.prev')}</Button>
          <Button size="sm" onClick={() => table.nextPage()} disabled={!table.getCanNextPage()}>{t('table.next')}</Button>
        </div>
      ) : null}
    </div>
  )
}
