import { useMemo, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { Button } from '@/components/ui/button'

/**
 * Row selection kept outside the list (D-472): ids survive paging, search and filters. Shared by the scan picker,
 * and meant for the devices list (B7) and incidents. Only a Set of ids; what may be selected is the caller's rule.
 */
export function useRowSelection(init?: () => Iterable<string>) {
  const [ids, setIds] = useState<ReadonlySet<string>>(() => new Set(init?.()))
  const ops = useMemo(() => ({
    toggle: (id: string, on: boolean) => setIds((s) => { const n = new Set(s); if (on) n.add(id); else n.delete(id); return n }),
    add: (list: Iterable<string>) => setIds((s) => new Set([...s, ...list])),
    remove: (list: Iterable<string>) => setIds((s) => { const n = new Set(s); for (const id of list) n.delete(id); return n }),
    replace: (list: Iterable<string>) => setIds(new Set(list)),
    clear: () => setIds(new Set()),
  }), [])
  return [ids, ops] as const
}

/** The state of a group checkbox over `ids`: all, some (indeterminate) or none selected. */
export function groupState(ids: readonly string[], sel: ReadonlySet<string>): boolean | 'indeterminate' {
  const n = ids.filter((id) => sel.has(id)).length
  return n === 0 ? false : n === ids.length ? true : 'indeterminate'
}

/** One page of `items`; the page index is clamped so a shorter list never shows an empty page. */
export function pageOf<T>(items: readonly T[], page: number, size: number) {
  const pages = Math.max(1, Math.ceil(items.length / size))
  const p = Math.min(Math.max(0, page), pages - 1)
  return { rows: items.slice(p * size, (p + 1) * size), page: p, pages }
}

/** Previous / next with "Page n of m", like DataTable's; hidden when there is one page. */
export function Pager({ page, pages, onPage, label }: { page: number; pages: number; onPage: (p: number) => void; label: string }) {
  const { t } = useTranslation()
  if (pages <= 1) return null
  return (
    <nav aria-label={label} className="flex items-center justify-end gap-2 text-[13px] text-muted">
      <span>{t('table.page', { page: page + 1, pages })}</span>
      <Button size="sm" onClick={() => onPage(page - 1)} disabled={page === 0}>{t('table.prev')}</Button>
      <Button size="sm" onClick={() => onPage(page + 1)} disabled={page >= pages - 1}>{t('table.next')}</Button>
    </nav>
  )
}
