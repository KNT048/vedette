import { useMemo, useState } from 'react'

/**
 * Row selection kept outside the list: ids survive paging, search and filters. Shared by the scan picker,
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
