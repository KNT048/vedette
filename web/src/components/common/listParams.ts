import { useCallback, useMemo, useState } from 'react'
import { useInRouterContext, useLocation, useSearchParams } from 'react-router'

/** A list's search, page (0-based), page size (undefined = the list's default) and sort ("" = the list's default order; "name" is
 *  ascending, "-name" descending). */
export type ListState = { q: string; page: number; size: number | undefined; sort: string }
export type ListParams = ListState & { set: (patch: Partial<ListState>) => void }

/** The URL key of a list from its caption: "Software of this device" → "software-of-this-device", at most 24 characters. */
export function listKey(caption: string): string {
  return caption.toLowerCase().normalize('NFKD').replace(/[^a-z0-9]+/g, '-').replace(/^-+|-+$/g, '').slice(0, 24).replace(/-+$/, '') || 'list'
}

/** The sort of a list as a sorting state, and back: one column, the leading "-" meaning descending. */
export const decodeSort = (v: string): { id: string; desc: boolean }[] => (v ? [{ id: v.replace(/^-/, ''), desc: v.startsWith('-') }] : [])
export const encodeSort = (s: { id: string; desc: boolean }[]): string => (s[0] ? `${s[0].desc ? '-' : ''}${s[0].id}` : '')

/** The keys a list keeps in the URL: `<key>.q`, `.page`, `.size`, `.sort`. */
const LIST_KEY = /^[a-z0-9-]+\.(?:q|page|size|sort)$/

/** A link inside the page that changes the page's own query (`?tab=software`) keeps every list's search, page, size and sort: the
 *  query of the link is laid over the current one, and only the list keys are carried over (a filter the link names is the link's).
 *  Anything but a query-only link (`/findings?tab=open`, `#top`) is returned as it is. */
export function keepListParams(to: string, search: string): string {
  if (!to.startsWith('?')) return to
  const hash = to.indexOf('#')
  const own = new URLSearchParams(hash < 0 ? to.slice(1) : to.slice(1, hash))
  const merged = new URLSearchParams()
  for (const [k, v] of new URLSearchParams(search)) if (LIST_KEY.test(k) && !own.has(k)) merged.append(k, v)
  for (const [k, v] of own) merged.append(k, v)
  const qs = merged.toString()
  return `${qs ? `?${qs}` : '?'}${hash < 0 ? '' : to.slice(hash)}`
}

/** The largest page a server-paged list accepts (the API's limit cap): a bigger size in the URL reads as this one. */
export const MAX_PAGE_SIZE = 200

const int = (v: string | null) => {
  const n = v === null ? Number.NaN : Number.parseInt(v, 10)
  return Number.isFinite(n) && n > 0 ? n : undefined
}

/** `<key>.q`, `<key>.page` (1-based) and `<key>.size` in the URL query: back, forward, reload and a shared link keep them. The
 *  default of each (no search, page 1, the list's size) leaves the key out. */
function useUrlList(key: string): ListParams {
  const [params, setParams] = useSearchParams()
  const k = useCallback((n: string) => `${key}.${n}`, [key])
  const q = params.get(k('q')) ?? ''
  const page = (int(params.get(k('page'))) ?? 1) - 1
  const asked = int(params.get(k('size')))
  const size = asked === undefined ? undefined : Math.min(asked, MAX_PAGE_SIZE)
  const sort = params.get(k('sort')) ?? ''
  const set = useCallback((patch: Partial<ListState>) => {
    setParams((prev) => {
      const p = new URLSearchParams(prev)
      const put = (n: string, v: string | undefined) => { if (v) p.set(k(n), v); else p.delete(k(n)) }
      if ('q' in patch) put('q', patch.q?.trim() || undefined)
      if ('page' in patch) put('page', patch.page ? String(patch.page + 1) : undefined)
      if ('size' in patch) put('size', patch.size ? String(patch.size) : undefined)
      if ('sort' in patch) put('sort', patch.sort || undefined)
      return p
    }, { replace: true, preventScrollReset: true })
  }, [setParams, k])
  return useMemo(() => ({ q, page, size, sort, set }), [q, page, size, sort, set])
}

/** The same state kept in the component, for a list rendered outside a router (a test of the component alone). */
function useLocalList(): ListParams {
  const [s, setS] = useState<ListState>({ q: '', page: 0, size: undefined, sort: '' })
  const set = useCallback((patch: Partial<ListState>) => setS((o) => ({ ...o, ...patch })), [])
  return useMemo(() => ({ ...s, set }), [s, set])
}

/** A list's search, page and size: in the URL under `key` inside the app's router, in the component outside one. The choice is made
 *  once per mounted list (a list never moves in or out of a router), so the hooks run in the same order on every render. */
export function useListParams(key: string): ListParams {
  const inRouter = useInRouterContext()
  const impl: (key: string) => ListParams = inRouter ? useUrlList : useLocalList
  return impl(key)
}

/** `keepListParams` for the page being shown: `const to = useKeepListParams()` then `<Link to={to('?tab=software')}>`. */
export function useKeepListParams(): (to: string) => string {
  const { search } = useLocation()
  return useCallback((to: string) => keepListParams(to, search), [search])
}
