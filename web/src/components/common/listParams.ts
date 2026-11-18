import { useCallback, useMemo, useState } from 'react'
import { useInRouterContext, useSearchParams } from 'react-router'

/** A list's search, page (0-based) and page size (undefined = the list's default). */
export type ListState = { q: string; page: number; size: number | undefined }
export type ListParams = ListState & { set: (patch: Partial<ListState>) => void }

/** The URL key of a list from its caption: "Software of this device" → "software-of-this-device", at most 24 characters. */
export function listKey(caption: string): string {
  return caption.toLowerCase().normalize('NFKD').replace(/[^a-z0-9]+/g, '-').replace(/^-+|-+$/g, '').slice(0, 24).replace(/-+$/, '') || 'list'
}

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
  const size = int(params.get(k('size')))
  const set = useCallback((patch: Partial<ListState>) => {
    setParams((prev) => {
      const p = new URLSearchParams(prev)
      const put = (n: string, v: string | undefined) => { if (v) p.set(k(n), v); else p.delete(k(n)) }
      if ('q' in patch) put('q', patch.q?.trim() || undefined)
      if ('page' in patch) put('page', patch.page ? String(patch.page + 1) : undefined)
      if ('size' in patch) put('size', patch.size ? String(patch.size) : undefined)
      return p
    }, { replace: true, preventScrollReset: true })
  }, [setParams, k])
  return useMemo(() => ({ q, page, size, set }), [q, page, size, set])
}

/** The same state kept in the component, for a list rendered outside a router (a test of the component alone). */
function useLocalList(): ListParams {
  const [s, setS] = useState<ListState>({ q: '', page: 0, size: undefined })
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
