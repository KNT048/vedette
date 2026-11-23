import { useCallback, useSyncExternalStore } from 'react'
import { useLocation } from 'react-router'

// "A link never points at the page it is on": a link to the shown page and its shown tab (with the same filters) is a link that does
// nothing, so a tile or a link that would point here is drawn as plain text. The page tabs (PageTabs) say which tab is shown, since
// a page without ?tab= shows its first tab; a stat strip above the tabs reads it from here.

type Tabs = { shown: string; first: string }
const tabsByPath = new Map<string, Tabs>()
const listeners = new Set<() => void>()
const emit = () => { for (const l of listeners) l() }

/** PageTabs: the tab shown on this path, and the first one (the tab a link without ?tab= opens). null when the tabs go away. */
export function setShownTabs(path: string, tabs: Tabs | null) {
  const was = tabsByPath.get(path)
  if (tabs === null) { if (was) { tabsByPath.delete(path); emit() } return }
  if (was?.shown === tabs.shown && was.first === tabs.first) return
  tabsByPath.set(path, tabs)
  emit()
}

/** The keys a list keeps in the URL (its page, search, size and sort): they do not make a link point somewhere else. */
const LIST_KEY = /^[a-z0-9-]+\.(?:q|page|size|sort)$/

/** The query of a URL without the list keys, in one order, with the tab the page shows when the query names none. */
function canon(search: string, tab: string | undefined): string {
  const p = new URLSearchParams(search)
  const out: [string, string][] = []
  for (const [k, v] of p) if (!LIST_KEY.test(k) && k !== 'tab') out.push([k, v])
  const t = p.get('tab') ?? tab
  if (t) out.push(['tab', t])
  return out.sort(([a, x], [b, y]) => (a === b ? x.localeCompare(y) : a.localeCompare(b))).map(([k, v]) => `${k}=${v}`).join('&')
}

/** True when `to` names the page being shown, its shown tab and the same filters (a link with a #anchor is a jump, never "here"). */
export function pointsHere(to: string, here: { pathname: string; search: string }, tabs: Tabs | undefined): boolean {
  const u = new URL(to, `http://x${here.pathname}${here.search}`)
  if (u.hash || u.pathname !== here.pathname) return false
  return canon(u.search, tabs?.first) === canon(here.search, tabs?.shown)
}

/** `const isHere = useIsHere()` then `isHere('?tab=hits')`: whether the link would lead to the page as it is shown. */
export function useIsHere(): (to: string) => boolean {
  const loc = useLocation()
  const tabs = useSyncExternalStore(
    (l) => { listeners.add(l); return () => { listeners.delete(l) } },
    () => tabsByPath.get(loc.pathname),
    () => undefined,
  )
  return useCallback((to: string) => pointsHere(to, loc, tabs), [loc, tabs])
}
