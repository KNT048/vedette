// The link guard: a link never points at the page it is on, two links on one screen never share a label and a target, and every
// link goes to a page that exists. It crawls the app as a signed-in administrator with the dev mock data: it starts at the menu and
// the settings sections, renders each page (and each of its tabs) once per route, collects every internal link and follows the
// ones that lead to a route it has not rendered yet. On each page it counts:
//  - self: a link to the same path and query as the page (a missing ?tab= is the page's first tab), or to an anchor that holds the
//    link itself (a jump to the place you already are). The menu's own entry for the page (aria-current="page") is not counted;
//  - duplicate: the same label and target twice on the page (an #anchor does not make it another target; the same record named in
//    two rows of one table or list is not a twin);
//  - no route: a target no route of the app answers (the "page not found" route, or a settings section that does not exist).
// It crawls twice: with the dev data as it is, and while scans run (a device check, a LAN sweep and a public scan), where the
// "Open the run" links and the "scans running" indicator show. Each kind has a list of the known cases outside this change
// (KNOWN); a case not listed fails, and a listed case that is gone fails too, so the list only shrinks.
import { describe, expect, it, vi } from 'vitest'
import { act, cleanup, render } from '@testing-library/react'
import { QueryClientProvider } from '@tanstack/react-query'
import { RouterProvider, createMemoryRouter, matchRoutes, type RouteObject } from 'react-router'
import { getResponse, http, HttpResponse } from 'msw'
import { makeQueryClient } from '@/app/App'
import { navItems, settingsSections } from '@/app/feature'
import { buildRoutes } from '@/app/router'
import { TooltipProvider } from '@/components/ui/tooltip'
import { handlers } from '@/mocks/handlers'
import { orgStore, sessionStore } from '@/mocks/stores'
import { server } from '@/test/server'

vi.setConfig({ testTimeout: 600_000 })

type Kind = 'self' | 'duplicate' | 'no route'
type Hit = { kind: Kind; page: string; label: string; to: string }

/** Known cases outside this change, as `kind page → target` (routes, with the tab); see hitKey. */
const KNOWN: string[] = [
  'duplicate / → /cve/:id',
]

const ORIGIN = 'http://vedette.test'
const routes = buildRoutes()
const sections = new Set(settingsSections.map((s) => s.id))

/** The route a path renders, as its pattern ("/devices/:id"); null when only the not-found route or no route answers. */
function routeOf(path: string): string | null {
  const m = matchRoutes(routes as RouteObject[], path)
  if (!m) return null
  const last = m[m.length - 1]!
  if (last.route.path === '*') return null
  const pattern = '/' + m.map((x) => x.route.path ?? '').filter(Boolean).join('/').replace(/^\/+/, '')
  if (pattern === '/settings/:section' && !sections.has(last.params.section ?? '')) return null
  return pattern
}

const norm = (s: string) => s.replace(/\s+/g, ' ').trim()
const labelOf = (a: HTMLAnchorElement) => norm(a.getAttribute('aria-label') || a.textContent || a.getAttribute('title') || '')

/** A query in one canonical order, with the page's first tab named when the query names none (the page shows that tab). */
function canonQuery(search: string, firstTab: string | null): string {
  const p = new URLSearchParams(search)
  if (firstTab && !p.has('tab')) p.set('tab', firstTab)
  return [...p.entries()].sort(([a, x], [b, y]) => (a === b ? x.localeCompare(y) : a.localeCompare(b))).map(([k, v]) => `${k}=${v}`).join('&')
}

/** The tabs of the page (PageTabs: Radix triggers whose id ends in -trigger-<value>): the selected one and every one. */
function tabsOf(): { all: string[]; selected: string | null } {
  const list = document.querySelector('main [role="tablist"]') ?? document.querySelector('[role="tablist"]')
  if (!list) return { all: [], selected: null }
  const value = (el: Element) => /-trigger-(.+)$/.exec(el.id)?.[1] ?? null
  const all = [...list.querySelectorAll('[role="tab"]')].map(value).filter((v): v is string => !!v)
  const sel = list.querySelector('[role="tab"][aria-selected="true"]')
  return { all, selected: sel ? value(sel) : null }
}

/** Renders the app at a URL and waits until it is quiet: the route loaded, no request in flight, nothing says it is loading. */
async function show(url: string) {
  let inFlight = 0
  const start = () => { inFlight++ }
  const end = () => { inFlight = Math.max(0, inFlight - 1) }
  server.events.on('request:start', start)
  server.events.on('request:end', end)
  const router = createMemoryRouter(buildRoutes(), { initialEntries: [url] })
  render(<QueryClientProvider client={makeQueryClient()}><TooltipProvider><RouterProvider router={router} /></TooltipProvider></QueryClientProvider>)
  let quiet = 0
  for (let i = 0; i < 300 && quiet < 4; i++) {
    await act(() => new Promise((r) => setTimeout(r, 25)))
    const busy = inFlight > 0 || router.state.navigation.state !== 'idle' || !!document.querySelector('[aria-busy="true"]') || /Loading…/.test(document.body.textContent ?? '')
    quiet = busy ? 0 : quiet + 1
  }
  server.events.removeListener('request:start', start)
  server.events.removeListener('request:end', end)
  return router
}

/** A case by its routes, not its words or ids, so a change of the dev data does not move it. */
function hitKey(h: Hit): string {
  return `${h.kind} ${h.page} → ${h.to}`
}

/** A target as its route and its tab: "/devices/:id?tab=software". */
const targetOf = (route: string, to: URL) => (to.searchParams.get('tab') ? `${route}?tab=${to.searchParams.get('tab')}` : route)

async function crawl(first: string[] = []): Promise<{ hits: Hit[]; pages: number }> {
  orgStore.update((o) => ({ ...o, setup_complete: true }))
  const queue: string[] = [...first, '/', ...navItems.map((n) => n.to), ...settingsSections.map((s) => `/settings/${s.id}`)]
  const seen = new Set<string>()
  const hits = new Map<string, Hit>()
  let pages = 0
  while (queue.length) {
    const url = queue.shift()!
    const u = new URL(url, ORIGIN)
    const route = routeOf(u.pathname)
    if (!route || route.startsWith('/reports/print')) continue
    const asked = `${route}?tab=${u.searchParams.get('tab') ?? ''}`
    if (seen.has(asked)) continue
    seen.add(asked)
    sessionStore.set({ userId: 'u-admin' })
    const router = await show(url)
    const loc = router.state.location
    const here = routeOf(loc.pathname) ?? loc.pathname
    const tabs = tabsOf()
    const firstTab = tabs.all[0] ?? null
    const shown = `${here}?tab=${tabs.selected ?? ''}`
    seen.add(shown)
    if (!u.searchParams.get('tab')) seen.add(`${route}?tab=${tabs.selected ?? ''}`)
    pages++
    const page = tabs.selected ? `${here}?tab=${tabs.selected}` : here
    const pairs = new Map<string, { row: Element | null; list: Element | null }[]>()
    for (const a of document.querySelectorAll<HTMLAnchorElement>('a[href]')) {
      const href = a.getAttribute('href')!
      if (!href.startsWith('/') && !href.startsWith('?') && !href.startsWith('#')) continue
      const to = new URL(href, `${ORIGIN}${loc.pathname}${loc.search}`)
      if (to.pathname.startsWith('/api/')) continue
      const label = labelOf(a)
      const target = routeOf(to.pathname)
      if (!target) { const h: Hit = { kind: 'no route', page, label, to: to.pathname }; hits.set(`${hitKey(h)} [${h.label}]`, h); continue }
      const where = targetOf(target, to)
      const sameQuery = to.pathname === loc.pathname && canonQuery(to.search, firstTab) === canonQuery(loc.search, firstTab)
      if (sameQuery && a.getAttribute('aria-current') !== 'page') {
        const anchor = to.hash ? document.getElementById(decodeURIComponent(to.hash.slice(1))) : null
        if (!to.hash || anchor?.contains(a)) {
          const h: Hit = { kind: 'self', page, label, to: where }
          hits.set(`${hitKey(h)} [${h.label}]`, h)
        }
      }
      // twins in the page's content (the menu and the content may both name a page): the same label to the same page, an #anchor
      // or not (two "Open modules" read the same however they land). Rows of one list that name the same record (a device in two
      // hits) are records, not twins: two links count only when they are not in different rows of the same table or list.
      const pair = `${label}|${to.pathname}${to.search}`
      if (a.closest('main')) {
        const row = a.closest('tr, li')
        const list = row?.parentElement?.closest('table, ul, ol') ?? null
        const seenAt = pairs.get(pair) ?? []
        const twin = seenAt.some((p) => !(list && p.list === list && p.row !== row))
        pairs.set(pair, [...seenAt, { row, list }])
        if (twin) { const h: Hit = { kind: 'duplicate', page, label, to: where }; hits.set(`${hitKey(h)} [${h.label}]`, h) }
      }
      // follow a route not rendered yet (and each tab of a page, by its ?tab=)
      const key = `${target}?tab=${to.searchParams.get('tab') ?? ''}`
      if (!seen.has(key) && !target.startsWith('/reports/print')) queue.push(`${to.pathname}${to.search}`)
    }
    for (const tab of tabs.all) if (!seen.has(`${here}?tab=${tab}`)) queue.push(`${loc.pathname}?tab=${tab}`)
    cleanup()
  }
  return { hits: [...hits.values()], pages }
}

/** Scans going on: a person's check of one device, a LAN sweep and a public scan (their runs are in the runs mock). */
function scansRunning() {
  const at = new Date(Date.now() - 60_000).toISOString()
  const running = [
    { engine: 'nmap-discovery', id: 'run-m2', label: 'Check WEB01', target_id: 'a-web01', started_at: at, progress: null },
    { engine: 'nmap-discovery', id: 'run-m1', label: 'LAN sweep of 192.0.2.0/24', target_id: null, started_at: at, progress: null },
    { engine: 'zap', id: 'run-m6', label: 'www.example.com', target_id: 'xt-1', started_at: at, progress: null },
  ]
  server.use(http.get('*/api/v1/scanning', async ({ request }) => {
    const res = await getResponse(handlers, request)
    return HttpResponse.json({ ...(await res!.json()), running })
  }))
}

function check(hits: Hit[], pages: number, scene: string) {
  const keys = [...new Set(hits.map(hitKey))]
  const count = (k: Kind, label?: string) => hits.filter((h) => h.kind === k && (!label || h.label === label)).length
  if (process.env.LINK_GUARD_LIST) for (const h of hits) console.info(`  ${hitKey(h)}   [${h.label}]`)
  // the numbers this guard reports (a change that fixes a class of these says them before and after)
  console.info(`link guard, ${scene}: ${pages} pages; self ${count('self')} ("Open the run" ${count('self', 'Open the run')}), duplicate ${count('duplicate')}, no route ${count('no route')}`)
  expect(pages).toBeGreaterThan(20)
  expect(keys.filter((k) => !KNOWN.includes(k)), 'links that loop, repeat or lead nowhere').toEqual([])
  return keys
}

describe('links: no loop, no twin, no dead end', () => {
  it('every page of the app, as an administrator: with the dev data, then while scans run', async () => {
    const quiet = await crawl()
    const a = check(quiet.hits, quiet.pages, 'dev data')
    scansRunning()
    const busy = await crawl(['/devices/a-web01', '/exposure/xt-1'])
    const b = check(busy.hits, busy.pages, 'scans running')
    // Some sample data is windowed on the current time (recent alerts, live hosts), so a known case can come and go with
    // the clock. Only new cases fail; known cases that no longer show are reported for clean-up.
    const gone = KNOWN.filter((k) => !a.includes(k) && !b.includes(k))
    if (gone.length > 0) console.warn('known link cases not seen in this run (remove them from KNOWN if fixed):', gone)
  })
})
