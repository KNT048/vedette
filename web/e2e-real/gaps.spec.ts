// The gap map (D-171): every route of Kiên's modules, opened as the administrator on the real box. Each must render with no JavaScript
// error and no 5xx from the API, except the exact 501 answers of backend that is not built yet. KNOWN_501 only shrinks: an entry that is
// no longer answered 501 on its route fails that route's test, and a new 5xx fails its route. Each entry names its owner and the
// deferred line that tracks it. KNOWN_404 is the same for a 404 on an API path the GUI calls (a module that is not wired yet): any other
// API 404 fails its route, and an entry that is no longer answered 404 fails too.
import { expect, test } from '@playwright/test'
import { api, authFile } from './box'
import { h1 } from './ui'
import { collectErrors } from '../e2e/helpers'

test.use({ storageState: authFile('admin'), actionTimeout: 10_000 })

/** route -> "METHOD /api/v1/path" -> owner and the deferred line. */
const KNOWN_404: Record<string, Record<string, string>> = {
  '/devices/setup': { 'GET /api/v1/inventory/agents': 'Kiên (inventory) · .ai/deferred/feat-e2e-real-harness.md:22 (agent-intake is not wired, cmd/vedette/modules.go)' },
}
const KNOWN_501: Record<string, Record<string, string>> = {
  '/settings/updates': { 'GET /api/v1/core/updates': 'Kiên (core) · .ai/deferred/feat-core-os-updates.md:3 (software updates /core/updates*)' },
  '/assistant': { 'GET /api/v1/ai/asks': 'Mlee (ai) · .ai/deferred/feat-e2e-real-specs-sal.md (the "Ask your data" history and POST /ai/ask)' },
  '/settings/siem': { 'GET /api/v1/logs/siem': 'Mlee (logs) · .ai/deferred/feat-e2e-real-specs-sal.md (SIEM forwarding, L5)' },
}

/** A 501 the page may or may not trigger (it depends on which module switches the other specs left): allowed, never required. */
const MAYBE_501: Record<string, Record<string, string>> = {
  '/logs': { 'GET /api/v1/ai/logs/digest': 'Mlee (ai) · .ai/deferred/feat-ai-activity.md:18 (the log digest, not built)' },
}

const SECTIONS = ['general', 'modules', 'users', 'connections', 'audit', 'updates', 'network', 'privacy', 'mcp', 'data', 'feeds', 'response', 'ai', 'siem']
const ROUTES = ['/', '/lookup', '/devices', '/devices/setup', '/findings', '/honeypot', '/response', '/account', '/logs', '/scans', '/assistant', ...SECTIONS.map((s) => `/settings/${s}`)]

async function check(page: import('@playwright/test').Page, route: string, info: import('@playwright/test').TestInfo) {
  const errors = collectErrors(page)
  const server: string[] = []
  const seen = new Set<string>()
  const seen404 = new Set<string>()
  const notFound: string[] = []
  const where: string[] = [] // the console errors with the file they came from, for the failure message
  page.on('console', (m) => { if (m.type() === 'error') where.push(`${m.text()} @ ${m.location().url}`) })
  page.on('response', (r) => {
    const url = new URL(r.url())
    if (!url.pathname.startsWith('/api/')) return
    const key = `${r.request().method()} ${url.pathname}`
    if (r.status() === 404) {
      if (key in (KNOWN_404[route] ?? {})) { seen404.add(key); info.annotations.push({ type: 'known-404', description: `${route}: ${key}` }) }
      else notFound.push(key)
    }
    if (r.status() < 500) return
    if (r.status() === 501 && key in (KNOWN_501[route] ?? {})) seen.add(key)
    else if (r.status() === 501 && key in (MAYBE_501[route] ?? {})) return
    else server.push(`${key} -> ${r.status()}`)
  })
  await page.goto(route)
  await expect(h1(page), `${route} has a heading`).toBeVisible()
  await page.waitForLoadState('networkidle')
  expect(server, `${route}: the API answered 5xx`).toEqual([])
  expect(notFound, `${route}: the API answered 404 (a module that is not wired, or a path that drifted)`).toEqual([])
  const gone404 = Object.keys(KNOWN_404[route] ?? {}).filter((k) => !seen404.has(k))
  expect(gone404, `${route}: no longer 404, remove from KNOWN_404\n${gone404.join('\n')}`).toEqual([])
  const gone = Object.keys(KNOWN_501[route] ?? {}).filter((k) => !seen.has(k))
  expect(gone, `${route}: no longer 501, remove from KNOWN_501\n${gone.join('\n')}`).toEqual([])
  // a 5xx shows in the console as a failed resource without its URL: the response check above is the one that names it
  expect(errors.filter((e) => !/status of 5\d\d/.test(e)), `${route}: script errors\n${where.join('\n')}`).toEqual([])
}

for (const route of ROUTES) {
  test(`${route} renders with no script error and no 5xx outside KNOWN_501`, async ({ page }, info) => {
    await check(page, route, info)
  })
}

test('/devices/<the box> renders with no script error and no 5xx', async ({ page }, info) => {
  const list = await api<{ items: { id: string; is_box: boolean }[] }>(page.request, 'GET', '/inventory/devices')
  const boxId = list.body.items.find((d) => d.is_box)?.id
  expect(boxId, 'the box device exists').toBeTruthy()
  await check(page, `/devices/${boxId}`, info)
})
