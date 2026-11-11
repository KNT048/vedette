// The gap map (D-171): every route of Kiên's modules, opened as the administrator on the real box. Each must render with no JavaScript
// error and no 5xx from the API, except the exact 501 answers of backend that is not built yet. KNOWN_501 only shrinks: an entry that is
// no longer answered 501 on its route fails that route's test, and a new 5xx fails its route. Each entry names its owner and the
// deferred line that tracks it. A 404 on an API path the GUI calls is recorded as an annotation of the test (not a failure): it means a
// module that is not wired yet.
import { expect, test } from '@playwright/test'
import { api, authFile } from './box'
import { h1 } from './ui'
import { collectErrors } from '../e2e/helpers'

test.use({ storageState: authFile('admin'), actionTimeout: 10_000 })

/** route -> "METHOD /api/v1/path" -> owner and the deferred line. */
const KNOWN_501: Record<string, Record<string, string>> = {
  '/settings/updates': { 'GET /api/v1/core/updates': 'Kiên (core) · .ai/deferred/feat-core-os-updates.md:3 (software updates /core/updates*)' },
}

const SECTIONS = ['general', 'modules', 'users', 'connections', 'audit', 'updates', 'network', 'privacy', 'mcp', 'data', 'feeds', 'response']
const ROUTES = ['/', '/lookup', '/devices', '/devices/setup', '/findings', '/honeypot', '/response', '/account', ...SECTIONS.map((s) => `/settings/${s}`)]

async function check(page: import('@playwright/test').Page, route: string, info: import('@playwright/test').TestInfo) {
  const errors = collectErrors(page)
  const server: string[] = []
  const seen = new Set<string>()
  const where: string[] = [] // the console errors with the file they came from, for the failure message
  page.on('console', (m) => { if (m.type() === 'error') where.push(`${m.text()} @ ${m.location().url}`) })
  page.on('response', (r) => {
    const url = new URL(r.url())
    if (!url.pathname.startsWith('/api/')) return
    const key = `${r.request().method()} ${url.pathname}`
    if (r.status() === 404) info.annotations.push({ type: 'api-404', description: `${route}: ${key}` })
    if (r.status() < 500) return
    if (r.status() === 501 && key in (KNOWN_501[route] ?? {})) seen.add(key)
    else server.push(`${key} -> ${r.status()}`)
  })
  await page.goto(route)
  await expect(h1(page), `${route} has a heading`).toBeVisible()
  await page.waitForLoadState('networkidle')
  expect(server, `${route}: the API answered 5xx`).toEqual([])
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
