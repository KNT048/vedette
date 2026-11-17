// #825: page load of Home on a real box, cold (empty browser cache) and warm, desktop. Signs in through the API (the
// browser context keeps the session cookie), then opens / and reports: the navigation timing, the time until the dashboard tiles are
// on screen ("Today at a glance"), the API calls Home made and the bytes the page transferred.
// Usage: ORIGIN=https://<box>:8443 EMAIL=<viewer> PASSWORD=<password> RUNS=5 node web/e2e/qa/home-load.mjs
// (through ~/vedette-wt/heavy on a shared box). API timing and core RSS: scripts/dev/home-summary-measure.sh.
import { chromium } from '@playwright/test'

const ORIGIN = process.env.ORIGIN ?? 'https://127.0.0.1:8443'
const RUNS = Number(process.env.RUNS ?? 5)
const { EMAIL, PASSWORD } = process.env
if (!EMAIL || !PASSWORD) {
  console.error('set EMAIL and PASSWORD (a viewer account is enough)')
  process.exit(2)
}

const browser = await chromium.launch()
const pct = (xs, p) => [...xs].sort((a, b) => a - b)[Math.min(xs.length - 1, Math.max(0, Math.ceil(xs.length * p) - 1))]
const rows = []
for (const mode of ['cold', 'warm']) {
  const ctx = await browser.newContext({ ignoreHTTPSErrors: true, viewport: { width: 1280, height: 900 } })
  const login = await ctx.request.post(`${ORIGIN}/api/v1/auth/login`, { data: { email: EMAIL, password: PASSWORD } })
  if (!login.ok()) {
    console.error(`sign-in failed: HTTP ${login.status()}`)
    process.exit(1)
  }
  const page = await ctx.newPage()
  if (mode === 'warm') { // fill the HTTP cache once
    await page.goto(`${ORIGIN}/`)
    await page.getByRole('list', { name: 'Today at a glance' }).waitFor({ timeout: 30_000 })
  }
  const tiles = [], dcl = [], load = [], kb = [], calls = []
  for (let i = 0; i < RUNS; i++) {
    const cdp = mode === 'cold' ? await ctx.newCDPSession(page) : null
    if (cdp) { await cdp.send('Network.enable'); await cdp.send('Network.clearBrowserCache') }
    const api = []
    const onReq = (r) => { if (r.url().includes('/api/v1/')) api.push(new URL(r.url()).pathname.replace('/api/v1', '')) }
    page.on('request', onReq)
    const t0 = Date.now()
    await page.goto(`${ORIGIN}/`)
    await page.getByRole('list', { name: 'Today at a glance' }).waitFor({ timeout: 30_000 })
    tiles.push(Date.now() - t0)
    await page.waitForLoadState('networkidle')
    page.off('request', onReq)
    const nav = await page.evaluate(() => {
      const n = performance.getEntriesByType('navigation')[0]
      const bytes = performance.getEntriesByType('resource').reduce((s, r) => s + (r.transferSize || 0), n.transferSize || 0)
      return { dcl: n.domContentLoadedEventEnd, load: n.loadEventEnd, bytes }
    })
    dcl.push(nav.dcl); load.push(nav.load); kb.push(nav.bytes / 1024); calls.push(api.length)
    if (i === 0) console.log(`${mode}: API calls of one Home view: ${[...new Set(api)].join(', ')}`)
    if (cdp) await cdp.detach()
  }
  rows.push({ mode, tiles, dcl, load, kb, calls })
  await ctx.close()
}
await browser.close()
console.log(`\n${ORIGIN}, ${RUNS} runs each, desktop 1280\n`)
console.log('| load | tiles visible p50 / max ms | DOMContentLoaded p50 ms | load p50 ms | transferred p50 KB | API calls |')
console.log('|------|----------------------------|-------------------------|-------------|--------------------|-----------|')
for (const r of rows) {
  console.log(`| ${r.mode} | ${pct(r.tiles, 0.5)} / ${Math.max(...r.tiles)} | ${pct(r.dcl, 0.5).toFixed(0)} | ${pct(r.load, 0.5).toFixed(0)} | ${pct(r.kb, 0.5).toFixed(1)} | ${pct(r.calls, 0.5)} |`)
}
