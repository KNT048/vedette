// Real-browser CSP check of the interface served by the core binary (D-149). Usage: node scripts/csp-check.mjs <base-url>
// Opens "/" and a client route in headless Chromium, records console messages and securitypolicyviolation events, and fails on any
// violation, any CSP console error, a failed request, or when the first screen (setup or sign-in) does not render.
import { chromium } from '@playwright/test'

const base = process.argv[2]
if (!base) throw new Error('usage: csp-check.mjs <base-url>')

const browser = await chromium.launch()
let failed = false
try {
  for (const route of ['/', '/findings/123']) {
    const page = await browser.newPage()
    const console_ = []
    const failedReq = []
    page.on('console', (m) => console_.push(`${m.type()}: ${m.text()}`))
    page.on('pageerror', (e) => console_.push(`pageerror: ${e.message}`))
    page.on('requestfailed', (r) => failedReq.push(`${r.url()} ${r.failure()?.errorText}`))
    await page.addInitScript(() => {
      window.__csp = []
      document.addEventListener('securitypolicyviolation', (e) => window.__csp.push(`${e.violatedDirective} blocked ${e.blockedURI}`))
    })
    const resp = await page.goto(base + route, { waitUntil: 'networkidle' })
    // First screen: the app mounts something into #root (setup, or sign-in), whatever the box's state.
    await page.waitForFunction(() => (document.getElementById('root')?.innerText ?? '').trim().length > 0, null, { timeout: 15000 }).catch(() => {})
    const text = ((await page.locator('#root').innerText().catch(() => '')) || '').replace(/\s+/g, ' ').trim()
    const csp = await page.evaluate(() => window.__csp)
    const cspConsole = console_.filter((m) => /content security policy|refused to/i.test(m))
    console.log(`${route}: HTTP ${resp?.status()}, CSP header: ${resp?.headers()['content-security-policy']}`)
    console.log(`  first screen: ${JSON.stringify(text.slice(0, 120))}`)
    console.log(`  securitypolicyviolation events: ${csp.length}${csp.length ? ' ' + JSON.stringify(csp) : ''}`)
    console.log(`  console messages: ${console_.length}${console_.length ? '\n    ' + console_.join('\n    ') : ''}`)
    console.log(`  failed requests: ${failedReq.length}${failedReq.length ? ' ' + failedReq.join('; ') : ''}`)
    if (csp.length || cspConsole.length || failedReq.length || !text || resp?.status() !== 200) failed = true
    await page.close()
  }
} finally {
  await browser.close()
}
if (failed) {
  console.error('csp-check: FAIL')
  process.exit(1)
}
console.log('csp-check: ok')
