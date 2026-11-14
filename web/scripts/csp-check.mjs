// Real-browser CSP check of the interface served by the core binary (D-149).
// Usage: VEDETTE_SETUP_CODE=<code> node scripts/csp-check.mjs <base-url> (the code is optional; it is read from the
// environment, not argv, so it does not show in ps)
// Records console messages and securitypolicyviolation events in headless Chromium and fails on any violation, any CSP console error, a failed
// request, or a first screen that does not render. Pre-login: "/", a client route and an approval link in the real token format.
// With a setup code (the one the box prints in its log), it also does first-run setup through the real API (sample data), reloads (signed in),
// opens the account menu and a dialog from it, and visits a second page.
import { chromium } from '@playwright/test'

const base = process.argv[2]
const setupCode = process.env.VEDETTE_SETUP_CODE
if (!base) throw new Error('usage: VEDETTE_SETUP_CODE=<code> csp-check.mjs <base-url>')

// v1.<22 base64url>.<22 base64url>: the format of the real approval links (web TOKEN_RE).
const token = 'v1.AbCdEfGhIjKlMnOpQrStUv.0123456789_-abcdefghij'

let failed = false
const fail = (msg) => {
  failed = true
  console.log(`  FAIL: ${msg}`)
}

const browser = await chromium.launch()

async function track(page) {
  const log = { console: [], requests: [] }
  page.on('console', (m) => log.console.push(`${m.type()}: ${m.text()}`))
  page.on('pageerror', (e) => log.console.push(`pageerror: ${e.message}`))
  page.on('requestfailed', (r) => log.requests.push(`${r.url()} ${r.failure()?.errorText}`))
  await page.addInitScript(() => {
    window.__csp = []
    document.addEventListener('securitypolicyviolation', (e) => window.__csp.push(`${e.violatedDirective} blocked ${e.blockedURI}`))
  })
  return log
}

const rootText = async (page) => {
  await page.waitForFunction(() => (document.getElementById('root')?.innerText ?? '').trim().length > 0, null, { timeout: 15000 }).catch(() => {})
  return ((await page.locator('#root').innerText().catch(() => '')) || '').replace(/\s+/g, ' ').trim()
}

// report prints and judges what the page has collected so far (the violation list is read from the page, the rest from the tracker).
async function report(page, log, label) {
  const csp = await page.evaluate(() => window.__csp)
  const cspConsole = log.console.filter((m) => /content security policy|refused to/i.test(m))
  console.log(`  [${label}] securitypolicyviolation events: ${csp.length}${csp.length ? ' ' + JSON.stringify(csp) : ''}`)
  console.log(`  [${label}] console messages: ${log.console.length}${log.console.length ? '\n    ' + log.console.join('\n    ') : ''}`)
  console.log(`  [${label}] failed requests: ${log.requests.length}${log.requests.length ? ' ' + log.requests.join('; ') : ''}`)
  if (csp.length || cspConsole.length || log.requests.length) fail(`${label}: CSP violation or failed request`)
}

try {
  for (const [route, want] of [['/', null], ['/findings/123', null], [`/approve/${token}`, /invalid|expired|no longer|not valid|not found/i]]) {
    const page = await browser.newPage()
    const log = await track(page)
    const resp = await page.goto(base + route, { waitUntil: 'networkidle' })
    const text = await rootText(page)
    console.log(`${route}: HTTP ${resp?.status()}, CSP header: ${resp?.headers()['content-security-policy']}`)
    console.log(`  first screen: ${JSON.stringify(text.slice(0, 140))}`)
    if (resp?.status() !== 200 || !text) fail(`${route}: status ${resp?.status()} or nothing rendered`)
    if (want && !want.test(text)) fail(`${route}: expected the invalid or expired link state`)
    await report(page, log, route)
    await page.close()
  }

  if (setupCode) {
    const ctx = await browser.newContext()
    const page = await ctx.newPage()
    const log = await track(page)
    await page.goto(base + '/', { waitUntil: 'networkidle' })
    console.log('first-run setup through the real API, then signed in:')
    const res = await page.evaluate(async (code) => {
      const post = async (path, body) => {
        const r = await fetch('/api/v1' + path, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) })
        return { status: r.status, body: (await r.text()).slice(0, 300) }
      }
      const admin = { name: 'CSP Check', email: 'csp@example.com', password: 'correct-horse-battery-staple-91' }
      const s = await post('/core/setup', { org: 'CSP Check', admin, lan: ['192.168.77.0/24'], commitment: true, bundle: 'smb', setup_code: code, accept_terms: true })
      if (s.status !== 200 && s.status !== 201) return s
      const l = await post('/auth/login', { email: admin.email, password: admin.password })
      return l.status === 200 || l.status === 204 ? s : l
    }, setupCode)
    console.log(`  setup and sign-in -> ${res.status} ${res.body}`)
    if (res.status !== 200 && res.status !== 201) fail('first-run setup or sign-in was refused')
    await page.goto(base + '/', { waitUntil: 'networkidle' })
    console.log(`  signed-in first screen: ${JSON.stringify((await rootText(page)).slice(0, 140))}`)

    // A menu (Radix DropdownMenu), then a dialog (Radix Dialog) from its "Report a problem" item.
    await page.getByRole('button', { name: /Account:/ }).click()
    await page.getByRole('menu').waitFor({ timeout: 8000 })
    console.log('  account menu opened')
    await page.getByRole('menuitem').nth(1).click() // 0 = My account, 1 = Report a problem
    await page.getByRole('dialog').waitFor({ timeout: 8000 })
    console.log(`  dialog opened: ${JSON.stringify(((await page.getByRole('dialog').innerText()) || '').replace(/\s+/g, ' ').slice(0, 80))}`)
    await page.keyboard.press('Escape')
    // /settings, and the four routes where zod's eval probe used to be reported (issue #201).
    for (const route of ['/settings', '/devices/setup', '/response', '/settings/connections', '/settings/response']) {
      await page.goto(base + route, { waitUntil: 'networkidle' })
      console.log(`  ${route}: ${JSON.stringify((await rootText(page)).slice(0, 100))}`)
    }
    await report(page, log, 'signed in')
    await ctx.close()
  } else {
    console.log('(no setup code given: the signed-in part is not covered)')
  }
} catch (e) {
  fail(String(e?.message ?? e))
} finally {
  await browser.close()
}
if (failed) {
  console.error('csp-check: FAIL')
  process.exit(1)
}
console.log('csp-check: ok')
