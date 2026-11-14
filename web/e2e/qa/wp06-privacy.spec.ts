import { expect, test } from '@playwright/test'
import { collectErrors, expectAccessible } from '../helpers'
import { begin, noHScroll, stepper, THEMES } from './wp06-shared'

// WP-06 independent check, area 5: "As the owner of a company I want to see exactly what leaves the box, the anonymous signal included."
// Settings -> Privacy must match PRIVACY.md: 16 flows, payload verbatim, the word IDS nowhere, single sign-on (OIDC) listed.
const FLOWS = [
  /feeds/i, /anonymous signal/i, /AI/, /lookups?|need a key/i, /notifications?/i, /update/i, /SIEM/, /CVE/, /external (exposure|surface)/i, /time sync|NTP/i, /single sign-on|OIDC/i, /connections you add/i, /MCP server/, /Wazuh pull/, /Outside view/, /Greenbone feed/,
]

for (const theme of THEMES) {
  test(`privacy [${theme}]: fifteen flows as in PRIVACY.md, payload verbatim, no "IDS", SSO flow listed`, async ({ page }, info) => {
    const errors = collectErrors(page)
    const shot = stepper(page, info, 'privacy', theme)
    await begin(page, theme)
    await page.goto('/settings/privacy')
    await expect(page.getByRole('heading', { name: 'Data flows that leave the box' })).toBeVisible()
    await shot('flows')
    // Wide screens: a table. Phones (< 768 px): one card per flow, so nothing is cut off (like the other tables of the app).
    const flows = page.getByRole('table', { name: 'Data flows that leave the box' }).or(page.getByRole('list', { name: 'Data flows that leave the box' }))
    const phone = (page.viewportSize()?.width ?? 1366) < 768
    const rows = phone ? flows.locator('> li') : flows.locator('tbody tr')
    const n = await rows.count()
    const names = phone ? await rows.locator('> div > div:first-child > span:first-child').allTextContents() : await rows.locator('td:first-child').allTextContents()
    console.log('FLOWS', JSON.stringify(names))
    expect(n, 'every flow of PRIVACY.md is on one page (no hidden second page)').toBe(16)
    FLOWS.forEach((re, i) => expect(names[i], `flow ${i + 1}`).toMatch(re))
    // flow texts
    const all = await flows.innerText()
    console.log('TABLE', all)
    expect.soft(all, 'PRIVACY.md flow 6 names the privileged helper vedette-host; the screen does not').toMatch(/vedette-host/)
    expect(all).not.toMatch(/vedette-updater/)
    expect.soft(all, 'PRIVACY.md flow 9 names the destination (the Vedette project endpoint on Cloudflare); the screen only says "a public-IP lookup service"').toMatch(/Cloudflare/)
    expect(all).toMatch(/PKCE|authorization code|issuer/i) // flow 11
    expect(all).toMatch(/Only the address you typed/) // flow 12
    // the word IDS, anywhere on the page, whole word
    const body = await page.locator('body').innerText()
    expect(body, 'the word "IDS"').not.toMatch(/\bIDS\b/)
    // anonymous signal: switch, payload verbatim
    await page.locator('#telemetry').scrollIntoViewIfNeeded()
    await shot('signal')
    // D-153: the anonymous signal is not sent; the screen says so, with no switch and no payload
    await expect(page.locator('#telemetry')).toContainText('Anonymous signal: not sent.')
    await expect(page.getByRole('switch', { name: /anonymous signal/i })).toHaveCount(0)
    await expect(page.locator('#telemetry pre, #telemetry code')).toHaveCount(0)
    // D-154: nothing sends the signal, so the API refuses to turn it on (the backend answers the same) and reports it off
    const patched = await page.evaluate(async () => {
      const r = await fetch('/api/v1/core/privacy', { method: 'PATCH', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ telemetry: true }) })
      return { status: r.status, code: ((await r.json()) as { error?: { code?: string } }).error?.code }
    })
    expect(patched).toEqual({ status: 400, code: 'telemetry_unavailable' })
    await noHScroll(page, 'privacy')
    await expectAccessible(page, 'privacy')
    expect(errors.filter((e) => !/status of (4|5)\d\d/.test(e))).toEqual([])
  })
}

test('the word "IDS" appears nowhere else in the settings pages either', async ({ page }) => {
  await begin(page, 'light')
  for (const s of ['general', 'modules', 'network', 'updates', 'privacy', 'data']) {
    await page.goto(`/settings/${s}`)
    await expect(page.getByRole('heading', { level: 1 }).first()).toBeVisible()
    expect(await page.locator('body').innerText(), `IDS on /settings/${s}`).not.toMatch(/\bIDS\b/)
  }
  for (const p of ['/', '/devices', '/findings', '/logs', '/honeypot']) {
    await page.goto(p)
    await page.waitForTimeout(400)
    expect(await page.locator('body').innerText(), `IDS on ${p}`).not.toMatch(/\bIDS\b/)
  }
})
