import { expect, test } from '@playwright/test'
import { collectErrors, expectAccessible } from '../helpers'
import { begin, noHScroll, stepper, THEMES } from './wp06-shared'

// WP-06 independent check, area 5: "As the owner of a company I want to see exactly what leaves the box, the anonymous signal included."
// Settings -> Privacy must match PRIVACY.md: 11 flows, payload verbatim, the word IDS nowhere, single sign-on (OIDC) listed.
const FLOWS = [
  /feeds/i, /anonymous signal/i, /AI/, /lookups?|need a key/i, /notifications?/i, /update/i, /SIEM/, /CVE/, /external (exposure|surface)/i, /time sync|NTP/i, /single sign-on|OIDC/i,
]

for (const theme of THEMES) {
  test(`privacy [${theme}]: eleven flows as in PRIVACY.md, payload verbatim, no "IDS", SSO flow listed`, async ({ page }, info) => {
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
    expect(n, 'every flow of PRIVACY.md is on one page (no hidden second page)').toBe(11)
    FLOWS.forEach((re, i) => expect(names[i], `flow ${i + 1}`).toMatch(re))
    // flow texts
    const all = await flows.innerText()
    console.log('TABLE', all)
    expect.soft(all, 'PRIVACY.md flow 6 names the privileged helper vedette-host; the screen does not').toMatch(/vedette-host/)
    expect(all).not.toMatch(/vedette-updater/)
    expect.soft(all, 'PRIVACY.md flow 9 names the destination (the Vedette project endpoint on Cloudflare); the screen only says "a public-IP lookup service"').toMatch(/Cloudflare/)
    expect(all).toMatch(/PKCE|authorization code|issuer/i) // flow 11
    // the word IDS, anywhere on the page, whole word
    const body = await page.locator('body').innerText()
    expect(body, 'the word "IDS"').not.toMatch(/\bIDS\b/)
    // anonymous signal: switch, payload verbatim
    await page.locator('#telemetry').scrollIntoViewIfNeeded()
    await shot('signal')
    const code = await page.locator('#telemetry pre, #telemetry code').first().innerText()
    console.log('PAYLOAD', code)
    const payload = JSON.parse(code)
    const keys = Object.keys(payload)
    console.log('PAYLOAD KEYS', JSON.stringify(keys))
    for (const k of ['install_id', 'country', 'version', 'cve_matches']) expect(keys, `payload key ${k} (PRIVACY.md flow 2)`).toContain(k)
    // no internal/public IPs, no names in the payload
    expect(code, 'IP address in the payload').not.toMatch(/\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b/)
    expect(code, 'company/device name in the payload').not.toMatch(/acme|fw-hq|nas-photos|synology-box/i)
    // PRIVACY.md lists exactly: counts of trap touches, bad connections, cve matches, devices by type
    console.log('PAYLOAD KEYS vs PRIVACY.md: trap touches / bad connections / devices by type')
    // turning it off changes the label and keeps the payload visible ("the exact payload is always visible there")
    const sw = page.getByRole('switch', { name: /anonymous signal/i }).first()
    await sw.click()
    await expect(page.getByText(/Saved|saved/).first()).toBeVisible()
    await shot('signal-off')
    expect(await page.locator('#telemetry pre, #telemetry code').first().innerText()).toContain('install_id')
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
