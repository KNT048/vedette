import { createHmac } from 'node:crypto'
import { expect, test, type Page } from '@playwright/test'
import { collectErrors, expectAccessible, shot } from '../helpers'
import { DIACRITICS, finishClean, sampleStart, setEgress } from './clean'

// QA module exposure (S-EXP-1): one list of targets (domains and public IPs; a name under a domain sits under it). A domain is
// proven by a DNS TXT record; this box's own public IPs are found by the box and proven by its going out through them.
// An administrator's first Scan now (two-step sign-in on) records the confirmation; no tick box, no consent documents.
const api = (page: Page, method: string, path: string, body?: unknown) =>
  page.evaluate(async ([m, p, b]) => {
    const r = await fetch(`/api/v1${p as string}`, { method: m as string, headers: { 'Content-Type': 'application/json' }, body: b ? JSON.stringify(b) : undefined })
    return { status: r.status, body: await r.json().catch(() => null) }
  }, [method, path, body] as const)
const ASIS_PART = 'Vedette is provided as is under the Apache-2.0 license'
const NOTICE = '2026-11-18' // the current confirmation sentence (contract.ts NOTICE_VERSION)
const B32 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'
/** RFC 6238 code (SHA-1, 6 digits, 30 s) written in the test, like twofa.spec.ts. */
function totp(secret: string, now: number) {
  let bits = 0, v = 0
  const key: number[] = []
  for (const c of secret.toUpperCase()) { const i = B32.indexOf(c); if (i < 0) continue; v = (v << 5) | i; bits += 5; if (bits >= 8) { key.push((v >>> (bits - 8)) & 255); bits -= 8 } }
  const c = Buffer.alloc(8); c.writeBigUInt64BE(BigInt(Math.floor(now / 30000)))
  const h = createHmac('sha1', Buffer.from(key)).update(c).digest()
  const o = h[19]! & 15
  return String((((h[o]! & 127) << 24) | (h[o + 1]! << 16) | (h[o + 2]! << 8) | h[o + 3]!) % 1_000_000).padStart(6, '0')
}
/** Turn on two-step sign-in for the signed-in administrator through the account API (an authenticator app). */
async function turnOnTwoStep(page: Page, password: string) {
  const start = await api(page, 'POST', '/core/account/2fa/start', { password })
  expect(start.status).toBe(200)
  const now = await page.evaluate(() => Date.now()) // the page's clock: a test that moves it must get the code of the page's time
  expect((await api(page, 'POST', '/core/account/2fa/confirm', { code: totp(start.body.secret, now) })).status).toBe(200)
}
/** A table on a wide screen, a list on a phone: the same name either way. */
const tableOrList = (page: Page, name: string) => page.getByRole('table', { name }).or(page.getByRole('list', { name }))
const targets = (page: Page) => tableOrList(page, 'Targets')
const link = (page: Page, value: string) => targets(page).getByRole('link', { name: value, exact: true })
const nodeId = async (page: Page, value: string) => ((await api(page, 'GET', '/exposure/tree')).body.items as { id: string; value: string }[]).find((n) => n.value === value)?.id

test('clean install: no sample targets, the box finds its two IPs by itself; a domain goes through TXT verification, the commitment, a scan and deletion', async ({ page, isMobile }) => {
  test.setTimeout(120_000)
  const errors = collectErrors(page)
  const size = isMobile ? 'mobile' : 'desktop'
  await page.clock.install() // time flows; the test jumps over the 30 seconds between two DNS checks of a target
  await finishClean(page)
  await page.goto('/exposure')
  await expect(page.locator('header:has(h1)').first()).toContainText('2 targets, none scanned yet')
  await expect(page.getByText('example.com')).toHaveCount(0)
  await expect(link(page, '203.0.113.10')).toBeVisible() // found at first start, nothing was clicked
  await expect(link(page, '203.0.113.11')).toBeVisible()
  await expect(targets(page).getByText('Needs an admin\'s first scan').first()).toBeVisible()
  await shot(page, 'exposure', `clean-start-${size}`)
  await expectAccessible(page, 'exposure clean start')

  // Bad input: error in the field, typed value kept, Enter submits, an IP is not a domain.
  await page.getByRole('button', { name: 'Add target' }).first().click()
  const dlg = page.getByRole('dialog', { name: 'Add a target' })
  const input = dlg.getByRole('textbox', { name: 'Domain' })
  await input.press('Enter')
  await expect(dlg.getByText('Enter a domain, for example example.com.')).toBeVisible()
  await input.fill('https://example.com/')
  await input.press('Enter')
  await expect(dlg.getByText(/without http:\/\//).last()).toBeVisible()
  await expect(input).toHaveValue('https://example.com/')
  await input.fill('203.0.113.5')
  await input.press('Enter')
  await expect(dlg.getByText(/IP address.*choose Public IP/i)).toBeVisible()
  await page.keyboard.press('Escape')
  await expect(page.getByRole('dialog')).toHaveCount(0)

  await page.getByRole('button', { name: 'Add target' }).first().click()
  await input.fill('Shop-Test.Example')
  await input.press('Enter')
  await expect(page).toHaveURL(/\/exposure\/xt-/)
  const url = page.url().split('?')[0]!
  const id = url.split('/').pop()!
  await expect(page.locator('header:has(h1)').first()).toContainText('shop-test.example needs ownership proof before it can be scanned')
  const scan = page.getByRole('button', { name: 'Scan now', exact: true })
  await expect(scan).toBeDisabled()
  await expect(page.getByText('Cannot scan yet: shop-test.example has no ownership proof. Prove it on the Ownership tab.')).toBeVisible()
  const ownership = page.getByRole('tabpanel', { name: /^Ownership/ })
  await expect(page.getByRole('tab', { name: /^Ownership/, selected: true })).toBeVisible() // a new domain opens on its proof
  await expect(ownership.getByText(/^vedette-verify=[0-9a-f]{16}$/)).toBeVisible()
  await expect(page.getByText(/reverse dns/i)).toHaveCount(0)
  await expect(page.locator('input[type="file"]')).toHaveCount(0)
  await shot(page, 'exposure', `target-unverified-${size}`)
  await expectAccessible(page, 'target unverified')

  // First check: not found; survives a reload; the next check (after the 30-second pause) finds it.
  await ownership.getByRole('button', { name: 'Check', exact: true }).click()
  await expect(ownership.getByRole('status').filter({ hasText: /^Not found/ })).toBeVisible()
  await expect(ownership.getByRole('button', { name: /^Check again in \d+ s$/ })).toBeDisabled()
  await page.reload()
  await expect(ownership.getByRole('status').filter({ hasText: /^Not found/ })).toBeVisible()
  await page.clock.fastForward('00:31')
  await ownership.getByRole('button', { name: 'Check', exact: true }).click()
  await expect(ownership.getByRole('status').filter({ hasText: /^Found/ })).toBeVisible()
  await expect(page.locator('header:has(h1)').first()).toContainText('shop-test.example is ready for its first scan')

  // Proven but not confirmed, administrator without two-step sign-in: no scan, in the button (with the way to turn it on) and in the API.
  await scan.click()
  await expect(page.getByRole('alert').filter({ hasText: 'Turn on two-step sign-in' })).toBeVisible()
  await expect(page.getByRole('link', { name: 'Turn on two-step sign-in' })).toHaveAttribute('href', '/settings/account?tab=sign-in#two-step')
  const blocked = await api(page, 'POST', `/exposure/tree/${id}/scan`, { notice_version: NOTICE })
  expect(blocked.status).toBe(403)
  expect(blocked.body.error.code).toBe('twofa_required')

  // With two-step sign-in on, the sentence stands next to the button; there is no tick box for it. Scan now records it.
  await turnOnTwoStep(page, 'a-very-long-password-123')
  await page.reload()
  const note = page.getByRole('note', { name: 'Pressing Scan now records this confirmation' })
  await expect(note).toContainText('By choosing Scan now I confirm that my company owns shop-test.example')
  await expect(note).toContainText(ASIS_PART)
  await expect(page.getByRole('checkbox', { name: /I confirm/ })).toHaveCount(0)
  await shot(page, 'exposure', `commitment-${size}`)
  await expect(scan).toBeEnabled()
  await scan.click()
  await expect(note).toHaveCount(0) // recorded: the next scans need no confirmation
  await page.getByRole('tab', { name: /^Ownership/ }).click()
  await expect(page.getByText(/Confirmed by admin@testco\.example on .*, by pressing Scan now\./)).toBeVisible()
  await page.getByRole('tab', { name: 'Scans' }).click()
  await page.clock.fastForward('00:05') // the mock's run ends a few seconds after it starts
  await page.reload()
  await expect(page.getByRole('tabpanel', { name: 'Scans' }).getByText(/Done|Finished/).first()).toBeVisible()
  await shot(page, 'exposure', `target-scanned-${size}`)
  await expectAccessible(page, 'target scanned')

  // The audit log recorded who confirmed and when.
  expect(JSON.stringify((await api(page, 'GET', '/core/audit')).body)).toContain('exposure.commitment')

  // Delete: the confirmation says what is lost, Cancel keeps it, Delete removes it.
  await page.goto(url)
  await page.getByRole('button', { name: 'Delete', exact: true }).click()
  const del = page.getByRole('dialog', { name: 'Delete shop-test.example?' })
  await expect(del).toContainText('This cannot be undone.')
  await del.getByRole('button', { name: 'Cancel' }).click()
  await expect(page.getByRole('dialog')).toHaveCount(0)
  await page.getByRole('button', { name: 'Delete', exact: true }).click()
  await del.getByRole('button', { name: 'Delete', exact: true }).click()
  await expect(page).toHaveURL(/\/exposure(\?|$)/)
  await expect(link(page, 'shop-test.example')).toHaveCount(0)
  expect((await api(page, 'GET', `/exposure/tree/${id}`)).status).toBe(404)
  expect(errors).toEqual([])
})

// The company uses two public IPs behind a load balancer: auto-detect is all it needs.
// Steps: first start finds both IPs without a click; auto-detect off keeps the list and hides the interval; on again; change the interval; remove one IP
// (the confirmation says whether it comes back); Detect now brings it back; the Ignored list keeps it out until Restore. Light, then dark; desktop and phone.
test('clean install, two public IPs behind a load balancer: auto-detect finds both, remove one, Detect now brings it back', async ({ page, isMobile }) => {
  test.setTimeout(120_000)
  const errors = collectErrors(page)
  const size = isMobile ? 'mobile' : 'desktop'
  await finishClean(page) // its first page load already ran the first check, on the default addresses
  await setEgress(page, '198.51.100.7,198.51.100.8')
  const box = page.getByRole('region', { name: 'Public IP of this box' }) // the Settings tab
  const ignoredBox = page.getByRole('region', { name: 'Ignored IPs' })
  const toggle = box.getByRole('switch', { name: "Detect the box's public IPs automatically" })
  const settings = async () => { await page.goto('/exposure?tab=settings'); await expect(box.getByRole('button', { name: 'Detect now' })).toBeVisible() }
  const list = async () => { await page.goto('/exposure?tab=targets'); await expect(targets(page)).toBeVisible() }
  await settings()
  await box.getByRole('button', { name: 'Detect now' }).click()
  await expect(box.getByRole('status').filter({ hasText: /^Succeeded/ })).toContainText('The box reaches the Internet via 2 public IPs: 198.51.100.7, 198.51.100.8.')
  await list()
  await expect(link(page, '198.51.100.7')).toBeVisible()
  await expect(link(page, '198.51.100.8')).toBeVisible()
  await settings()
  await expect(box.getByText('Auto-detect is on: the box checks its public IPs every hour.')).toBeVisible()
  await expect(box.getByRole('textbox')).toHaveCount(0) // the box's own IP is never typed in here
  await shot(page, 'exposure', `box-ip-two-ips-${size}`)
  await expectAccessible(page, 'exposure box ips')

  // Manual mode: the interval goes away, Detect now stays, and the list keeps its IPs.
  await toggle.click()
  await expect(box.getByText('Auto-detect is off: the box checks only when you select Detect now.')).toBeVisible()
  await expect(box.getByRole('combobox', { name: 'Check every' })).toHaveCount(0)
  await expect(box.getByRole('button', { name: 'Detect now' })).toBeEnabled()
  await toggle.click()
  await expect(box.getByRole('combobox', { name: 'Check every' })).toHaveValue('60')
  await box.getByRole('combobox', { name: 'Check every' }).selectOption('15')
  await expect(box.getByText('Auto-detect is on: the box checks its public IPs every 15 minutes.')).toBeVisible()
  await page.reload()
  await expect(box.getByRole('combobox', { name: 'Check every' })).toHaveValue('15') // saved
  await list()
  await expect(link(page, '198.51.100.8')).toBeVisible()

  // Remove one IP from its own page: the confirmation offers "Don't add it again if detected" (ticked) and says what happens; Cancel keeps the IP.
  const KEEP_OFF = "Don't add it again if detected"
  const dialog = page.getByRole('dialog', { name: 'Delete 198.51.100.8?' })
  const removeIp = async () => { await list(); await link(page, '198.51.100.8').click(); await page.getByRole('button', { name: 'Delete', exact: true }).click(); await expect(dialog).toBeVisible() }
  await removeIp()
  await expect(dialog.getByRole('checkbox', { name: KEEP_OFF })).toBeChecked()
  await expect(dialog).toContainText('Vedette will never add this IP back and never scan it.')
  await shot(page, 'exposure', `box-ip-remove-${size}`)
  await dialog.getByRole('checkbox', { name: KEEP_OFF }).uncheck()
  await expect(dialog).toContainText('it is added again as a new target')
  await dialog.getByRole('button', { name: 'Cancel' }).click()
  await expect(dialog).toHaveCount(0)
  await list()
  await expect(link(page, '198.51.100.8')).toBeVisible()

  // Unticked: the IP is only removed, and the next check brings it back while the box still uses it.
  await removeIp()
  await expect(dialog.getByRole('checkbox', { name: KEEP_OFF })).toBeChecked() // ticked again for every removal
  await dialog.getByRole('checkbox', { name: KEEP_OFF }).uncheck()
  await dialog.getByRole('button', { name: 'Delete', exact: true }).click()
  await expect(page).toHaveURL(/\/exposure(\?|$)/)
  await expect(link(page, '198.51.100.8')).toHaveCount(0)
  await expect(link(page, '198.51.100.7')).toBeVisible()
  await settings()
  await expect(ignoredBox.getByText('198.51.100.8')).toHaveCount(0)
  await box.getByRole('button', { name: 'Detect now' }).click()
  await expect(box.getByRole('status').filter({ hasText: /^Succeeded/ })).toContainText('198.51.100.7, 198.51.100.8')
  await list()
  await expect(link(page, '198.51.100.8')).toBeVisible()

  // Ticked (the default): the IP goes on the Ignored list. Detect now does not add it back; Restore lets the next Detect now add it again.
  await removeIp()
  await dialog.getByRole('button', { name: 'Delete', exact: true }).click()
  await expect(link(page, '198.51.100.8')).toHaveCount(0)
  await settings()
  await expect(ignoredBox.getByText('198.51.100.8')).toBeVisible()
  await expect(ignoredBox.getByRole('textbox')).toHaveCount(0) // the list only blocks: an IP is never typed in
  await shot(page, 'exposure', `box-ip-ignored-${size}`)
  await expectAccessible(page, 'exposure ignored list')
  await box.getByRole('button', { name: 'Detect now' }).click()
  await expect(box.getByRole('status').filter({ hasText: /^Succeeded/ })).toContainText('Not added, on your Ignored list: 198.51.100.8.')
  await list()
  await expect(link(page, '198.51.100.8')).toHaveCount(0)
  await expect(link(page, '198.51.100.7')).toBeVisible()
  await settings()
  await ignoredBox.getByRole('button', { name: 'Restore 198.51.100.8' }).click()
  await expect(ignoredBox.getByText('No ignored IPs')).toBeVisible()
  await list()
  await expect(link(page, '198.51.100.8')).toHaveCount(0) // restoring adds nothing by itself
  await settings()
  await box.getByRole('button', { name: 'Detect now' }).click()
  await expect(box.getByRole('status').filter({ hasText: /^Succeeded/ })).toContainText('198.51.100.7, 198.51.100.8')
  await list()
  await expect(link(page, '198.51.100.8')).toBeVisible()

  // Audited: the first start by the box itself ("system"), the removal, the Ignored list and the clicks by the person.
  const audit = JSON.stringify((await api(page, 'GET', '/core/audit')).body)
  expect(audit).toContain('exposure.auto_detect')
  expect(audit).toContain('"user":"system"')
  expect(audit).toContain('exposure.target_delete')
  expect(audit).toContain('exposure.ip_restore')
  // An address typed as a domain, or a private one typed as an IP, is refused by the server; so is an interval below 5 minutes.
  expect((await api(page, 'POST', '/exposure/tree', { value: '198.51.100.9', kind: 'domain' })).body.error.code).toBe('ip_not_allowed')
  expect((await api(page, 'POST', '/exposure/tree', { value: '10.0.0.9', kind: 'ip' })).body.error.code).toBe('ip_not_allowed')
  expect((await api(page, 'PUT', '/exposure/box-ip/settings', { auto: true, interval_min: 0 })).body.error.code).toBe('bad_interval')

  // Dark: same page, same answer, readable.
  await page.emulateMedia({ colorScheme: 'dark' })
  await page.reload() // a fresh render: colours caught mid-transition are not what a person reads
  await expect(link(page, '198.51.100.8')).toBeVisible()
  await shot(page, 'exposure', `box-ip-two-ips-dark-${size}`)
  await expectAccessible(page, 'exposure box ips dark')
  expect(errors).toEqual([])
})

test('clean install: Detect now refuses private and CGNAT results; a public IP gets its page, is verified only while the box goes out through it, and is scanned', async ({ page, isMobile }) => {
  test.setTimeout(120_000)
  const errors = collectErrors(page)
  // "The box cannot reach the public IP services" is answered 502 unreachable. The browser logs every 502 as a console error, and collectErrors
  // keeps 5xx on purpose. So this one request is expected: count its 502s, take exactly that many console entries out at the end, and leave
  // every other error (including a surprise 502 elsewhere) fatal.
  let detect502 = 0
  page.on('response', (r) => { if (r.status() === 502 && r.request().method() === 'POST' && r.url().endsWith('/api/v1/exposure/box-ip/verify')) detect502++ })
  await finishClean(page)
  await page.goto('/exposure?tab=settings')
  const box = page.getByRole('region', { name: 'Public IP of this box' })
  const result = box.getByRole('status').filter({ hasText: /^(Succeeded|Failed)/ })
  await box.getByRole('button', { name: 'Detect now' }).waitFor()
  // how the box finds its IPs is behind the section's ⓘ; its text is the button's accessible description
  await expect(box.getByRole('button', { name: 'About Public IP of this box' })).toHaveAccessibleDescription(/.+/)
  await setEgress(page, '100.64.20.7')
  await box.getByRole('button', { name: 'Detect now' }).click()
  await expect(result).toContainText('private, reserved or shared carrier (CGNAT) address')
  await expect(result).toContainText('Failed')
  await shot(page, 'exposure', `box-ip-refused-${isMobile ? 'mobile' : 'desktop'}`)
  await setEgress(page, 'offline')
  await box.getByRole('button', { name: 'Detect now' }).click()
  await expect(result).toContainText('could not reach the public IP services')
  await setEgress(page, '198.51.100.7')
  await box.getByRole('button', { name: 'Detect now' }).click()
  await expect(result).toContainText('The box reaches the Internet via 198.51.100.7. Verified until')
  await page.goto('/exposure?tab=targets')
  await link(page, '198.51.100.7').click()
  await expect(page).toHaveURL(/\/exposure\/xt-/)
  await expect(page.locator('header:has(h1)').first()).toContainText('198.51.100.7 is ready for its first scan')
  await page.getByRole('tab', { name: /^Ownership/ }).click()
  const ownership = page.getByRole('tabpanel', { name: /^Ownership/ })
  await expect(ownership.getByText('This IP is proved because this box reaches the Internet through it.')).toBeVisible()
  await expect(ownership.getByText('Last seen by the box')).toBeVisible()
  await expect(ownership.getByText('Expires on')).toBeVisible()
  await expect(ownership.getByText('Valid', { exact: true })).toBeVisible()

  // Wrong route: the box now goes out elsewhere, so Verify again explains what to do, and Scan now waits for the proof.
  await setEgress(page, '198.51.100.8')
  await ownership.getByRole('button', { name: 'Verify again', exact: true }).click()
  await expect(ownership.getByText('This box currently reaches the Internet via 198.51.100.8, not 198.51.100.7. Ask your admin to route the box through 198.51.100.7 (for example switch WAN), then verify again.')).toBeVisible()
  await expect(page.getByRole('button', { name: 'Scan now', exact: true })).toBeDisabled()
  await shot(page, 'exposure', `ip-wrong-route-${isMobile ? 'mobile' : 'desktop'}`)
  await expectAccessible(page, 'ip target wrong route')
  await setEgress(page, '198.51.100.7')
  await ownership.getByRole('button', { name: 'Verify again', exact: true }).click()
  await expect(ownership.getByRole('status').filter({ hasText: /^Verified/ })).toContainText('The box reaches the Internet via 198.51.100.7.')

  // The administrator's first Scan now (two-step sign-in on) records the confirmation; the run goes to the Scans tab.
  await turnOnTwoStep(page, 'a-very-long-password-123')
  await page.reload()
  await page.getByRole('button', { name: 'Scan now', exact: true }).click()
  await expect(page.getByRole('note', { name: 'Pressing Scan now records this confirmation' })).toHaveCount(0)
  await page.getByRole('tab', { name: /^Ownership/ }).click()
  await expect(page.getByText(/Confirmed by admin@testco\.example on .*, by pressing Scan now\./)).toBeVisible()
  await page.getByRole('tab', { name: 'Scans' }).click()
  await expect(page.getByRole('tabpanel', { name: 'Scans' }).getByText(/Running|Queued|Done|Finished/).first()).toBeVisible()
  await expect(page.getByRole('tab', { name: 'Names' })).toHaveCount(0) // an IP has no names under it
  await expectAccessible(page, 'ip target scans')
  expect(detect502, 'the offline Detect now answered 502 once').toBe(1)
  const is502 = (m: string) => /status of 502/.test(m)
  expect(errors.filter(is502), 'one console entry per expected 502').toHaveLength(detect502)
  expect(errors.filter((m) => !is502(m))).toEqual([])
})

test('sample: a domain without its TXT record and a typed IP without proof cannot be scanned (button and API); a name its parent proves can; Scan now runs', async ({ page, isMobile }) => {
  test.setTimeout(120_000)
  const errors = collectErrors(page)
  await sampleStart(page)
  await page.goto('/exposure')
  await expect(page.locator('header:has(h1)').first()).toContainText(/^\d+ open issues on your Internet-facing targets$/)
  await expect(link(page, '198.51.100.2')).toBeVisible()
  await expect(targets(page)).toContainText(/git\.example\.com\s*under example\.com\s*Covered\s*by the proof of example\.com/)
  await shot(page, 'exposure', `list-${isMobile ? 'mobile' : 'desktop'}`)
  await expectAccessible(page, 'exposure list')

  // A domain whose TXT record was not found: locked, with the reason, and the API says the same.
  await page.goto('/exposure/xt-13?tab=ownership')
  await expect(page.locator('header:has(h1)').first()).toContainText('shop.example.net needs ownership proof before it can be scanned')
  await expect(page.getByRole('button', { name: 'Scan now', exact: true })).toBeDisabled()
  await expect(page.getByRole('tabpanel', { name: /^Ownership/ }).getByRole('status').filter({ hasText: /^Not found/ })).toBeVisible()
  expect((await api(page, 'POST', '/exposure/tree/xt-13/scan')).body.error.code).toBe('not_verified')
  await shot(page, 'exposure', `domain-unproved-${isMobile ? 'mobile' : 'desktop'}`)

  // An IP typed in by a person: proved by a token file or a reverse DNS name, never scanned before.
  await page.goto('/exposure/xt-15?tab=ownership')
  await expect(page.locator('header:has(h1)').first()).toContainText('198.51.100.3 needs ownership proof before it can be scanned')
  await expect(page.getByRole('button', { name: 'Scan now', exact: true })).toBeDisabled()
  await expect(page.getByText('Prove this address is yours with a token file served on it, or with a reverse DNS name.')).toBeVisible()
  expect((await api(page, 'POST', '/exposure/tree/xt-15/scan')).body.error.code).toBe('not_verified')

  // A name under a proven domain is covered by its proof; its results are there, and Scan now queues a run.
  await page.goto('/exposure/xt-12')
  await expect(page.getByRole('heading', { level: 1 })).toHaveText(/^git\.example\.com: \d+ open issues?$/)
  await expect(tableOrList(page, 'Issues of git.example.com')).toBeVisible()
  await page.getByRole('tab', { name: /^Services/ }).click()
  await expect(page.getByRole('tabpanel', { name: /^Services/ }).getByRole('table').or(page.getByRole('tabpanel', { name: /^Services/ }).getByRole('list')).first()).toBeVisible()
  await expectAccessible(page, 'xt-12 services')
  const scan = page.getByRole('button', { name: /^(Deep scan|Scan) now$/ })
  await expect(scan).toBeEnabled()
  await scan.click()
  await page.getByRole('tab', { name: 'Scans' }).click()
  await expect(page.getByRole('tabpanel', { name: 'Scans' }).getByText(/Running|Queued/).first()).toBeVisible()
  expect((await api(page, 'POST', '/exposure/tree/xt-12/scan')).body.error.code).toBe('busy') // one run of a target at a time
  expect(errors).toEqual([])
})

test('viewer: results are visible, every action is locked with a visible reason', async ({ page, isMobile }) => {
  await sampleStart(page)
  // On a phone the account menu sits behind "Open menu" (qa/shell.spec.ts); the locks must hold there too.
  if (isMobile) await page.getByRole('button', { name: 'Open menu' }).click()
  await page.getByRole('button', { name: /Account/ }).first().click()
  await page.getByRole('menuitem', { name: 'Sign out' }).click()
  await page.getByLabel('Email', { exact: true }).fill('director@acme.example')
  await page.getByLabel('Password', { exact: true }).fill('vedette-demo')
  await page.getByRole('button', { name: 'Sign in' }).click()
  await page.goto('/exposure/xt-14')
  await expect(tableOrList(page, 'Issues of 198.51.100.2')).toBeVisible()
  await expect(page.getByRole('button', { name: /^(Deep scan|Scan) now$/ })).toBeDisabled()
  await expect(page.getByRole('button', { name: 'Delete', exact: true })).toBeDisabled()
  await expect(page.getByRole('button', { name: 'Edit', exact: true })).toBeDisabled()
  await expect(page.getByText(/You have view-only access|Requires (Operator|Admin) role/).first()).toBeVisible()
  await page.goto('/exposure')
  await expect(page.getByRole('button', { name: 'Add target' }).first()).toBeDisabled()
  await page.goto('/exposure?tab=settings')
  await expect(page.getByRole('switch', { name: "Detect the box's public IPs automatically" })).toBeDisabled()
  await expect(page.getByRole('button', { name: 'Detect now' })).toBeDisabled()
  await expect(page.getByRole('button', { name: 'Restore 203.0.113.77' })).toBeDisabled()
  await expect(page.getByText('Requires Admin role').first()).toBeVisible()
})

test('English only and dark mode: no Vietnamese in any exposure page, no console errors', async ({ page }) => {
  test.setTimeout(120_000)
  const errors = collectErrors(page)
  await sampleStart(page)
  await page.emulateMedia({ colorScheme: 'dark' })
  const paths = ['/exposure', '/exposure?tab=settings', '/exposure/xt-11', '/exposure/xt-11?tab=names', '/exposure/xt-12?tab=services', '/exposure/xt-13?tab=ownership',
    '/exposure/xt-14?tab=scans', '/exposure/xt-14?tab=ownership', '/exposure/xt-14?tab=outside', '/exposure/xt-15?tab=ownership']
  for (const path of paths) {
    await page.goto(path)
    await expect(page.getByRole('heading', { level: 1 })).toBeVisible()
    await expect(page.getByRole('status').filter({ hasText: /^Loading$/ })).toHaveCount(0)
    const text = (await page.locator('main').innerText()).replace(/Sample data/g, '')
    expect(text.match(DIACRITICS), `${path} contains Vietnamese: ${text.match(/.{20}[ăâđêôơư].{20}/i)?.[0]}`).toBeNull()
    await shot(page, 'exposure', `dark-${path.replace(/\W/g, '_')}`)
    await expectAccessible(page, `${path} dark`)
  }
  expect(errors).toEqual([])
})

test('clean install: an IPv6 address is refused like a private one, an IP page offers the same Delete dialog, the shared 10 attempts show on Detect now, one date format', async ({ page, isMobile }) => {
  test.setTimeout(120_000)
  const errors = collectErrors(page)
  await finishClean(page)
  await page.goto('/exposure')
  await expect(link(page, '203.0.113.10')).toBeVisible() // the box found its IPs by itself at first start

  // IPv6 is not a domain, and as a Public IP it is refused with the reason.
  await page.getByRole('button', { name: 'Add target' }).first().click()
  const dlg = page.getByRole('dialog', { name: 'Add a target' })
  const input = dlg.getByRole('textbox', { name: 'Domain' })
  for (const v of ['2001:4860:4860::8888', '[::1]']) {
    await input.fill(v)
    await input.press('Enter')
    await expect(dlg.getByText(/IP address/)).toBeVisible()
    await expect(dlg.getByText(/Enter only a domain name/)).toHaveCount(0)
  }
  await dlg.getByRole('button', { name: 'Public IP' }).click()
  const ip = dlg.getByRole('textbox', { name: /Public IP/ })
  await ip.fill('2001:4860:4860::8888')
  await ip.press('Enter')
  await expect(dlg.getByText(/IPv6 addresses cannot be scanned from the Internet/)).toBeVisible()
  await expect(page).toHaveURL(/\/exposure(\?|$)/)
  await page.keyboard.press('Escape')
  await expect(page.getByRole('dialog')).toHaveCount(0)

  // The IP's own page: Delete opens the dialog with "Don't add it again" ticked by default.
  await link(page, '203.0.113.10').click()
  await expect(page).toHaveURL(/\/exposure\/xt-/)
  await page.getByRole('tab', { name: /^Ownership/ }).click()
  await expect(page.getByText(/proved because (this|the) box reaches the Internet through it/i)).toHaveCount(1)
  await expect(page.getByRole('button', { name: 'About Verify again' })).toHaveAccessibleDescription(/.+/) // the details are behind the ⓘ
  await page.getByRole('button', { name: 'Delete', exact: true }).click()
  const del = page.getByRole('dialog', { name: 'Delete 203.0.113.10?' })
  await expect(del.getByRole('checkbox', { name: "Don't add it again if detected" })).toBeChecked()
  await shot(page, 'exposure', `ip-remove-dialog-${isMobile ? 'mobile' : 'desktop'}`)
  await del.getByRole('button', { name: 'Cancel' }).click()
  await expect(del).toHaveCount(0)

  // One date format everywhere: no 09/11/2026, no 2026-11-09, no "UTC".
  const main = await page.locator('main').innerText()
  expect(main).not.toMatch(/\b\d{1,2}\/\d{1,2}\/\d{4}\b|\b\d{4}-\d{2}-\d{2}\b|\bUTC\b/)
  expect(main).toMatch(/\b\d{1,2} (Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sept?|Oct|Nov|Dec) \d{4}\b/)

  // The 10 attempts an hour are shared (Detect now and Verify again of the box's IP); when they are used up Detect now says so and stays locked.
  const boxIp = await nodeId(page, '203.0.113.10')
  expect((await api(page, 'POST', `/exposure/tree/${boxIp}/verify`)).status).toBe(200)
  await page.goto('/exposure?tab=settings')
  const box = page.getByRole('region', { name: 'Public IP of this box' })
  await expect(box.getByRole('button', { name: 'Detect now' })).toBeVisible() // the mock API answers only once the page has started
  for (let i = 0; i < 9; i++) expect((await api(page, 'POST', '/exposure/box-ip/verify')).status).toBe(200)
  expect((await api(page, 'POST', `/exposure/tree/${boxIp}/verify`)).status).toBe(429)
  await page.reload()
  await expect(box.getByRole('button', { name: 'Detect now' })).toBeDisabled()
  await expect(box.getByText(/Try again in about \d+ minutes?\./)).toBeVisible()
  await shot(page, 'exposure', `detect-rate-limited-${isMobile ? 'mobile' : 'desktop'}`)
  await expectAccessible(page, 'exposure detect rate limited')
  expect(errors).toEqual([])
})
