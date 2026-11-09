import { expect, test, type Page } from '@playwright/test'
import { collectErrors, expectAccessible, shot } from '../helpers'
import { DIACRITICS, finishClean, sampleStart, setEgress } from './clean'

// QA module exposure (S-EXP-1): domain = DNS TXT only; public IP = only the IP this box uses to reach the Internet;
// one commitment checkbox instead of consent documents.
const api = (page: Page, method: string, path: string, body?: unknown) =>
  page.evaluate(async ([m, p, b]) => {
    const r = await fetch(`/api/v1${p as string}`, { method: m as string, headers: { 'Content-Type': 'application/json' }, body: b ? JSON.stringify(b) : undefined })
    return { status: r.status, body: await r.json().catch(() => null) }
  }, [method, path, body] as const)
const visible = (page: Page, text: string | RegExp) => page.getByText(text).locator('visible=true').first()
const ASIS = 'Vedette is provided as is under the Apache-2.0 license; its author, Kien Nguyen, is not responsible for how you use it.'
const COMMIT = 'I confirm my company owns this domain/IP and I am authorized to scan it.'

test('clean install: no sample targets, the box finds its two IPs by itself; a domain goes through TXT verification, the commitment, a scan and deletion', async ({ page, isMobile }) => {
  test.setTimeout(120_000)
  const errors = collectErrors(page)
  await finishClean(page)
  await page.goto('/exposure')
  await expect(page.getByRole('heading', { level: 1 })).toHaveText(/2 items cannot be scanned yet/)
  await expect(page.getByText('acme.example')).toHaveCount(0)
  await expect(page.locator('#box-ip').getByRole('link', { name: '203.0.113.10' })).toBeVisible() // found at first start, nothing was clicked
  await shot(page, 'exposure', `clean-empty-${isMobile ? 'mobile' : 'desktop'}`)
  await expectAccessible(page, 'exposure empty')

  // Bad input: error in the field, typed value kept, Enter submits, IPs cannot be typed.
  await page.getByRole('button', { name: 'Add domain' }).first().click()
  const input = page.getByRole('textbox', { name: 'Domain' })
  await input.press('Enter')
  await expect(page.getByText('Enter a domain, for example example.com.')).toBeVisible()
  await input.fill('https://example.com/')
  await input.press('Enter')
  await expect(page.getByText(/without http:\/\//)).toBeVisible()
  await expect(input).toHaveValue('https://example.com/')
  await input.fill('203.0.113.5')
  await input.press('Enter')
  await expect(page.getByText(/Public IPs are not typed in/)).toBeVisible()
  await page.keyboard.press('Escape')
  await expect(page.getByRole('dialog')).toHaveCount(0)

  await page.getByRole('button', { name: 'Add domain' }).first().click()
  await page.getByRole('textbox', { name: 'Domain' }).fill('Shop-Test.Example')
  await page.getByRole('textbox', { name: 'Domain' }).press('Enter')
  await expect(page).toHaveURL(/\/exposure\/xt-/)
  const url = page.url()
  const id = url.split('/').pop()!
  await expect(page.getByRole('heading', { level: 1 })).toHaveText(/shop-test\.example cannot be scanned yet: awaiting ownership proof/)
  const scan = page.getByRole('button', { name: 'Scan now' })
  await expect(scan).toBeDisabled()
  await expect(page.locator('#scan-reason')).toContainText('has no ownership proof')
  await expect(page.getByText(/vedette-verify=[0-9a-f]{16}/).first()).toBeVisible()
  await expect(page.getByText(/reverse dns/i)).toHaveCount(0)
  await expect(page.locator('input[type="file"]')).toHaveCount(0)
  await shot(page, 'exposure', `target-unverified-${isMobile ? 'mobile' : 'desktop'}`)
  await expectAccessible(page, 'target unverified')

  // First check: not found; survives a reload; second check: found.
  await page.getByRole('button', { name: 'Check', exact: true }).click()
  await expect(page.getByRole('status').filter({ hasText: 'was not found' })).toBeVisible()
  await page.reload()
  await expect(page.getByText('Not found').first()).toBeVisible()
  await page.getByRole('button', { name: 'Check', exact: true }).click()
  await expect(page.getByText(/Verified with a DNS TXT record/)).toBeVisible()

  // Verified but not confirmed: still no scan, in the button and in the API.
  await expect(scan).toBeDisabled()
  await expect(page.locator('#scan-reason')).toContainText('you have not confirmed')
  const blocked = await api(page, 'POST', `/exposure/targets/${id}/scan`)
  expect(blocked.status).toBe(400)
  expect(blocked.body.error.code).toBe('commitment_required')

  // Commitment: exact wording, as-is line, needs the tick.
  await expect(page.getByText(COMMIT)).toBeVisible()
  await expect(page.getByText(ASIS)).toBeVisible()
  await page.getByRole('button', { name: 'Confirm and allow scanning' }).click()
  await expect(page.getByText('Tick the box to confirm.')).toBeVisible()
  await page.getByRole('checkbox').check()
  await expect(page.getByText('Tick the box to confirm.')).toHaveCount(0)
  await shot(page, 'exposure', `commitment-${isMobile ? 'mobile' : 'desktop'}`)
  await page.getByRole('button', { name: 'Confirm and allow scanning' }).click()
  await expect(page.getByText(/Confirmed by admin@testco\.example on /)).toBeVisible()

  await expect(scan).toBeEnabled()
  await scan.click()
  await expect(page.getByRole('heading', { level: 1 })).toHaveText(/subdomain\(s\), \d+ admin interface\(s\)/)
  await expect(page.getByRole('table', { name: 'Ports open to the Internet' })).toBeVisible()
  await expect(page.getByText('At least two scan days are needed to compare')).toBeVisible()
  await shot(page, 'exposure', `target-results-${isMobile ? 'mobile' : 'desktop'}`)
  await expectAccessible(page, 'target with results')

  // The audit log recorded who ticked and when.
  const audit = await api(page, 'GET', '/core/audit')
  expect(JSON.stringify(audit.body)).toContain('exposure.commitment')

  // Delete: confirmation says what is lost, Cancel keeps it, Delete removes the data.
  await page.goto(url)
  await page.getByRole('button', { name: 'Delete target' }).click()
  await expect(page.getByRole('dialog')).toContainText('cannot be undone')
  await page.getByRole('button', { name: 'Cancel' }).click()
  await expect(page.getByRole('dialog')).toHaveCount(0)
  await page.getByRole('button', { name: 'Delete target' }).click()
  await page.getByRole('dialog').getByRole('button', { name: 'Delete', exact: true }).click()
  await expect(page).toHaveURL(/\/exposure$/)
  expect((await api(page, 'GET', `/exposure/targets/${id}/snapshots`)).status).toBe(404)
  expect(errors).toEqual([])
})

// kien 2026-11-09: "KH co nhieu IP public va load balance, chi can bat che do tu detect". The company uses two public IPs behind a load balancer.
// Walk: first start finds both IPs without a click; auto-detect off keeps the list and hides the interval; on again; change the interval; remove one IP
// (the confirmation says it comes back); Detect now brings it back. Light first, then dark; desktop and phone (the pane is a list on a phone).
test('clean install, two public IPs behind a load balancer: auto-detect finds both, remove one, Detect now brings it back', async ({ page, isMobile }) => {
  test.setTimeout(120_000)
  const errors = collectErrors(page)
  const size = isMobile ? 'mobile' : 'desktop'
  await finishClean(page)
  await setEgress(page, '198.51.100.7,198.51.100.8')
  await page.goto('/exposure')
  const box = page.locator('#box-ip')
  const link = (ip: string) => box.getByRole('link', { name: ip })
  const toggle = page.getByRole('switch', { name: "Detect the box's public IPs automatically" })

  // First start: nothing was clicked, both IPs are in the list and the last check says so.
  await expect(box.getByText('Auto-detect is on: the box checks its public IPs every hour.')).toBeVisible()
  await expect(link('198.51.100.7')).toBeVisible()
  await expect(link('198.51.100.8')).toBeVisible()
  await expect(box.getByRole('status')).toContainText('The box reaches the Internet via 2 public IPs: 198.51.100.7, 198.51.100.8.')
  await expect(box.getByText('Removed IPs come back if the box keeps using them while auto-detect is on, unless you chose not to add them again.')).toBeVisible()
  await expect(box.getByRole('textbox')).toHaveCount(0) // an IP is never typed in
  await shot(page, 'exposure', `box-ip-two-ips-${size}`)
  await expectAccessible(page, 'exposure box ips')

  // Manual mode: the interval goes away, the list and Detect now stay.
  await toggle.click()
  await expect(box.getByText('Auto-detect is off: the box checks only when you select Detect now.')).toBeVisible()
  await expect(box.getByRole('combobox', { name: 'Check every' })).toHaveCount(0)
  await expect(box.getByRole('button', { name: 'Detect now' })).toBeEnabled()
  await expect(link('198.51.100.8')).toBeVisible()
  await shot(page, 'exposure', `box-ip-auto-off-${size}`)
  await toggle.click()
  await expect(box.getByRole('combobox', { name: 'Check every' })).toHaveValue('60')
  await box.getByRole('combobox', { name: 'Check every' }).selectOption('15')
  await expect(box.getByText('Auto-detect is on: the box checks its public IPs every 15 minutes.')).toBeVisible()
  await page.reload()
  await expect(box.getByRole('combobox', { name: 'Check every' })).toHaveValue('15') // saved

  // Remove one IP: the confirmation asks "Don't add it again if detected" (ticked), the hint says what happens; Cancel keeps the IP.
  const KEEP_OFF = "Don't add it again if detected"
  const ignoredBox = page.locator('#box-ignored')
  await box.getByRole('button', { name: 'Remove 198.51.100.8' }).click()
  const dialog = page.getByRole('dialog')
  await expect(dialog).toContainText('Remove 198.51.100.8 from the list?')
  await expect(dialog.getByRole('checkbox', { name: KEEP_OFF })).toBeChecked()
  await expect(dialog).toContainText('Vedette will never add this IP back and never scan it.')
  await shot(page, 'exposure', `box-ip-remove-${size}`)
  await dialog.getByRole('checkbox', { name: KEEP_OFF }).uncheck()
  await expect(dialog).toContainText('it is added again as a new target')
  await dialog.getByRole('button', { name: 'Cancel' }).click()
  await expect(dialog).toHaveCount(0)
  await expect(link('198.51.100.8')).toBeVisible()

  // Unticked: the IP is only removed, and auto-detect brings it back when the box still uses it.
  await box.getByRole('button', { name: 'Remove 198.51.100.8' }).click()
  await expect(dialog.getByRole('checkbox', { name: KEEP_OFF })).toBeChecked() // ticked again for every removal
  await dialog.getByRole('checkbox', { name: KEEP_OFF }).uncheck()
  await dialog.getByRole('button', { name: 'Remove', exact: true }).click()
  await expect(link('198.51.100.8')).toHaveCount(0)
  await expect(link('198.51.100.7')).toBeVisible()
  await expect(ignoredBox.getByText('198.51.100.8')).toHaveCount(0)
  await box.getByRole('button', { name: 'Detect now' }).click()
  await expect(link('198.51.100.8')).toBeVisible()
  await expect(page.getByText('The box reaches the Internet via 2 public IPs: 198.51.100.7, 198.51.100.8. Each is verified until').first()).toBeVisible()

  // Ticked (the default): the IP goes on the Ignored list. Detect now does not add it back; Restore lets the next Detect now add it again.
  await box.getByRole('button', { name: 'Remove 198.51.100.8' }).click()
  await dialog.getByRole('button', { name: 'Remove', exact: true }).click()
  await expect(link('198.51.100.8')).toHaveCount(0)
  await expect(ignoredBox.getByText('198.51.100.8')).toBeVisible()
  await expect(ignoredBox.getByRole('textbox')).toHaveCount(0) // the list only blocks: an IP is never typed in
  await shot(page, 'exposure', `box-ip-ignored-${size}`)
  await expectAccessible(page, 'exposure ignored list')
  await box.getByRole('button', { name: 'Detect now' }).click()
  await expect(box.getByRole('status')).toContainText('Not added, on your Ignored list: 198.51.100.8.')
  await expect(link('198.51.100.8')).toHaveCount(0)
  await expect(link('198.51.100.7')).toBeVisible()
  await ignoredBox.getByRole('button', { name: 'Restore 198.51.100.8' }).click()
  await expect(ignoredBox.getByText('No ignored IPs')).toBeVisible()
  await expect(link('198.51.100.8')).toHaveCount(0) // restoring adds nothing by itself
  await box.getByRole('button', { name: 'Detect now' }).click()
  await expect(link('198.51.100.8')).toBeVisible()

  // Both audited: the first start by the box itself ("system"), the removal and the click by the person.
  const audit = JSON.stringify((await api(page, 'GET', '/core/audit')).body)
  expect(audit).toContain('exposure.auto_detect')
  expect(audit).toContain('"user":"system"')
  expect(audit).toContain('exposure.target_delete')
  expect(audit).toContain('exposure.ip_ignore')
  expect(audit).toContain('exposure.ip_restore')
  // Typing an IP is still refused by the server.
  expect((await api(page, 'POST', '/exposure/targets', { value: '198.51.100.9' })).body.error.code).toBe('ip_not_allowed')
  expect((await api(page, 'PUT', '/exposure/box-ip/settings', { auto: true, interval_min: 0 })).body.error.code).toBe('bad_interval')

  // Dark: same page, same answer, readable.
  await page.emulateMedia({ colorScheme: 'dark' })
  await expect(link('198.51.100.8')).toBeVisible()
  await shot(page, 'exposure', `box-ip-two-ips-dark-${size}`)
  await expectAccessible(page, 'exposure box ips dark')
  expect(errors).toEqual([])
})

test('clean install: Detect now refuses private and CGNAT results; a public IP gets its page, is confirmed and scanned', async ({ page, isMobile }) => {
  test.setTimeout(120_000)
  const errors = collectErrors(page)
  // "The box cannot reach the public IP services" is answered 502 unreachable (API_CONVENTIONS section 3, 502). The browser logs every 502 as a
  // console error, and collectErrors keeps 5xx on purpose. So this one request is expected: count its 502s, take exactly that many console
  // entries out at the end, and leave every other error (including a surprise 502 elsewhere) fatal.
  let detect502 = 0
  page.on('response', (r) => { if (r.status() === 502 && r.request().method() === 'POST' && r.url().endsWith('/api/v1/exposure/box-ip/verify')) detect502++ })
  await finishClean(page)
  await page.goto('/exposure')
  const box = page.locator('#box-ip')
  await box.getByRole('button', { name: 'Detect now' }).waitFor()
  await box.getByText('How the box finds its IPs').click()
  for (const t of [/You cannot type an IP/, /Private, reserved and shared carrier \(CGNAT/, /Detect now is limited to 10 attempts per hour/]) await expect(box.getByText(t)).toBeVisible()
  await setEgress(page, '100.64.20.7')
  await box.getByRole('button', { name: 'Detect now' }).click()
  await expect(box.getByRole('status')).toContainText('private, reserved or shared carrier (CGNAT) address')
  await expect(box.getByRole('status')).toContainText('Failed')
  await shot(page, 'exposure', `box-ip-refused-${isMobile ? 'mobile' : 'desktop'}`)
  await setEgress(page, 'offline')
  await box.getByRole('button', { name: 'Detect now' }).click()
  await expect(box.getByRole('status')).toContainText('could not reach the public IP services')
  await setEgress(page, '198.51.100.7')
  await box.getByRole('button', { name: 'Detect now' }).click()
  await expect(box.getByRole('status')).toContainText('The box reaches the Internet via 198.51.100.7. Verified until')
  await box.getByRole('link', { name: '198.51.100.7' }).click()
  await expect(page).toHaveURL(/\/exposure\/xt-/)
  await expect(page.getByRole('heading', { level: 1 })).toHaveText(/198\.51\.100\.7 cannot be scanned yet: needs your confirmation/)
  await expect(page.getByText('Last seen by the box')).toBeVisible()
  await expect(page.getByText('Expires on')).toBeVisible()
  await expect(page.getByText('Valid', { exact: true })).toBeVisible()
  await expect(page.getByRole('button', { name: 'Scan now' })).toBeDisabled()
  // Wrong route: the box now exits elsewhere, so Verify again explains what to do.
  await setEgress(page, '198.51.100.8')
  await page.getByRole('button', { name: 'Verify again' }).click()
  await expect(page.getByRole('status').filter({ hasText: 'This box currently reaches the Internet via 198.51.100.8, not 198.51.100.7. Ask your admin to route the box through 198.51.100.7 (for example switch WAN), then verify again.' })).toBeVisible()
  await setEgress(page, '198.51.100.7')
  await page.getByRole('button', { name: 'Verify again' }).click()
  await expect(page.getByRole('status').filter({ hasText: /Verified until/ })).toBeVisible()
  await page.getByRole('checkbox').check()
  await page.getByRole('button', { name: 'Confirm and allow scanning' }).click()
  // Scan-time check (D-79): the box no longer goes out through this IP, so the scan is paused, the IP stays, and it works again when the box is back.
  await expect(page.getByRole('button', { name: 'Scan now' })).toBeEnabled()
  await setEgress(page, '198.51.100.8')
  await page.getByRole('button', { name: 'Scan now' }).click()
  await expect(page.getByText(/no longer reaches the Internet through 198.51.100.7/).first()).toBeVisible()
  await expect(page.getByText(/Scans of it are paused until the box uses it again/).first()).toBeVisible()
  await shot(page, 'exposure', `scan-paused-${isMobile ? 'mobile' : 'desktop'}`)
  await setEgress(page, '198.51.100.7')
  await page.getByRole('button', { name: 'Scan now' }).click()
  await expect(page.getByRole('heading', { level: 1 })).toHaveText(/198\.51\.100\.7: \d+ open port\(s\)/)
  await expect(page.getByRole('heading', { name: 'Subdomains' })).toHaveCount(0)
  await expectAccessible(page, 'ip target results')
  expect(detect502, 'the offline Detect now answered 502 once').toBe(1)
  const is502 = (m: string) => /status of 502/.test(m)
  expect(errors.filter(is502), 'one console entry per expected 502').toHaveLength(detect502)
  expect(errors.filter((m) => !is502(m))).toEqual([])
})

test('sample: expired IP, expiring IP, missing TXT record and unverified domain cannot be scanned (button and API); the two live IPs are valid', async ({ page, isMobile }) => {
  test.setTimeout(120_000)
  const errors = collectErrors(page)
  await sampleStart(page)
  await page.goto('/exposure')
  await expect(page.getByRole('heading', { level: 1 })).toHaveText(/2 admin interfaces are exposed to the Internet/)
  await expect(page.locator('#box-ip').getByText('Auto-detect is on: the box checks its public IPs every hour.')).toBeVisible()
  await expect(page.locator('#box-ip').getByRole('link', { name: '203.0.113.11' })).toBeVisible() // the sample company has two live IPs behind a load balancer
  await expect(visible(page, /Expires in \d+ days/)).toBeVisible()
  await shot(page, 'exposure', `list-${isMobile ? 'mobile' : 'desktop'}`)
  await expectAccessible(page, 'exposure list')

  // Expired IP: locked; verify again only works when the box egresses through that IP.
  await page.goto('/exposure/xt-4')
  await expect(page.getByRole('heading', { level: 1 })).toHaveText(/203\.0\.113\.55 cannot be scanned yet: verification expired/)
  await expect(page.getByRole('button', { name: 'Scan now' })).toBeDisabled()
  expect((await api(page, 'POST', '/exposure/targets/xt-4/scan')).body.error.code).toBe('expired')
  await shot(page, 'exposure', `ip-expired-${isMobile ? 'mobile' : 'desktop'}`)
  await page.getByRole('button', { name: 'Verify again' }).click()
  await expect(page.getByRole('status').filter({ hasText: /not 203\.0\.113\.55/ })).toBeVisible()
  await setEgress(page, '203.0.113.55')
  await page.getByRole('button', { name: 'Verify again' }).click()
  await expect(page.getByRole('heading', { level: 1 })).toHaveText(/203\.0\.113\.55 is ready for its first scan/)
  await setEgress(page, null)

  // Missing TXT: scan blocked even though the domain was verified before; adding the record back fixes it.
  await page.goto('/exposure/xt-5')
  await expect(page.getByRole('heading', { level: 1 })).toHaveText(/old-site\.example cannot be scanned yet: DNS TXT record missing/)
  await expect(page.getByRole('button', { name: 'Scan now' })).toBeDisabled()
  expect((await api(page, 'POST', '/exposure/targets/xt-5/scan')).body.error.code).toBe('txt_missing')
  await page.getByRole('button', { name: 'Check again' }).click()
  await expect(page.getByRole('heading', { level: 1 })).toHaveText(/old-site\.example is ready for its first scan/)

  // Unverified domain: nothing to scan, commitment refused by the API.
  await page.goto('/exposure/xt-3')
  await expect(page.getByRole('button', { name: 'Scan now' })).toBeDisabled()
  expect((await api(page, 'POST', '/exposure/targets/xt-3/scan')).body.error.code).toBe('not_verified')
  expect((await api(page, 'POST', '/exposure/targets/xt-3/commitment', { confirm: true })).body.error.code).toBe('not_verified')

  // Compare two days and a fresh scan.
  await page.goto('/exposure/xt-1')
  await expect(page.getByRole('heading', { name: 'Compare two days' })).toBeVisible()
  await expect(page.getByText(/\d+ added, \d+ gone, \d+ changed/)).toBeVisible()
  await page.getByLabel('From date').selectOption({ index: 2 })
  await page.getByLabel('To date').selectOption({ index: 0 })
  await expect(page.getByText(/[1-9]\d* added/)).toBeVisible()
  await page.getByLabel('From date').selectOption({ index: 0 })
  await expect(page.getByText('Choose two different days.')).toBeVisible()
  await shot(page, 'exposure', `compare-${isMobile ? 'mobile' : 'desktop'}`)
  await expectAccessible(page, 'xt-1 compare')
  await page.getByRole('button', { name: 'Scan now' }).click()
  await expect(page.getByText('staging.acme.example').first()).toBeVisible()
  expect(errors).toEqual([])
})

test('viewer: results are visible, every action is locked with a visible reason', async ({ page, isMobile }) => {
  await sampleStart(page)
  // On a phone the account menu sits behind "Open menu" (qa/shell.spec.ts); the locks must hold there too.
  if (isMobile) await page.getByRole('button', { name: 'Open menu' }).click()
  await page.getByRole('button', { name: /Account/ }).first().click()
  await page.getByRole('menuitem', { name: 'Sign out' }).click()
  await page.getByLabel('Email').fill('director@acme.example')
  await page.getByLabel('Password').fill('vedette-demo')
  await page.getByRole('button', { name: 'Sign in' }).click()
  await page.goto('/exposure/xt-1')
  await expect(page.getByRole('table', { name: 'Ports open to the Internet' })).toBeVisible()
  await expect(page.getByRole('button', { name: 'Scan now' })).toBeDisabled()
  await expect(page.getByRole('button', { name: 'Delete target' })).toBeDisabled()
  await expect(page.getByText(/You have view-only access/)).toBeVisible()
  await page.goto('/exposure')
  await expect(page.getByRole('button', { name: 'Add domain' }).first()).toBeDisabled()
  await expect(page.getByRole('switch', { name: "Detect the box's public IPs automatically" })).toBeDisabled()
  await expect(page.getByRole('button', { name: 'Detect now' })).toBeDisabled()
  await expect(page.getByRole('button', { name: 'Remove 203.0.113.11' })).toBeDisabled()
  await expect(page.getByRole('button', { name: 'Restore 203.0.113.77' })).toBeDisabled()
  await expect(page.getByText('Requires Admin role').first()).toBeVisible()
})

test('English only and dark mode: no Vietnamese in any exposure page, no console errors', async ({ page }) => {
  const errors = collectErrors(page)
  await sampleStart(page)
  await page.emulateMedia({ colorScheme: 'dark' })
  for (const path of ['/exposure', '/exposure/xt-1', '/exposure/xt-2', '/exposure/xt-3', '/exposure/xt-4', '/exposure/xt-5', '/exposure/xt-6', '/exposure/xt-7']) {
    await page.goto(path)
    await expect(page.getByRole('heading', { level: 1 })).toBeVisible()
    await expect(page.getByRole('status').filter({ hasText: /^Loading$/ })).toHaveCount(0)
    const text = (await page.locator('main').innerText()).replace(/Sample data|Kiên/g, '')
    expect(text.match(DIACRITICS), `${path} contains Vietnamese: ${text.match(/.{20}[ăâđêôơư].{20}/i)?.[0]}`).toBeNull()
    await shot(page, 'exposure', `dark-${path.replace(/\W/g, '_')}`)
    await expectAccessible(page, `${path} dark`)
  }
  expect(errors).toEqual([])
})
