// The exposure module (External exposure) on the real backend, on a box that must not reach the internet (S-EXP-1, exposure INV-1, INV-2, INV-6, INV-7, INV-14, PRE-4, FORBID-1, FORBID-2).
// Steps from e2e/qa/exposure.spec.ts. Entity-scoped: every domain here is made and removed by the test that uses it; box-wide settings are in exposure.global.spec.ts.
// NOTHING HERE REACHES THE INTERNET. A public IP can only come from the three public "what is my IP" services (Detect now, auto-detect, Verify again of an IP), a domain
// is only proved by a real DNS TXT lookup (Check), and the box has no setting that sends either to a loopback fake. So no test presses them, and what needs them is NOT covered:
// a verified domain or IP, the commitment, a scan, the INV-13 pause, the Ignored list with an IP in it, the 10-attempts limit, Detect now offline. See .ai/deferred/feat-e2e-real-exposure.md.
// What is covered is everything on the way to those steps: the page, adding and refusing domains, the proof the box asks for, the refusals of scan and commitment on an unproven domain
// (and that they change nothing), deleting, the roles, the audit rows.
import { expect, test, type Page } from '@playwright/test'
import { ACCOUNTS, api, authFile } from './box'
import { anon, as, audit, auditIds, autoLine, domain, headline, list, made, refused, scanCell, snapshot, sweep, target, type ApiErr, type Tgt } from './exposure-shared'
import { expectAccessible, h1, noErrors, noVietnamese } from './ui'
import { collectErrors, shot } from '../e2e/helpers'

test.use({ actionTimeout: 10_000 })
test.afterEach(sweep)

const toast = (page: Page, re: RegExp) => expect(page.locator('[data-sonner-toast]').filter({ hasText: re }).first()).toBeVisible()
const domainTable = (page: Page) => page.getByRole('table', { name: 'Declared domains' })
const ipTable = (page: Page) => page.getByRole('table', { name: 'Public IPs of this box' })
const addPost = (page: Page) => page.waitForResponse((r) => r.url().endsWith('/api/v1/exposure/targets') && r.request().method() === 'POST')
const NEEDS_ADMIN = 'Requires Admin role'
const NEEDS_OPERATOR = 'Requires Operator role'
/** 5xx answers of the API that a page saw while a test ran: a test ends with `expect(server).toEqual([])`. */
function watch5xx(page: Page): string[] {
  const seen: string[] = []
  page.on('response', (r) => { if (r.url().includes('/api/') && r.status() >= 500) seen.push(`${r.request().method()} ${r.url()} ${r.status()}`) })
  return seen
}

/** The refusals of the add-domain call (INV-6, INV-2, FORBID-2): input, status, code and the exact message. */
const E_EMPTY = 'Enter a domain, for example example.com.'
const E_BAD = 'Enter only a domain name, without http://, a path, a port or spaces. Example: example.com.'
const E_DOMAIN = 'Not a valid domain. Example: example.com.'
const E_IP = 'Public IPs are not typed in. The box finds its own public IPs: turn on auto-detect or select "Detect now" under Public IPs of this box.'
const REFUSALS: [string, number, string, string][] = [
  ['', 400, 'empty', E_EMPTY],
  ['   ', 400, 'empty', E_EMPTY],
  ['https://example.com/', 400, 'bad_value', E_BAD],
  ['example.com/path', 400, 'bad_value', E_BAD],
  ['example.com:8080', 400, 'bad_value', E_BAD],
  ['user@example.com', 400, 'bad_value', E_BAD],
  ['two words.example', 400, 'bad_value', E_BAD],
  ['203.0.113.5', 400, 'ip_not_allowed', E_IP],
  ['8.8.8.8', 400, 'ip_not_allowed', E_IP],
  ['2001:db8::1', 400, 'ip_not_allowed', E_IP],
  ['[::1]', 400, 'ip_not_allowed', E_IP],
  ['::ffff:8.8.8.8', 400, 'ip_not_allowed', E_IP],
  ['localhost', 400, 'bad_value', E_DOMAIN],
  ['-bad.example', 400, 'bad_value', E_DOMAIN],
  ['bad_.example', 400, 'bad_value', E_DOMAIN],
  ['bad.123', 400, 'bad_value', E_DOMAIN],
  [`${'a'.repeat(64)}.example`, 400, 'bad_value', E_DOMAIN],
  [`${'a'.repeat(63)}.${'b'.repeat(63)}.${'c'.repeat(63)}.${'d'.repeat(63)}.example`, 400, 'bad_value', E_DOMAIN],
]

test.describe('the page, read as a viewer (S-EXP-1)', () => {
  test.use({ storageState: authFile('viewer') })

  test('it renders what the box holds, in English, accessibly, with no server error', async ({ page }) => {
    const errors = collectErrors(page)
    const server = watch5xx(page)
    const c = await as('viewer')
    let d
    try { d = await list(c) } finally { await c.dispose() }
    await page.goto('/exposure')
    await expect(h1(page)).toHaveText(headline(d.items))
    await expect(page.getByText('Sample data')).toHaveCount(0) // the real box never shows the mock's label
    await expect(page.getByText(/Only what you have proven you own and confirmed is scanned\./).first()).toBeVisible()
    await expect(page.getByText('Scanning your external surface is active scanning, so Vedette sets two conditions.')).toBeVisible()
    // Domains: one row per domain of the box, or the empty state
    const domains = d.items.filter((i) => i.kind === 'domain')
    if (domains.length === 0) {
      await expect(page.getByText('No domain yet')).toBeVisible()
      await expect(page.getByText('Select Add domain and follow the DNS TXT steps.')).toBeVisible()
    } else {
      await expect(domainTable(page).getByRole('row')).toHaveCount(domains.length + 1)
      for (const t of domains) {
        const row = domainTable(page).getByRole('row').filter({ has: page.getByRole('link', { name: t.value, exact: true }) })
        await expect(row, t.value).toHaveCount(1)
        await expect(row).toContainText(scanCell(t))
        await expect(row).toContainText(t.commitment ? 'Commitment confirmed' : 'Not confirmed yet')
      }
    }
    // Public IPs: the settings line, the last check exactly as stored, one row per IP, the Ignored list
    const box = page.locator('#box-ip')
    await expect(box.getByText(autoLine(d.box_ip), { exact: true })).toBeVisible()
    if (d.box_ip.last_run === null) await expect(box.getByText(/^No check yet\. The first check is a full check/)).toBeVisible()
    else {
      const status = box.getByRole('status')
      await expect(status).toContainText(d.box_ip.last_run.ok ? 'Succeeded' : 'Failed')
      await expect(status).toContainText(d.box_ip.last_run.message)
    }
    if (d.box_ip.retry_in_min === null) await expect(page.getByText(/Try again in about/)).toHaveCount(0)
    else await expect(page.getByText(`Try again in about ${d.box_ip.retry_in_min} minute${d.box_ip.retry_in_min === 1 ? '' : 's'}. The 10 attempts an hour are used up.`).first()).toBeVisible()
    await expect(box.getByRole('textbox')).toHaveCount(0) // an IP is never typed in (FORBID-2)
    const ips = d.items.filter((i) => i.kind === 'ip')
    if (ips.length === 0) {
      await expect(box.getByText('No public IP yet')).toBeVisible()
      await expect(box.getByText(d.box_ip.auto ? 'Select Detect now to look right away.' : 'Auto-detect is off. Turn it on, or select Detect now.')).toBeVisible()
    } else {
      await expect(ipTable(page).getByRole('row')).toHaveCount(ips.length + 1)
      for (const t of ips) {
        const row = ipTable(page).getByRole('row').filter({ has: page.getByRole('link', { name: t.value, exact: true }) })
        await expect(row, t.value).toHaveCount(1)
        await expect(row).toContainText(scanCell(t))
      }
    }
    const ignored = page.locator('#box-ignored')
    if (d.ignored.length === 0) await expect(ignored.getByText('No ignored IPs')).toBeVisible()
    else for (const i of d.ignored) await expect(ignored.getByRole('row').filter({ hasText: i.value })).toHaveCount(1)
    // the help says how the box finds its IP, and that nothing is typed
    await box.getByText('How the box finds its IPs').click()
    for (const t of [/checkip\.amazonaws\.com \(AWS\), icanhazip\.com \(Cloudflare\) and ifconfig\.me\/ip \(Google Cloud\)/, /You cannot type an IP\./, /Private, reserved and shared carrier \(CGNAT, 100\.64\.0\.0\/10\) addresses are refused/, /share 10 attempts per hour/]) await expect(box.getByText(t)).toBeVisible()
    await expect(page.locator('body')).not.toContainText(/undefined|NaN|\[object|1970|goroutine/)
    await expectAccessible(page, 'exposure list')
    await noVietnamese(page, 'exposure list')
    await shot(page, 'real', 'exposure-list')
    expect(server).toEqual([])
    noErrors(errors)
  })

  test('the API answers reads honestly: the same list for every role, an unknown target is a 404, a bad date is refused, nobody signed out reads anything', async () => {
    const c = await as('viewer')
    const out = await anon()
    try {
      const l = await list(c)
      expect(Object.keys(l).sort()).toEqual(['box_ip', 'ignored', 'items'])
      expect(Object.keys(l.box_ip).sort()).toEqual(['auto', 'interval_min', 'last_run', 'retry_in_min'])
      const NOPE = 'xt-nosuchtarget'
      const gone = refused(404, 'not_found', 'No such target. It may have been deleted.')
      for (const p of [`/exposure/targets/${NOPE}`, `/exposure/targets/${NOPE}/snapshots`]) expect(await api<ApiErr>(c, 'GET', p), p).toMatchObject(gone)
      expect(await api<ApiErr>(c, 'GET', `/exposure/targets/${NOPE}/snapshots/2026-01-01`)).toMatchObject(refused(404, 'not_found', 'No snapshot for this day.'))
      expect(await api<ApiErr>(c, 'GET', `/exposure/targets/${NOPE}/diff?from=2026-01-01&to=2026-01-02`)).toMatchObject(refused(404, 'not_found', 'There is no snapshot for one of the two selected days.'))
      for (const p of ['/exposure/targets/x/snapshots/yesterday', '/exposure/targets/x/diff?from=a&to=b', '/exposure/targets/x/diff']) expect((await api(c, 'GET', p)).status, p).toBe(400)
      for (const p of ['/me', '/exposure/targets', `/exposure/targets/${NOPE}`, '/exposure/targets/x/snapshots', '/exposure/targets/x/diff?from=2026-01-01&to=2026-01-02']) {
        expect(await api<ApiErr>(out, 'GET', p), `signed out: ${p}`).toMatchObject({ status: 401, body: { error: { code: 'unauthenticated' } } })
      }
      for (const role of ['operator', 'admin'] as const) {
        const other = await as(role)
        try { expect(await list(other), `${role} reads the same list`).toEqual(l) } finally { await other.dispose() }
      }
    } finally { await c.dispose(); await out.dispose() }
  })

  test('a target that does not exist: the page says so and offers the way back', async ({ page }) => {
    const errors = collectErrors(page)
    await page.goto('/exposure/xt-nosuchtarget')
    await expect(page.getByRole('alert').first()).toBeVisible()
    await expect(page.getByRole('link', { name: 'Back to external exposure' })).toHaveAttribute('href', '/exposure')
    await expect(page.locator('body')).not.toContainText(/undefined|\[object|goroutine|sql:/)
    await noVietnamese(page, 'target not found')
    noErrors(errors, /status of 404/)
  })
})

test.describe('domains as an administrator (S-EXP-1, INV-1, INV-6, INV-7, PRE-4)', () => {
  test.use({ storageState: authFile('admin') })

  test('the add form refuses what is not a domain, with the exact answer, and saves nothing', async ({ page }) => {
    const errors = collectErrors(page)
    const server = watch5xx(page)
    const admin = await as('admin')
    try {
      const before = await snapshot(admin)
      const auditBefore = await auditIds(admin, 'exposure.target_add')
      // every refusal through the API: status, code and the whole message
      for (const [value, status, code, message] of REFUSALS) {
        expect(await api<ApiErr>(admin, 'POST', '/exposure/targets', { value }), JSON.stringify(value)).toMatchObject(refused(status, code, message))
      }
      for (const body of [{}, { value: 5 }, { value: null }]) expect((await api(admin, 'POST', '/exposure/targets', body)).status, JSON.stringify(body)).toBe(400)
      expect(await snapshot(admin), 'a refusal saves nothing').toBe(before)
      // the form shows the server's own sentence in the field, keeps what was typed, and Enter submits
      await page.goto('/exposure')
      await page.getByRole('button', { name: 'Add domain' }).first().click()
      const dlg = page.getByRole('dialog', { name: 'Add a domain' })
      const input = dlg.getByRole('textbox', { name: 'Domain' })
      await input.press('Enter')
      await expect(dlg.getByText(E_EMPTY, { exact: true })).toBeVisible() // checked in the form: no request leaves
      for (const [value, , , message] of REFUSALS.filter((r) => ['https://example.com/', '203.0.113.5', '2001:db8::1', 'localhost'].includes(r[0]))) {
        await input.fill(value)
        const reply = addPost(page)
        await input.press('Enter')
        expect((await reply).status()).toBe(400)
        await expect(dlg.getByText(message, { exact: true })).toBeVisible()
        await expect(input).toHaveValue(value)
        await expect(input).toHaveAttribute('aria-invalid', 'true')
      }
      await expectAccessible(page, 'add domain dialog with an error')
      await page.keyboard.press('Escape')
      await expect(page.getByRole('dialog')).toHaveCount(0)
      expect(await snapshot(admin), 'the form saved nothing either').toBe(before)
      expect([...(await auditIds(admin, 'exposure.target_add'))].filter((id) => !auditBefore.has(id)), 'a refusal is not an audit row').toEqual([])
      expect(server).toEqual([])
      noErrors(errors, /status of 400/)
    } finally { await admin.dispose() }
  })

  test('add: the box asks for a DNS TXT proof and nothing can be scanned; delete removes it and leaves the audit log', async ({ page }) => {
    test.setTimeout(120_000)
    const errors = collectErrors(page)
    const server = watch5xx(page)
    const value = domain()
    made.push(value)
    const admin = await as('admin')
    const op = await as('operator')
    try {
      const auditBefore = await auditIds(admin, value)
      await page.goto('/exposure')
      await page.getByRole('button', { name: 'Add domain' }).first().click()
      const dlg = page.getByRole('dialog', { name: 'Add a domain' })
      await dlg.getByRole('textbox', { name: 'Domain' }).fill(` ${value.toUpperCase()} `) // the box keeps the lower-case name without the spaces
      await expect(dlg.getByRole('textbox', { name: 'Domain' })).toHaveValue(` ${value.toUpperCase()} `)
      const reply = addPost(page)
      await dlg.getByRole('textbox', { name: 'Domain' }).press('Enter')
      const res = await reply
      expect(res.status()).toBe(201)
      const id = ((await res.json()) as Tgt).id
      await toast(page, new RegExp(`Added ${value.replaceAll('.', '\\.')}\\. Next step: verify ownership\\.`))
      await expect(page).toHaveURL(`/exposure/${id}`)

      // what the box stored: an unproven domain with a token, nothing else
      const t = await target(admin, id)
      expect(t).toMatchObject({
        id, kind: 'domain', value, status: 'unverified', method: null, verified_at: null, expires_at: null, validity: null, last_check: null, commitment: null,
        scannable: false, blocked_reason: 'unverified', last_scan_at: null, latest: null,
      })
      expect(t.token).toMatch(/^[0-9a-f]{16}$/)
      const stored = JSON.stringify(t)

      // the page: heading, chips, the reason in words, the record to add, no way past step 1
      await expect(h1(page)).toHaveText(`${value} cannot be scanned yet: awaiting ownership proof`)
      await expect(page.getByText('Awaiting ownership proof').first()).toBeVisible()
      await expect(page.getByText('Not confirmed yet').first()).toBeVisible()
      await expect(page.getByText('Never scanned').first()).toBeVisible()
      const scan = page.getByRole('button', { name: 'Scan now' })
      await expect(scan).toBeDisabled()
      await expect(page.locator('#scan-reason')).toHaveText(`Cannot scan yet: ${value} has no ownership proof. Do step 1 below first.`)
      await expect(scan).toHaveAttribute('aria-describedby', 'scan-reason')
      const verify = page.locator('#step-verify')
      await expect(verify.getByText(`Add a TXT record to the DNS of ${value}.`)).toBeVisible()
      await expect(verify.getByText('TXT', { exact: true })).toBeVisible()
      await expect(verify.getByText(`@ (or ${value})`, { exact: true })).toBeVisible()
      await expect(verify.getByLabel('TXT record value')).toHaveText(`vedette-verify=${t.token}`)
      await expect(verify.getByText(/This record only proves you control the DNS\. It gives Vedette no other access\./)).toBeVisible()
      await expect(page.getByText(/reverse dns/i)).toHaveCount(0)
      await expect(page.locator('input[type="file"]')).toHaveCount(0) // no consent document to upload (D-26)
      // the Check button is there; it is not pressed: it asks real DNS (see the header)
      await expect(verify.getByRole('button', { name: 'Check', exact: true })).toBeEnabled()
      // step 2 is closed: nothing to tick before the proof
      await expect(page.locator('#step-commit').getByText('Finish step 1 first. You can confirm only after ownership is verified.')).toBeVisible()
      await expect(page.getByRole('checkbox')).toHaveCount(0)
      await expect(page.getByText('No scan results yet')).toBeVisible()
      await expectAccessible(page, 'unverified domain')
      await noVietnamese(page, 'unverified domain')
      await shot(page, 'real', 'exposure-domain-unverified')

      // it is in the list of domains, and the headline counts it
      await page.goto('/exposure')
      const fresh = await list(admin)
      await expect(h1(page)).toHaveText(headline(fresh.items))
      const row = domainTable(page).getByRole('row').filter({ has: page.getByRole('link', { name: value, exact: true }) })
      await expect(row).toContainText('Awaiting ownership proof')
      await expect(row).toContainText('Needs ownership proof')
      await expect(row).toContainText('No result yet')

      // INV-1 / FORBID-1: no scan of an unproven domain, as admin or as operator, and no commitment before the proof (INV-7)
      const noProof = `${value} has no ownership proof, so it cannot be scanned. Finish verification first.`
      for (const who of [admin, op]) expect(await api<ApiErr>(who, 'POST', `/exposure/targets/${id}/scan`)).toMatchObject(refused(409, 'not_verified', noProof))
      const noCommit = 'Verify ownership first; only then can you confirm the commitment for this target.'
      for (const confirm of [true, false]) expect(await api<ApiErr>(admin, 'POST', `/exposure/targets/${id}/commitment`, { confirm }), `confirm ${confirm}`).toMatchObject(refused(409, 'not_verified', noCommit))
      expect(await api(admin, 'GET', `/exposure/targets/${id}/snapshots`)).toMatchObject({ status: 200, body: { items: [] } })
      expect(JSON.stringify(await target(admin, id)), 'the refusals changed nothing').toBe(stored)
      // an unproven domain cannot be put on the Ignored list either (only an IP can)
      const listBefore = await snapshot(admin)
      expect(await api<ApiErr>(admin, 'DELETE', `/exposure/targets/${id}?ignore=true`)).toMatchObject(refused(400, 'bad_value', 'Only a public IP can go on the Ignored list.'))
      expect((await api(admin, 'DELETE', `/exposure/targets/${id}?ignore=maybe`)).status).toBe(400)
      expect(await snapshot(admin), 'the refused delete kept the domain and the Ignored list').toBe(listBefore)

      // the same name again, in any case, is a duplicate; the list does not grow
      expect(await api<ApiErr>(admin, 'POST', '/exposure/targets', { value: value.toUpperCase() })).toMatchObject(refused(409, 'duplicate', `${value} is already in the list.`))
      expect(await snapshot(admin)).toBe(listBefore)

      // delete: the dialog says what is lost, Cancel keeps it, Delete removes it
      await page.goto(`/exposure/${id}`)
      await page.getByRole('button', { name: 'Delete target' }).click()
      const del = page.getByRole('dialog', { name: `Delete ${value}?` })
      await expect(del).toContainText('The snapshots and your confirmation for this target are removed from the box. The audit log is kept. This cannot be undone.')
      await del.getByRole('button', { name: 'Cancel' }).click()
      await expect(page.getByRole('dialog')).toHaveCount(0)
      expect(JSON.stringify(await target(admin, id)), 'Cancel kept it').toBe(stored)
      await page.getByRole('button', { name: 'Delete target' }).click()
      const gone = page.waitForResponse((r) => r.url().endsWith(`/api/v1/exposure/targets/${id}`) && r.request().method() === 'DELETE')
      await page.getByRole('dialog', { name: `Delete ${value}?` }).getByRole('button', { name: 'Delete', exact: true }).click()
      expect((await gone).status()).toBe(204)
      await expect(page).toHaveURL('/exposure')
      await toast(page, new RegExp(`Deleted ${value.replaceAll('.', '\\.')}`))
      await expect(page.getByRole('link', { name: value, exact: true })).toHaveCount(0)
      expect(await api<ApiErr>(admin, 'GET', `/exposure/targets/${id}`)).toMatchObject(refused(404, 'not_found', 'No such target. It may have been deleted.'))
      expect(await api<ApiErr>(admin, 'GET', `/exposure/targets/${id}/snapshots`)).toMatchObject(refused(404, 'not_found', 'No such target. It may have been deleted.'))
      expect((await list(admin)).items.map((i) => i.value)).not.toContain(value)
      expect(await api<ApiErr>(admin, 'DELETE', `/exposure/targets/${id}`)).toMatchObject(refused(404, 'not_found', 'No such target. It may have been deleted.'))

      // audit: exactly the two changes, by the administrator, nothing about a scan or a commitment; the log outlives the target
      const rows = (await audit(admin, value)).filter((r) => !auditBefore.has(r.id) && r.target === value)
      expect(rows.map((r) => [r.action, r.user]).sort()).toEqual([['exposure.target_add', ACCOUNTS.admin.email], ['exposure.target_delete', ACCOUNTS.admin.email]])
      expect(server).toEqual([])
      noErrors(errors, /status of (400|404|409)/)
    } finally { await op.dispose(); await admin.dispose() }
  })

  test('the Ignored list: restoring what is not on it is refused with the exact answer and changes nothing; a restore needs a canonical IPv4', async () => {
    const admin = await as('admin')
    try {
      const before = await snapshot(admin)
      const ids = await auditIds(admin, 'exposure.ip_restore')
      const onList = new Set((await list(admin)).ignored.map((i) => i.value))
      const free = ['203.0.113.9', '198.51.100.9'].find((ip) => !onList.has(ip))! // documentation addresses: never real, never on a list unless a test put them there
      expect(free, 'a documentation address that is not on the list').toBeDefined()
      expect(await api<ApiErr>(admin, 'DELETE', `/exposure/box-ip/ignored/${free}`)).toMatchObject(refused(404, 'not_found', 'This IP is not on the Ignored list.'))
      for (const bad of ['not-an-ip', '01.2.3.4', '1.2.3', '2001:db8::1', '::ffff:1.2.3.4']) {
        expect(await api<ApiErr>(admin, 'DELETE', `/exposure/box-ip/ignored/${encodeURIComponent(bad)}`), bad).toMatchObject(refused(400, 'bad_value', 'Not a valid IPv4 address.'))
      }
      expect(await snapshot(admin)).toBe(before)
      expect([...(await auditIds(admin, 'exposure.ip_restore'))].filter((id) => !ids.has(id)), 'a refused restore is not an audit row').toEqual([])
    } finally { await admin.dispose() }
  })
})

test.describe('roles (PRE-4, PRE-1, PRE-2)', () => {
  test('a viewer and an operator see the results, every admin action is locked with its reason, and the API refuses them without saving anything', async ({ browser }) => {
    test.setTimeout(150_000)
    const value = domain()
    made.push(value)
    const admin = await as('admin')
    const contexts = [] as { close(): Promise<void> }[]
    try {
      const made1 = await api<Tgt>(admin, 'POST', '/exposure/targets', { value })
      expect(made1.status, JSON.stringify(made1.body)).toBe(201)
      const id = made1.body.id
      const d = await list(admin)
      const ips = d.items.filter((i) => i.kind === 'ip')
      const before = await snapshot(admin)
      const auditBefore = await auditIds(admin, 'exposure.')

      for (const role of ['viewer', 'operator'] as const) {
        const ctx = await browser.newContext({ storageState: authFile(role) })
        contexts.push(ctx)
        const page = await ctx.newPage()
        const errors = collectErrors(page)
        const server = watch5xx(page)
        const operator = role === 'operator'

        // the list: the results are there, every control of the administrator is locked and says why
        await page.goto('/exposure')
        await expect(h1(page)).toHaveText(headline((await list(admin)).items))
        await expect(page.getByRole('button', { name: 'Add domain' }).first()).toBeDisabled()
        await expect(page.getByRole('button', { name: 'Add domain' }).first()).toHaveAttribute('title', NEEDS_ADMIN)
        await expect(page.getByRole('switch', { name: "Detect the box's public IPs automatically" })).toBeDisabled()
        await expect(page.getByRole('button', { name: 'Detect now' })).toBeDisabled()
        await expect(page.getByRole('button', { name: 'Detect now' })).toHaveAttribute('title', NEEDS_ADMIN)
        await expect(page.locator('#box-ip').getByText(NEEDS_ADMIN, { exact: true })).toBeVisible()
        for (const t of ips) await expect(page.getByRole('button', { name: `Remove ${t.value}` })).toBeDisabled()
        for (const i of d.ignored) await expect(page.getByRole('button', { name: `Restore ${i.value}` })).toBeDisabled()
        await expect(domainTable(page).getByRole('link', { name: value, exact: true })).toBeVisible()
        if (d.box_ip.auto) await expect(page.getByRole('combobox', { name: 'Check every' })).toBeDisabled()
        await expectAccessible(page, `exposure list as ${role}`)

        // the target page
        await page.goto(`/exposure/${id}`)
        await expect(h1(page)).toHaveText(`${value} cannot be scanned yet: awaiting ownership proof`)
        await expect(page.getByRole('button', { name: 'Delete target' })).toBeDisabled()
        await expect(page.getByRole('button', { name: 'Delete target' })).toHaveAttribute('title', NEEDS_ADMIN)
        await expect(page.getByRole('button', { name: 'Scan now' })).toBeDisabled() // blocked for everyone: no proof
        await expect(page.locator('#scan-reason')).toHaveText(`Cannot scan yet: ${value} has no ownership proof. Do step 1 below first.`)
        const check = page.locator('#step-verify').getByRole('button', { name: 'Check', exact: true })
        if (operator) {
          await expect(check).toBeEnabled() // an operator may re-check ownership (not pressed: real DNS)
          await expect(page.getByText(/You have view-only access/)).toHaveCount(0)
        } else {
          await expect(check).toBeDisabled()
          await expect(check).toHaveAttribute('title', NEEDS_OPERATOR)
          await expect(page.getByText('You have view-only access. Scanning and re-checking ownership need the operator role; confirming authorization and deleting need admin.')).toBeVisible()
        }
        await noVietnamese(page, `target as ${role}`)
        expect(server).toEqual([])
        noErrors(errors)

        // the API: the same refusals, role first (403 before anything is looked at), and nothing changes
        const c = await as(role)
        try {
          const FORBIDDEN = refused(403, 'forbidden', 'Your account is not allowed to do this.')
          const admin_only: [Parameters<typeof api>[1], string, unknown?][] = [
            ['POST', '/exposure/targets', { value: domain() }],
            ['PUT', '/exposure/box-ip/settings', { auto: false, interval_min: 15 }],
            ['POST', '/exposure/box-ip/verify'],
            ['POST', `/exposure/targets/${id}/commitment`, { confirm: true }],
            ['DELETE', `/exposure/targets/${id}`],
            ['DELETE', `/exposure/targets/${id}?ignore=true`],
            ['DELETE', '/exposure/box-ip/ignored/203.0.113.9'],
          ]
          for (const [m, p, b] of admin_only) expect(await api<ApiErr>(c, m, p, b), `${role} ${m} ${p}`).toMatchObject(FORBIDDEN)
          if (!operator) for (const p of [`/exposure/targets/${id}/scan`, `/exposure/targets/${id}/verify`]) expect(await api<ApiErr>(c, 'POST', p), `viewer POST ${p}`).toMatchObject(FORBIDDEN)
        } finally { await c.dispose() }
        expect(await snapshot(admin), `${role}: nothing was saved`).toBe(before)
        expect([...(await auditIds(admin, 'exposure.'))].filter((x) => !auditBefore.has(x)), `${role}: no audit row`).toEqual([])
      }
    } finally {
      for (const c of contexts) await c.close()
      await admin.dispose()
    }
  })
})
