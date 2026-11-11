// Operating system updates on the real backend through vedette-host (S-CORE-7, core INV-20/INV-21, D-53, D-55). The host is the fake machine of
// cmd/vedette/e2ehost_test.go: the real host/ops commands over a temporary root, with a fake apt. One list of two pending packages
// (libc6, and openssl from the security pocket) that an install empties. The steps are those of
// e2e/qa/wp06-updates-os.spec.ts. Global project: an install changes the box for every other spec, and the tests below depend on each
// other's order (never checked -> checked -> refused install -> failed install -> good install).
// Where the backend answers something the GUI has no screen for (a never-checked box) the test is test.fail() with the issue and the
// deferred line (D-171): it turns red when the GUI learns the state.
import { expect, request, test, type APIRequestContext, type Page } from '@playwright/test'
import { api, authFile, box, hostKnob } from './box'
import { expectAccessible, h1, noErrors, noVietnamese, stubSoftwareUpdates } from './ui'
import { collectErrors, shot } from '../e2e/helpers'

test.use({ storageState: authFile('admin'), actionTimeout: 10_000 })
test.describe.configure({ mode: 'serial' })

interface Os { os: { name: string; kernel: string; last_check: string }; pending: { name: string; current: string; new: string; security: boolean }[]; busy: boolean; auto_security: boolean; reboot_required: boolean }
interface Run { id: string; status: string; scope: string; user: string; lines: string[]; result: null | { installed: number; security: number; backup: string; health: { name: string; ok: boolean }[]; reboot_required: boolean } }

const as = (role: 'admin' | 'operator' | 'viewer') => request.newContext({ baseURL: box().base_url, storageState: authFile(role) })
const toast = (page: Page, re: RegExp) => expect(page.locator('[data-sonner-toast]').filter({ hasText: re }).first()).toBeVisible()
const osHeading = (page: Page) => page.getByRole('heading', { name: 'Operating system of this box' })
const pending = (page: Page) => page.getByRole('table', { name: 'Pending operating system updates' })
const runPanel = (page: Page) => page.locator('div[aria-live="polite"]').filter({ has: page.getByRole('heading', { name: 'Latest install run' }) })
const waitFinished = (page: Page) => expect(runPanel(page).getByText('Finished', { exact: true })).toBeVisible({ timeout: 30_000 })

/** Opens Settings -> Updates with the unbuilt software part stood in for (see stubSoftwareUpdates); the operating system part is all real. */
async function open(page: Page) {
  await stubSoftwareUpdates(page)
  await page.goto('/settings/updates')
}

async function admin<T>(fn: (c: APIRequestContext) => Promise<T>) {
  const c = await as('admin')
  try { return await fn(c) } finally { await c.dispose() }
}

test.afterAll(async () => { await hostKnob('lock', 'off'); await hostKnob('install_fail', 'off') })

test('a box that was never checked says so in words and with the right code, and no screen breaks', async ({ page }) => {
  const errors = collectErrors(page)
  const state = await admin((c) => api<{ error: { code: string; message: string } }>(c, 'GET', '/core/updates/os'))
  expect(state.status).toBe(409)
  expect(state.body.error.code).toBe('no_check_yet')
  await open(page)
  await expect(h1(page)).toBeVisible()
  await expect(page.getByRole('alert').filter({ hasText: state.body.error.message })).toBeVisible()
  await shot(page, 'real', 'os-never-checked')
  await noVietnamese(page, 'updates before the first check')
  noErrors(errors, /status of 4\d\d/)
})

// test.fail (D-171) 1: the operating system part of Settings -> Updates is drawn only after GET /core/updates (software updates) answers, and that
// answers 501 (unbuilt, .ai/deferred/feat-core-os-updates.md:3). On the real box, with nothing stood in, the page is "Could not load data"
// and the whole of S-CORE-7 is out of reach. Issue: https://github.com/KNT048/vedette/issues/230.
test('without any stand-in, Settings -> Updates draws the operating system part', async ({ page }) => {
  test.fail(true, 'GUI gap: the OS part waits for GET /core/updates, which answers 501 (issue #230, .ai/deferred/feat-core-os-updates.md:3)')
  await page.goto('/settings/updates')
  await expect(osHeading(page)).toBeVisible()
})

// test.fail (D-171) 2: on a box that was never checked the page shows only the error, and the error says "Click Check now" while the page has
// no such button. Nothing checks by itself, so on a fresh box the OS part cannot be used from the GUI even once item 1 is fixed.
// Issue: https://github.com/KNT048/vedette/issues/231, .ai/deferred/feat-core-os-updates.md:7 and :8.
test('on a box that was never checked the page offers the Check now button its message talks about', async ({ page }) => {
  test.fail(true, 'GUI gap: no_check_yet shows an error with no Check now button (issue #231, .ai/deferred/feat-core-os-updates.md:7-8)')
  await open(page)
  await expect(osHeading(page)).toBeVisible()
  await expect(page.getByRole('button', { name: 'Check now' })).toBeVisible()
})

test('the first check is made by an operator (the API: the GUI has no way to it yet), a viewer may not', async () => {
  const viewer = await as('viewer')
  const refused = await api<{ error: { code: string } }>(viewer, 'POST', '/core/updates/os/check')
  expect(refused.status).toBe(403)
  await viewer.dispose()
  const operator = await as('operator')
  const r = await api<Os>(operator, 'POST', '/core/updates/os/check')
  expect(r.status, JSON.stringify(r.body)).toBe(200)
  expect(r.body.pending.map((p) => [p.name, p.security])).toEqual([['libc6', false], ['openssl', true]]) // the kernel is a new package, not an upgrade: apt-get -s dist-upgrade lists it under NEW
  await operator.dispose()
})

test('the page shows the system, the two pending packages with their security flag, and Check now checks again', async ({ page }) => {
  const errors = collectErrors(page)
  const st = await admin((c) => api<Os>(c, 'GET', '/core/updates/os'))
  expect(st.status).toBe(200)
  const sec = st.body.pending.filter((p) => p.security).length
  await open(page)
  await expect(osHeading(page)).toBeVisible()
  await expectAccessible(page, 'updates, OS part')
  await expect(page.getByText(st.body.os.name, { exact: true })).toBeVisible()
  await expect(page.getByText(st.body.os.kernel, { exact: true })).toBeVisible()
  await expect(page.getByRole('heading', { name: `${st.body.pending.length} updates waiting, ${sec} of them security` })).toBeVisible()
  await expect(pending(page).locator('tbody tr')).toHaveCount(2)
  for (const p of st.body.pending) {
    const row = pending(page).getByRole('row').filter({ has: page.getByRole('cell', { name: p.name, exact: true }) })
    await expect(row, p.name).toHaveCount(1)
    await expect(row).toContainText(p.new)
    await expect(row.getByRole('cell').nth(3), `${p.name}: security column`).toHaveText(p.security ? 'Yes' : 'No')
  }
  const text = await page.locator('main').innerText()
  expect(text, 'the helper is named vedette-host (D-55)').toMatch(/vedette-host/)
  expect(text).not.toMatch(/vedette-updater|\bupdater\b/i)
  await expect(page.getByText('Supported', { exact: true })).toBeVisible()
  await shot(page, 'real', 'os-checked')
  const before = (await admin((c) => api<Os>(c, 'GET', '/core/updates/os'))).body.os.last_check
  await new Promise((ok) => setTimeout(ok, 1100)) // last_check has whole seconds
  await page.getByRole('button', { name: 'Check now' }).click()
  await toast(page, /Checked the package mirrors\./)
  await expect.poll(async () => (await admin((c) => api<Os>(c, 'GET', '/core/updates/os'))).body.os.last_check).not.toBe(before)
  await noVietnamese(page, 'updates')
  noErrors(errors, /status of 4\d\d/)
})

test('a viewer sees the list and cannot install or reboot; an operator can check but not install', async ({ browser }) => {
  for (const role of ['viewer', 'operator'] as const) {
    const c = await as(role)
    const ctx = await browser.newContext({ baseURL: box().base_url, storageState: await c.storageState(), locale: 'vi-VN', timezoneId: 'Asia/Ho_Chi_Minh' })
    const page = await ctx.newPage()
    await open(page)
    await expect(pending(page).locator('tbody tr')).toHaveCount(2)
    await expect(page.getByRole('button', { name: /Install security updates/ })).toBeDisabled()
    await expect(page.getByRole('button', { name: 'Install all updates' })).toBeDisabled()
    await expect(page.getByRole('button', { name: 'Reboot now' })).toBeDisabled()
    if (role === 'viewer') await expect(page.getByRole('button', { name: 'Check now' })).toBeDisabled()
    else await expect(page.getByRole('button', { name: 'Check now' })).toBeEnabled()
    const r = await api<{ error: { code: string } }>(c, 'POST', '/core/updates/os/install', { scope: 'all' })
    expect(r.status, role).toBe(403)
    await ctx.close()
    await c.dispose()
  }
})

test('an install while another package manager holds the dpkg lock is refused in words and starts nothing', async ({ page }) => {
  const errors = collectErrors(page)
  const runsBefore = await admin((c) => api<Run | null>(c, 'GET', '/core/updates/os/run'))
  await hostKnob('lock', 'on')
  try {
    await open(page)
    await expect(pending(page).locator('tbody tr')).toHaveCount(2)
    await page.getByRole('button', { name: /Install security updates/ }).click()
    await toast(page, /Another package manager is running on the box/)
    await shot(page, 'real', 'os-dpkg-locked')
    const after = await admin((c) => api<Run | null>(c, 'GET', '/core/updates/os/run'))
    expect(after.body?.id ?? null, 'no run was started').toBe(runsBefore.body?.id ?? null)
    expect((await admin((c) => api<Os>(c, 'GET', '/core/updates/os'))).body.busy).toBe(false)
  } finally {
    await hostKnob('lock', 'off')
  }
  noErrors(errors, /status of 4\d\d/)
})

test('an install that apt refuses ends as a finished run whose lines say why, with nothing installed', async ({ page }) => {
  const errors = collectErrors(page)
  await hostKnob('install_fail', 'on')
  try {
    await open(page)
    await page.getByRole('button', { name: /Install security updates/ }).click()
    await toast(page, /Install started/)
    await expect(page.getByRole('heading', { name: 'Latest install run' })).toBeVisible()
    await waitFinished(page)
    const panel = runPanel(page)
    await expect(panel.getByRole('log', { name: 'apt output' })).toContainText('failed: apt_failed')
    await expect(panel).toContainText('0 packages, 0 security')
    await shot(page, 'real', 'os-install-failed')
    const run = (await admin((c) => api<Run>(c, 'GET', '/core/updates/os/run'))).body
    expect(run).toMatchObject({ status: 'done', scope: 'security', user: 'admin@e2e.test' })
    expect(run.result?.installed).toBe(0)
    // the list is the same: nothing was installed, and the page is not stuck busy
    await expect.poll(async () => (await admin((c) => api<Os>(c, 'GET', '/core/updates/os'))).body.busy).toBe(false)
    expect((await admin((c) => api<Os>(c, 'GET', '/core/updates/os'))).body.pending).toHaveLength(2)
  } finally {
    await hostKnob('install_fail', 'off')
  }
  noErrors(errors, /status of 4\d\d/)
})

test('install all: the confirm says a backup comes first, progress shows, the result lists what was installed, and the list is empty after', async ({ page }) => {
  test.setTimeout(90_000)
  const errors = collectErrors(page)
  await open(page)
  await page.getByRole('button', { name: 'Install all updates' }).click()
  const dlg = page.getByRole('dialog', { name: 'Install all 2 updates?' })
  await expect(dlg).toContainText('A database backup is taken first.')
  await shot(page, 'real', 'os-install-confirm')
  await dlg.getByRole('button', { name: 'Cancel' }).click()
  await expect(page.getByRole('dialog')).toHaveCount(0)
  expect((await admin((c) => api<Run>(c, 'GET', '/core/updates/os/run'))).body.scope, 'Cancel started nothing').toBe('security')
  await page.getByRole('button', { name: 'Install all updates' }).click()
  await dlg.getByRole('button', { name: 'Install all', exact: true }).click()
  await toast(page, /Install started/)
  await expect(page.getByRole('heading', { name: 'Latest install run' })).toBeVisible()
  await waitFinished(page)
  const panel = runPanel(page)
  await expect(panel).toContainText('All updates')
  await expect(panel).toContainText('admin@e2e.test')
  await expect(panel).toContainText('2 packages, 1 security')
  await expect(panel.getByRole('log', { name: 'apt output' })).toContainText('Installing 2 packages')
  await expect(panel.getByText('vedette-core')).toBeVisible() // the health chip
  await expect(panel.getByText(/failed/)).toHaveCount(0)
  await shot(page, 'real', 'os-install-done')
  const run = (await admin((c) => api<Run>(c, 'GET', '/core/updates/os/run'))).body
  expect(run.status).toBe('done')
  expect(run.result).toMatchObject({ installed: 2, security: 1 })
  expect(run.result?.backup, 'the backup taken before the run').toMatch(/\S/)
  expect(run.result?.health).toEqual([{ name: 'vedette-core', ok: true }])
  // what the install left: no package waits, and the audit says who did it, twice (start and end), the end once
  await page.reload()
  await expect(page.getByText('Nothing waiting. The operating system is up to date.')).toBeVisible()
  await expect(page.getByRole('heading', { name: '0 updates waiting, 0 of them security' })).toBeVisible()
  const rows = await admin((c) => api<{ items: { action: string; user: string }[] }>(c, 'GET', '/core/audit?q=os.install'))
  const actions = rows.body.items.map((i) => i.action)
  // two runs reached the host in this spec (the one apt refused, then this one), each audited at its end exactly once; the refused-by-lock
  // attempt never became a run
  expect(actions.filter((a) => a === 'os.install_done')).toHaveLength(2)
  expect(actions.filter((a) => a === 'os.install').length).toBeGreaterThanOrEqual(2)
  expect(rows.body.items.find((i) => i.action === 'os.install')?.user).toBe('admin@e2e.test')
  noErrors(errors, /status of 4\d\d/)
})

test('a second install has nothing to do and the API says so', async () => {
  const r = await admin((c) => api<{ error: { code: string } }>(c, 'POST', '/core/updates/os/install', { scope: 'all' }))
  expect(r.status).toBe(409)
  expect(r.body.error.code).toBe('nothing_to_install')
})
