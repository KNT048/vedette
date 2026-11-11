// Operating system updates on the real backend through vedette-host (S-CORE-7, core INV-18/20/21, D-53, D-55). The host is the fake machine of
// cmd/vedette/e2ehost_test.go: the real host/ops commands over a temporary root, with a fake apt (two pending packages: libc6, and openssl from
// the security pocket, that an install empties), a fake apt-config and systemctl that follow the automatic-updates switch, and knobs for the
// dpkg lock, a failing install, a reboot-required flag, and the end of a reboot. The steps are those of e2e/qa/wp06-updates-os.spec.ts.
// Global project: an install or a reboot changes the box for every other spec, and the tests below depend on each other's order.
// Where the real box differs from what the GUI can show, the test is test.fail() with the issue and the deferred line (D-171), after it has
// confirmed the known symptom: a marker passes only on that symptom, any other failure is reported red (the pattern of logs-export.spec.ts).
import { existsSync, readdirSync } from 'node:fs'
import { join } from 'node:path'
import { expect, request, test, type APIRequestContext, type Page } from '@playwright/test'
import { api, authFile, box, hostKnob } from './box'
import { expectAccessible, h1, noErrors, noVietnamese, stubSoftwareUpdates } from './ui'
import { collectErrors, shot } from '../e2e/helpers'

test.use({ storageState: authFile('admin'), actionTimeout: 10_000 })
test.describe.configure({ mode: 'serial' })

interface Os {
  os: { name: string; kernel: string; last_check: string }; pending: { name: string; current: string; new: string; security: boolean }[]
  busy: boolean; auto_security: boolean; reboot_required: boolean; reboot_scheduled_at: string | null
  window: { mode: string; days: number[]; from: string; to: string }
}
interface Run { id: string; status: string; scope: string; user: string; lines: string[]; result: null | { installed: number; security: number; backup: string; health: { name: string; ok: boolean }[]; reboot_required: boolean } }

const as = (role: 'admin' | 'operator' | 'viewer') => request.newContext({ baseURL: box().base_url, storageState: authFile(role) })
const toast = (page: Page, re: RegExp) => expect(page.locator('[data-sonner-toast]').filter({ hasText: re }).first()).toBeVisible()
const osHeading = (page: Page) => page.getByRole('heading', { name: 'Operating system of this box' })
const pending = (page: Page) => page.getByRole('table', { name: 'Pending operating system updates' })
const runPanel = (page: Page) => page.locator('div[aria-live="polite"]').filter({ has: page.getByRole('heading', { name: 'Latest install run' }) })
const waitFinished = (page: Page) => expect(runPanel(page).getByText('Finished', { exact: true })).toBeVisible({ timeout: 30_000 })
const DAYS = ['Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday', 'Sunday']

/** Opens Settings -> Updates with the unbuilt software part stood in for (see stubSoftwareUpdates); the operating system part is all real. */
async function open(page: Page) {
  await stubSoftwareUpdates(page)
  await page.goto('/settings/updates')
}

async function admin<T>(fn: (c: APIRequestContext) => Promise<T>) {
  const c = await as('admin')
  try { return await fn(c) } finally { await c.dispose() }
}
const state = () => admin((c) => api<Os>(c, 'GET', '/core/updates/os'))
const lastRun = () => admin((c) => api<Run | null>(c, 'GET', '/core/updates/os/run'))
const waitRunDone = async (id?: string) => expect.poll(async () => { const r = (await lastRun()).body; return r && r.id !== id ? r.status : 'none' }, { timeout: 30_000 }).toBe('done')
/** INV-18: core removes the snapshot folder of a run or a download once the host is done with it. */
const snapshotsGone = () => expect.poll(() => { const d = join(box().data_dir, 'snapshots'); return existsSync(d) ? readdirSync(d) : [] }, { timeout: 15_000, message: 'snapshots/ in the data folder' }).toEqual([])
/** Only the known symptom may satisfy a test.fail: when it is not what the page shows, the expectation is switched off and the test is red. */
const knownSymptom = (known: boolean) => { if (!known) test.fail(false) }

let runsAtHost = 0 // installs that reached the host in this spec: each is audited at its end exactly once (os.install_done)

test.afterAll(async () => {
  await hostKnob('lock', 'off'); await hostKnob('install_fail', 'off'); await hostKnob('reboot_required', 'off')
})

test('a box that was never checked says so in words and with the right code, and no screen breaks', async ({ page }) => {
  const errors = collectErrors(page)
  const st = await admin((c) => api<{ error: { code: string; message: string } }>(c, 'GET', '/core/updates/os'))
  expect(st.status).toBe(409)
  expect(st.body.error.code).toBe('no_check_yet')
  await open(page)
  await expect(h1(page)).toBeVisible()
  await expect(page.getByRole('alert').filter({ hasText: st.body.error.message })).toBeVisible()
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
  await expect(h1(page)).toBeVisible()
  knownSymptom(await page.getByRole('alert').filter({ hasText: 'Could not load data' }).first().isVisible({ timeout: 8_000 }).catch(() => false))
  await expect(osHeading(page)).toBeVisible()
})

// test.fail (D-171) 2: on a box that was never checked the page shows only the error, and the error says "Click Check now" while the page has
// no such button. Nothing checks by itself, so on a fresh box the OS part cannot be used from the GUI even once item 1 is fixed.
// Issue: https://github.com/KNT048/vedette/issues/231, .ai/deferred/feat-core-os-updates.md:7 and :8.
test('on a box that was never checked the page offers the Check now button its message talks about', async ({ page }) => {
  test.fail(true, 'GUI gap: no_check_yet shows an error with no Check now button (issue #231, .ai/deferred/feat-core-os-updates.md:7-8)')
  await open(page)
  const said = await page.getByRole('alert').filter({ hasText: 'Click Check now.' }).first().isVisible({ timeout: 8_000 }).catch(() => false)
  knownSymptom(said && (await page.getByRole('button', { name: 'Check now' }).count()) === 0)
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
  const st = await state()
  expect(st.status).toBe(200)
  const sec = st.body.pending.filter((p) => p.security).length
  await open(page)
  await expect(osHeading(page)).toBeVisible()
  await expectAccessible(page, 'updates, OS part')
  await expect(page.getByText(st.body.os.name, { exact: true }).first()).toBeVisible()
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
  const before = st.body.os.last_check
  await page.getByRole('button', { name: 'Check now' }).click() // last_check has whole seconds: click until it moves
  await toast(page, /Checked the package mirrors\./)
  await expect.poll(async () => {
    if ((await state()).body.os.last_check === before) await page.getByRole('button', { name: 'Check now' }).click()
    return (await state()).body.os.last_check
  }, { timeout: 15_000 }).not.toBe(before)
  await noVietnamese(page, 'updates')
  noErrors(errors, /status of 4\d\d/)
})

// test.fail (D-171): the page heading is "<name>: {{count}} security updates waiting" with no plural form. Issue #240.
test('the page heading is grammatical when one security update waits', async ({ page }) => {
  test.fail(true, 'GUI: "1 security updates waiting" (issue #240, .ai/deferred/feat-e2e-real-harness.md)')
  await open(page)
  await expect(osHeading(page)).toBeVisible()
  const title = await h1(page).innerText()
  knownSymptom(/: 1 security updates waiting$/.test(title))
  expect(title).not.toMatch(/\b1 security updates\b/)
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
    await expect(page.getByRole('button', { name: 'Schedule reboot' })).toBeDisabled()
    await expect(page.getByRole('switch', { name: 'Automatic security updates' })).toBeDisabled()
    await expect(page.getByRole('button', { name: 'Save window' })).toBeDisabled()
    if (role === 'viewer') await expect(page.getByRole('button', { name: 'Check now' })).toBeDisabled()
    else await expect(page.getByRole('button', { name: 'Check now' })).toBeEnabled()
    const r = await api<{ error: { code: string } }>(c, 'POST', '/core/updates/os/install', { scope: 'all' })
    expect(r.status, role).toBe(403)
    await ctx.close()
    await c.dispose()
  }
})

test('a reboot the packages need is shown with the packages that need it, and goes away when it is no longer needed', async ({ page }) => {
  const errors = collectErrors(page)
  await hostKnob('reboot_required', 'on')
  try {
    await open(page)
    await page.getByRole('button', { name: 'Check now' }).click() // the box's answer is kept for 10 s; a check starts a new one
    await toast(page, /Checked the package mirrors\./)
    await expect(page.getByText('Reboot required', { exact: true })).toBeVisible()
    await expect(page.getByText('Needed by: libc6.')).toBeVisible()
    expect((await state()).body.reboot_required).toBe(true)
    await shot(page, 'real', 'os-reboot-required')
  } finally {
    await hostKnob('reboot_required', 'off')
  }
  await page.getByRole('button', { name: 'Check now' }).click()
  await expect(page.getByText('No reboot needed', { exact: true })).toBeVisible()
  expect((await state()).body.reboot_required).toBe(false)
  noErrors(errors, /status of 4\d\d/)
})

test('the automatic security updates switch is applied by the host and read back: off, then on, each audited', async ({ page }) => {
  const errors = collectErrors(page)
  const sw = page.getByRole('switch', { name: 'Automatic security updates' })
  await open(page)
  await expect(sw).toBeChecked()
  expect((await state()).body.auto_security).toBe(true)
  await sw.click()
  await toast(page, /Automatic security updates are off\./)
  await expect(sw).not.toBeChecked()
  await expect(page.getByText('Nothing is installed until you press a button below.')).toBeVisible()
  expect((await state()).body.auto_security, 'the host reads the setting back').toBe(false)
  await page.reload()
  await expect(sw).not.toBeChecked()
  await sw.click()
  await toast(page, /Automatic security updates are on\./)
  await expect(sw).toBeChecked()
  await expect(page.getByText('unattended-upgrades installs security updates by itself')).toBeVisible()
  expect((await state()).body.auto_security).toBe(true)
  const rows = await admin((c) => api<{ items: { action: string; user: string }[] }>(c, 'GET', '/core/audit?q=os.settings'))
  expect(rows.body.items.filter((i) => i.action === 'os.settings').length).toBeGreaterThanOrEqual(2)
  expect(rows.body.items[0].user).toBe('admin@e2e.test')
  noErrors(errors, /status of 4\d\d/)
})

test('the maintenance window is checked on the page, saved, and a reboot is scheduled in it and cancelled', async ({ page }) => {
  test.setTimeout(90_000)
  const errors = collectErrors(page)
  await open(page)
  const mode = page.getByRole('group', { name: 'Window mode' })
  await mode.getByRole('button', { name: 'Only in a window' }).click()
  for (const d of DAYS) await page.getByRole('checkbox', { name: d, exact: true }).uncheck()
  await expect(page.getByText('Pick at least one day.')).toBeVisible()
  await expect(page.getByRole('button', { name: 'Save window' })).toBeDisabled()
  for (const d of DAYS) await page.getByRole('checkbox', { name: d, exact: true }).check()
  await page.locator('#win-from').fill('03:00')
  await page.locator('#win-to').fill('03:00')
  await expect(page.getByText('The start and the end are the same, so the window is empty.')).toBeVisible()
  await expect(page.getByRole('button', { name: 'Save window' })).toBeDisabled()
  await page.locator('#win-from').fill('02:00')
  await page.locator('#win-to').fill('05:00')
  await page.getByRole('button', { name: 'Save window' }).click()
  await toast(page, /Maintenance window saved\./)
  const saved = (await state()).body.window
  expect(saved).toEqual({ mode: 'window', days: [1, 2, 3, 4, 5, 6, 7], from: '02:00', to: '05:00' })
  await expect(page.getByText('Mon, Tue, Wed, Thu, Fri, Sat, Sun, 02:00 to 05:00')).toBeVisible()
  await shot(page, 'real', 'os-window')

  await page.getByRole('button', { name: 'Schedule reboot' }).click()
  const dlg = page.getByRole('dialog', { name: 'Schedule a reboot' })
  await expect(dlg).toContainText('Maintenance window: Mon, Tue, Wed, Thu, Fri, Sat, Sun 02:00 to 05:00.')
  await dlg.getByRole('radio', { name: 'At the start of the next maintenance window' }).click()
  await dlg.getByRole('button', { name: 'Schedule reboot' }).click()
  await toast(page, /Reboot scheduled\./)
  await expect(page.getByText(/Reboot scheduled for /)).toBeVisible()
  const at = (await state()).body.reboot_scheduled_at
  expect(at, 'the host holds the schedule').toMatch(/^\d{4}-\d\d-\d\dT/)
  expect(new Date(at!).getTime()).toBeGreaterThan(Date.now())
  await shot(page, 'real', 'os-reboot-scheduled')
  await page.getByRole('button', { name: 'Cancel reboot' }).click()
  await toast(page, /Scheduled reboot cancelled\./)
  await expect(page.getByText(/Reboot scheduled for /)).toHaveCount(0)
  expect((await state()).body.reboot_scheduled_at).toBeNull()

  await mode.getByRole('button', { name: 'Any time' }).click() // put it back
  await page.getByRole('button', { name: 'Save window' }).click()
  await toast(page, /Maintenance window saved\./)
  expect((await state()).body.window.mode).toBe('always')
  noErrors(errors, /status of 4\d\d/)
})

test('an install while another package manager holds the dpkg lock is refused in words and starts nothing', async ({ page }) => {
  const errors = collectErrors(page)
  const runsBefore = await lastRun()
  await hostKnob('lock', 'on')
  try {
    await open(page)
    await expect(pending(page).locator('tbody tr')).toHaveCount(2)
    await page.getByRole('button', { name: /Install security updates/ }).click()
    await toast(page, /Another package manager is running on the box/)
    await shot(page, 'real', 'os-dpkg-locked')
    const after = await lastRun()
    expect(after.body?.id ?? null, 'no run was started').toBe(runsBefore.body?.id ?? null)
    expect((await state()).body.busy).toBe(false)
    await snapshotsGone()
  } finally {
    await hostKnob('lock', 'off')
  }
  noErrors(errors, /status of 4\d\d/)
})

// What the page showed for the failed install, for the test.fail that follows (one run, not two).
const failedShown = { successToast: false, finishedChip: false, inWords: false }

test('an install that apt refuses is a run whose lines say why, with nothing installed, and the box is not left busy', async ({ page }) => {
  const errors = collectErrors(page)
  const before = (await lastRun()).body?.id
  await hostKnob('install_fail', 'on')
  try {
    await open(page)
    await page.getByRole('button', { name: /Install security updates/ }).click()
    await toast(page, /Install started/)
    await waitRunDone(before)
    runsAtHost++
    const panel = runPanel(page)
    await expect(panel.getByRole('log', { name: 'apt output' })).toContainText('failed: apt_failed')
    failedShown.finishedChip = await panel.getByText('Finished', { exact: true }).isVisible()
    failedShown.successToast = await page.locator('[data-sonner-toast]').filter({ hasText: 'Finished: 0 packages installed.' }).first().isVisible()
    failedShown.inWords = await panel.getByText(/install (did not finish|failed)/i).first().isVisible()
    await shot(page, 'real', 'os-install-failed')
    const run = (await lastRun()).body!
    expect(run).toMatchObject({ status: 'done', scope: 'security', user: 'admin@e2e.test' })
    expect(run.lines.join('\n')).toContain('failed: apt_failed')
    expect(run.result?.installed).toBe(0)
    await expect.poll(async () => (await state()).body.busy).toBe(false)
    expect((await state()).body.pending).toHaveLength(2) // nothing was installed
    await snapshotsGone()
  } finally {
    await hostKnob('install_fail', 'off')
  }
  noErrors(errors, /status of 4\d\d/)
})

// test.fail (D-171): OsRun has no failed state, so a run apt refused is a green "Finished" with the success toast "Finished: 0 packages
// installed." and a raw log line. Issue #238.
test('a failed install is told in words, not shown as a finished success', async () => {
  test.fail(true, 'GUI/contract: a failed install looks like a success (issue #238, .ai/deferred/feat-e2e-real-harness.md)')
  knownSymptom(failedShown.successToast && failedShown.finishedChip)
  expect(failedShown.successToast, 'the success toast after a failed install').toBe(false)
  expect(failedShown.inWords, 'the panel says in words that the install failed').toBe(true)
})

test('install security updates: progress, result, health and the backup before it; the snapshot is gone after (INV-18)', async ({ page }) => {
  test.setTimeout(90_000)
  const errors = collectErrors(page)
  const before = (await lastRun()).body?.id
  await open(page)
  await page.getByRole('button', { name: /Install security updates/ }).click()
  await toast(page, /Install started\./)
  await expect(page.getByRole('heading', { name: 'Latest install run' })).toBeVisible()
  await waitFinished(page)
  await waitRunDone(before)
  runsAtHost++
  const run = (await lastRun()).body!
  expect(run).toMatchObject({ status: 'done', scope: 'security', user: 'admin@e2e.test' })
  expect(run.result?.backup, 'the backup taken before the run').toMatch(/\S/)
  expect(run.result?.health).toEqual([{ name: 'vedette-core', ok: true }])
  expect(run.result!.installed).toBeGreaterThan(0)
  const panel = runPanel(page)
  await expect(panel).toContainText('Security updates')
  await expect(panel).toContainText('admin@e2e.test')
  await expect(panel).toContainText(`${run.result!.installed} packages, ${run.result!.security} security`)
  await expect(panel.getByRole('log', { name: 'apt output' })).toContainText('Installing')
  await expect(panel.getByText('vedette-core')).toBeVisible()
  await expect(panel.getByText(/failed/)).toHaveCount(0)
  await shot(page, 'real', 'os-install-security-done')
  await snapshotsGone()
  noErrors(errors, /status of 4\d\d/)
})

test('install all: the confirm says a backup comes first, progress shows, the result lists what was installed, and the list is empty after', async ({ page }) => {
  test.setTimeout(90_000)
  const errors = collectErrors(page)
  await hostKnob('updates', 'reset') // the packages are pending again
  await open(page)
  await page.getByRole('button', { name: 'Check now' }).click()
  await expect(pending(page).locator('tbody tr')).toHaveCount(2)
  const before = (await lastRun()).body?.id
  await page.getByRole('button', { name: 'Install all updates' }).click()
  const dlg = page.getByRole('dialog', { name: 'Install all 2 updates?' })
  await expect(dlg).toContainText('A database backup is taken first.')
  await shot(page, 'real', 'os-install-confirm')
  await dlg.getByRole('button', { name: 'Cancel' }).click()
  await expect(page.getByRole('dialog')).toHaveCount(0)
  expect((await lastRun()).body?.id, 'Cancel started nothing').toBe(before)
  await page.getByRole('button', { name: 'Install all updates' }).click()
  await dlg.getByRole('button', { name: 'Install all', exact: true }).click()
  await toast(page, /Install started/)
  await expect(page.getByRole('heading', { name: 'Latest install run' })).toBeVisible()
  await waitFinished(page)
  await waitRunDone(before)
  runsAtHost++
  const panel = runPanel(page)
  await expect(panel).toContainText('All updates')
  await expect(panel).toContainText('admin@e2e.test')
  await expect(panel).toContainText('2 packages, 1 security')
  await expect(panel.getByRole('log', { name: 'apt output' })).toContainText('Installing 2 packages')
  await expect(panel.getByText('vedette-core')).toBeVisible() // the health chip
  await expect(panel.getByText(/failed/)).toHaveCount(0)
  await shot(page, 'real', 'os-install-done')
  const run = (await lastRun()).body!
  expect(run.status).toBe('done')
  expect(run.result).toMatchObject({ installed: 2, security: 1 })
  expect(run.result?.backup, 'the backup taken before the run').toMatch(/\S/)
  expect(run.result?.health).toEqual([{ name: 'vedette-core', ok: true }])
  await snapshotsGone()
  // what the install left: no package waits, and the audit says who did it
  await page.reload()
  await expect(page.getByText('Nothing waiting. The operating system is up to date.')).toBeVisible()
  await expect(page.getByRole('heading', { name: '0 updates waiting, 0 of them security' })).toBeVisible()
  const rows = await admin((c) => api<{ items: { action: string; user: string }[] }>(c, 'GET', '/core/audit?q=os.install'))
  const actions = rows.body.items.map((i) => i.action)
  // every run that reached the host is audited at its end exactly once; the attempt the dpkg lock refused never became a run
  expect(actions.filter((a) => a === 'os.install_done')).toHaveLength(runsAtHost)
  expect(actions.filter((a) => a === 'os.install').length).toBeGreaterThanOrEqual(runsAtHost)
  expect(rows.body.items.find((i) => i.action === 'os.install')?.user).toBe('admin@e2e.test')
  noErrors(errors, /status of 4\d\d/)
})

test('a second install has nothing to do and the API says so', async () => {
  const r = await admin((c) => api<{ error: { code: string } }>(c, 'POST', '/core/updates/os/install', { scope: 'all' }))
  expect(r.status).toBe(409)
  expect(r.body.error.code).toBe('nothing_to_install')
})

test('Reboot now asks first, then the host reboots (the last test: the host takes no writes until the box is back)', async ({ page }) => {
  const errors = collectErrors(page)
  await open(page)
  await page.getByRole('button', { name: 'Reboot now' }).click()
  const dlg = page.getByRole('dialog', { name: 'Reboot the box now?' })
  await expect(dlg).toContainText('offline for a minute or two')
  await shot(page, 'real', 'os-reboot-now')
  await dlg.getByRole('button', { name: 'Cancel' }).click()
  await expect(page.getByRole('dialog')).toHaveCount(0)
  let rows = await admin((c) => api<{ items: { action: string }[] }>(c, 'GET', '/core/audit?q=os.reboot'))
  expect(rows.body.items.filter((i) => i.action === 'os.reboot'), 'Cancel rebooted nothing').toHaveLength(0)
  await page.getByRole('button', { name: 'Reboot now' }).click()
  try {
    await dlg.getByRole('button', { name: 'Reboot now' }).click()
    await toast(page, /Reboot started\./)
    rows = await admin((c) => api<{ items: { action: string; user: string }[] }>(c, 'GET', '/core/audit?q=os.reboot'))
    expect(rows.body.items.find((i) => i.action === 'os.reboot')?.user).toBe('admin@e2e.test')
  } finally {
    await hostKnob('boot', 'aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee') // the box is back: a new boot id
  }
  noErrors(errors, /status of 4\d\d/)
})
