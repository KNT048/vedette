// Reports -> weekly report, "Send now" on the real backend (S-REP-1, reports INV-4, INV-10, PRE-1, POST-1): the report goes through the email channel to the saved
// recipients, and every attempt is in the history. The mail goes to the box's own fake SMTP sink (box.ts: mailbox), no internet. Global project: the reports module,
// the schedule and the email channel are box-wide. The module and the schedule are put back at the end; the email channel stays saved to the sink, as every spec that needs it leaves it.
import { expect, test, type APIRequestContext } from '@playwright/test'
import { ACCOUNTS, api, authFile, ensureEmailChannel, mailbox } from './box'
import { as } from './findings-seed'
import { expectAccessible, h1, noErrors, noVietnamese } from './ui'
import { collectErrors, shot } from '../e2e/helpers'

test.use({ storageState: authFile('admin'), actionTimeout: 10_000 })
test.describe.configure({ mode: 'serial' })

interface Sched { enabled: boolean; day: number; hour: number; recipients: string[]; next_run: string | null }
interface Hist { id: string; trigger: string; recipients: string[]; status: string; error?: string }
const NOT_READY = 'The email channel is not ready, so nothing was sent. Check Settings, Alert channels, then send again.'
const TO = ['ops@e2e.test', 'boss@e2e.test']

let admin: APIRequestContext
let wasOn = false
let original: Sched
const history = async () => (await api<{ items: Hist[] }>(admin, 'GET', '/reports/weekly/history')).body.items
const audits = async () => (await api<{ items: { action: string; target: string; detail?: string }[] }>(admin, 'GET', '/core/audit?q=report.send')).body.items.filter((a) => a.action === 'report.send')
const putSchedule = (s: Omit<Sched, 'next_run'>) => api(admin, 'PUT', '/reports/schedule', s)

test.beforeAll(async () => {
  admin = await as('admin')
  const mods = await api<{ modules: { id: string; enabled: boolean }[] }>(admin, 'GET', '/modules')
  wasOn = !!mods.body.modules.find((m) => m.id === 'reports')?.enabled
  if (!wasOn) {
    const on = await api(admin, 'PATCH', '/modules/reports', { enabled: true, with_dependencies: true })
    expect(on.status, `enable reports: ${JSON.stringify(on.body)}`).toBe(200)
  }
  const s = await api<Sched>(admin, 'GET', '/reports/schedule')
  expect(s.status).toBe(200)
  original = s.body
})
test.afterAll(async () => {
  try {
    if (original) expect((await putSchedule({ enabled: original.enabled, day: original.day, hour: original.hour, recipients: original.recipients })).status, 'the schedule is back').toBe(200)
    if (!wasOn) expect((await api(admin, 'PATCH', '/modules/reports', { enabled: false })).status, 'reports is back off').toBe(200)
  } finally { await admin.dispose() }
})

test('no recipient and no email channel: the box refuses, says why, and writes no history row (PRE-1)', async () => {
  expect((await putSchedule({ enabled: false, day: 1, hour: 8, recipients: [] })).status).toBe(200)
  const before = (await history()).length
  const none = await api<{ error: { code: string } }>(admin, 'POST', '/reports/weekly/send')
  expect(none, 'no recipient').toMatchObject({ status: 400, body: { error: { code: 'no_recipients' } } })
  expect((await putSchedule({ enabled: false, day: 1, hour: 8, recipients: TO })).status).toBe(200)
  await ensureEmailChannel(admin)
  expect((await api(admin, 'DELETE', '/notify/channels/email')).status, 'the email channel is removed').toBe(204)
  const noMail = await api<{ error: { code: string; message: string } }>(admin, 'POST', '/reports/weekly/send')
  expect(noMail, 'no email channel').toMatchObject({ status: 409, body: { error: { code: 'email_not_ready', message: NOT_READY } } })
  expect((await history()).length, 'a refused send is not in the history').toBe(before)
})

test('the schedule form: add and remove recipients, a wrong email is refused with the reason, save is stored and audited (INV-10)', async ({ page }) => {
  const errors = collectErrors(page)
  expect((await putSchedule({ enabled: false, day: 1, hour: 8, recipients: [] })).status).toBe(200)
  await page.goto('/reports')
  await expect(h1(page)).toBeVisible()
  const box = page.getByLabel('Recipients', { exact: true })
  await box.fill('not-an-email')
  await page.getByRole('button', { name: 'Add', exact: true }).click()
  await expect(page.getByText('The email is not valid. Use the form name@company.com.')).toBeVisible()
  for (const e of TO) { await box.fill(e); await box.press('Enter') }
  await box.fill(TO[0]!)
  await page.getByRole('button', { name: 'Add', exact: true }).click()
  await expect(page.getByText('This email is already in the list.')).toBeVisible()
  await box.fill('')
  await page.getByRole('button', { name: 'Remove boss@e2e.test' }).click()
  await box.fill(TO[1]!); await box.press('Enter')
  const list = page.getByRole('list', { name: 'Recipient list' })
  await expect(list.getByRole('listitem')).toHaveCount(2)
  await expectAccessible(page, 'reports weekly schedule')
  await page.getByRole('button', { name: 'Save', exact: true }).click()
  await expect(page.locator('[data-sonner-toast]').filter({ hasText: 'Schedule saved' }).first()).toBeVisible()
  expect((await api<Sched>(admin, 'GET', '/reports/schedule')).body.recipients, 'stored on the box').toEqual(TO)
  const a = (await api<{ items: { action: string }[] }>(admin, 'GET', '/core/audit?q=report.schedule')).body.items
  expect(a.some((x) => x.action === 'report.schedule'), 'the audit log holds the save').toBe(true)
  noErrors(errors)
})

test('Send now with the email channel off: the dialog shows the box\'s reason, nothing is mailed, no history row', async ({ page }) => {
  const errors = collectErrors(page)
  const sent0 = (await mailbox()).length
  const rows0 = (await history()).length
  await page.goto('/reports')
  await page.getByRole('button', { name: 'Send now' }).click()
  const dlg = page.getByRole('dialog', { name: 'Send the weekly report now?' })
  await expect(dlg).toContainText('The report will be sent to the 2 recipients below.')
  for (const e of TO) await expect(dlg.getByText(e)).toBeVisible()
  await dlg.getByRole('button', { name: 'Send', exact: true }).click()
  await expect(dlg.getByRole('alert')).toHaveText(NOT_READY)
  await expect(dlg, 'the dialog stays open so the person can read it').toBeVisible()
  expect((await mailbox()).length, 'nothing was mailed').toBe(sent0)
  expect((await history()).length, 'no history row').toBe(rows0)
  await dlg.getByRole('button', { name: 'Cancel' }).click()
  noErrors(errors, /status of 409/)
})

test('Send now through the email channel: the sink gets the digest for both recipients, the history and the audit log record it (POST-1, INV-4, INV-10)', async ({ page }) => {
  const errors = collectErrors(page)
  await ensureEmailChannel(admin)
  const sent0 = (await mailbox()).length
  const rows0 = await history()
  const audit0 = (await audits()).length
  await page.goto('/reports')
  await page.getByRole('button', { name: 'Send now' }).click()
  const dlg = page.getByRole('dialog', { name: 'Send the weekly report now?' })
  await expect(dlg.getByText('The content leaves through the email channel you configured, not through any Vedette server.')).toBeVisible()
  await shot(page, 'real', 'reports-send-confirm')
  await dlg.getByRole('button', { name: 'Send', exact: true }).click()
  await expect(page.locator('[data-sonner-toast]').filter({ hasText: 'Weekly report sent' }).first()).toBeVisible()
  await expect(dlg).toBeHidden()

  const fresh = (await mailbox()).slice(sent0)
  expect(fresh.length, 'one message reached the sink').toBeGreaterThan(0)
  const text = fresh.join('\n').toLowerCase()
  expect(text, 'the subject names the weekly report').toContain('weekly report')
  for (const e of TO) expect(text, `the mail is addressed to ${e}`).toContain(e)
  expect(text, 'the mail links back to the box, not to the content').toContain('/reports')

  const rows = await history()
  expect(rows.length, 'one new history row').toBe(rows0.length + 1)
  const row = rows.find((r) => !rows0.some((o) => o.id === r.id))!
  expect(row).toMatchObject({ trigger: 'manual', status: 'sent', recipients: TO })
  const table = page.getByRole('table', { name: 'History of weekly reports sent' })
  await expect(table.getByRole('row').nth(1)).toContainText('Manual')
  await expect(table.getByRole('row').nth(1)).toContainText('2 people')
  await expect(table.getByRole('row').nth(1)).toContainText('Sent')
  await expect(table.getByRole('link', { name: 'View and print' }).first()).toHaveAttribute('href', `/reports/print/weekly/${row.id}`)
  const a = await audits()
  expect(a.length, 'one audit row').toBe(audit0 + 1)
  expect(a[0]!.detail ?? '', 'who and how many, not the addresses').toContain('manual, sent, 2 recipients')
  await noVietnamese(page, 'reports')
  noErrors(errors)
})

test('roles: an operator can send, a viewer cannot (the button is locked and the API answers 403)', async ({ browser }) => {
  const op = await browser.newContext({ storageState: authFile('operator') })
  const vw = await browser.newContext({ storageState: authFile('viewer') })
  try {
    const sent0 = (await mailbox()).length
    const o = await op.newPage()
    await o.goto('/reports')
    await o.getByRole('button', { name: 'Send now' }).click()
    await o.getByRole('dialog').getByRole('button', { name: 'Send', exact: true }).click()
    await expect(o.locator('[data-sonner-toast]').filter({ hasText: 'Weekly report sent' }).first()).toBeVisible()
    expect((await mailbox()).length, 'the operator\'s send was mailed').toBeGreaterThan(sent0)
    const v = await vw.newPage()
    await v.goto('/reports')
    await expect(v.getByRole('button', { name: 'Send now' })).toBeDisabled()
    const sent1 = (await mailbox()).length
    const r = await api(vw.request, 'POST', '/reports/weekly/send')
    expect(r.status, `viewer ${ACCOUNTS.viewer.email} POST /reports/weekly/send`).toBe(403)
    expect((await mailbox()).length, 'nothing mailed for the viewer').toBe(sent1)
  } finally { await op.close(); await vw.close() }
})
