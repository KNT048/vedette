// "Report a problem" on the real box (S-CORE-5, D-42): the box sends nothing itself. The dialog shows the text that would be sent (the filled-in
// GitHub issue and the diagnostic bundle, with emails and IP addresses removed) so the person can copy it, download it, or open GitHub in
// their own browser. The browser context aborts every request that is not for the box: the only one that is ever tried is the GitHub page the
// person asked for with "Open GitHub issue", and it is aborted here, so nothing leaves this machine.
import { readFileSync } from 'node:fs'
import { expect, test, type BrowserContext, type Page } from '@playwright/test'
import { api, authFile, box } from './box'
import { h1, noErrors, noVietnamese } from './ui'
import { collectErrors, shot } from '../e2e/helpers'

test.use({ actionTimeout: 10_000 })

const SECRET_EMAIL = 'bob@example.com'
const SECRET_IP = '192.168.77.5'

/** A context that aborts everything that is not the box, and lists what it was asked for. */
async function sealed(browser: import('@playwright/test').Browser, role: 'admin' | 'viewer') {
  const context = await browser.newContext({ baseURL: box().base_url, storageState: authFile(role), locale: 'vi-VN', timezoneId: 'Asia/Ho_Chi_Minh', acceptDownloads: true })
  const outside: string[] = []
  await context.route((url) => url.origin !== new URL(box().base_url).origin && !/^(data|blob|about):/.test(url.href), async (route) => {
    outside.push(route.request().url())
    await route.abort()
  })
  return { context, outside }
}
async function openDialog(page: Page, visit = true) {
  if (visit) await page.goto('/')
  await expect(h1(page)).toBeVisible()
  await page.getByRole('button', { name: /Account:/ }).click()
  await page.getByRole('menuitem', { name: 'Report a problem' }).click()
  const dlg = page.getByRole('dialog', { name: 'Report a problem' })
  await expect(dlg).toBeVisible()
  return dlg
}
const bundleOf = (dlg: ReturnType<Page['getByRole']>) => dlg.getByLabel('JSON, preview of the diagnostic bundle')

test('the dialog shows what would be sent, with emails and IPs removed, and nothing leaves the box until the person opens GitHub', async ({ browser }) => {
  test.setTimeout(90_000)
  const { context, outside } = await sealed(browser, 'admin')
  await context.grantPermissions(['clipboard-read', 'clipboard-write'], { origin: new URL(box().base_url).origin })
  const page = await context.newPage()
  const errors = collectErrors(page)
  await page.goto('/')
  await expect(h1(page)).toBeVisible()
  // an error in the page, naming an email and an address, goes to the buffer of recent errors with both removed
  await page.evaluate(([mail, ip]) => window.dispatchEvent(new ErrorEvent('error', { message: `boom for ${mail} at ${ip}` })), [SECRET_EMAIL, SECRET_IP])
  const dlg = await openDialog(page, false) // the buffer of recent errors lives in the page: do not reload it
  await expect(dlg.getByText(/The box sends nothing itself/)).toBeVisible()
  await shot(page, 'real', 'bug-report')

  const modules = (await api<{ modules: { id: string; enabled: boolean }[] }>(context.request, 'GET', '/modules')).body.modules
  const shown = JSON.parse(await bundleOf(dlg).innerText()) as Record<string, any>
  expect(Object.keys(shown).sort(), 'only these fields, no devices, logs, findings, keys').toEqual(['app_version', 'data_mode', 'modules', 'recent_errors', 'route', 'user_agent'])
  expect(shown.data_mode, 'the release build talks to the real box').toBe('live')
  expect(shown.route).toBe('/')
  expect(shown.modules).toEqual(Object.fromEntries(modules.map((m) => [m.id, m.enabled ? 'on' : 'off'])))
  expect(shown.recent_errors.map((e: { message: string }) => e.message)).toContain('boom for [email] at [ip]')
  const text = await dlg.innerText()
  for (const secret of [SECRET_EMAIL, SECRET_IP, 'admin@e2e.test']) expect(text, `${secret} is not shown`).not.toContain(secret)

  // the text is there to copy
  await dlg.getByRole('button', { name: 'Copy' }).click()
  await expect(dlg.getByText('Copied', { exact: true })).toBeVisible()
  expect(JSON.parse(await page.evaluate(() => navigator.clipboard.readText()))).toEqual(shown)

  // the person's words, with an email and an address in them
  await dlg.getByLabel('What happened').fill(`The page for ${SECRET_IP} fails, mail me at ${SECRET_EMAIL}`)
  await dlg.getByLabel('Steps to reproduce').fill('1. Open Devices\n2. Click Add')
  await dlg.getByLabel('What you expected').fill('A form')
  expect(outside, 'nothing was requested outside the box while the report was written').toEqual([])

  // Download report: a file on this computer
  const saved = page.waitForEvent('download')
  await dlg.getByRole('button', { name: 'Download report' }).click()
  const file = await saved
  expect(file.suggestedFilename()).toMatch(/^vedette-report-\d{4}-\d{2}-\d{2}\.json$/)
  const body = readFileSync((await file.path())!, 'utf8')
  const report = JSON.parse(body) as { report: Record<string, string>; diagnostics: unknown }
  expect(report.report).toEqual({ what: 'The page for [ip] fails, mail me at [email]', steps: '1. Open Devices\n2. Click Add', expected: 'A form' })
  expect(report.diagnostics).toEqual(shown)
  for (const secret of [SECRET_EMAIL, SECRET_IP]) expect(body).not.toContain(secret)
  expect(outside, 'a download is not a request to anyone').toEqual([])

  // Open GitHub issue: the one request that leaves, in a new tab, opened by the person, and it is aborted here
  const [popup] = await Promise.all([context.waitForEvent('page'), dlg.getByRole('button', { name: 'Open GitHub issue' }).click()])
  await popup.waitForEvent('close', { timeout: 1500 }).catch(() => undefined)
  await expect.poll(() => outside.length).toBe(1)
  const url = new URL(outside[0]!)
  expect(`${url.origin}${url.pathname}`).toBe('https://github.com/KNT048/vedette/issues/new')
  expect(url.searchParams.get('title')).toBe('[bug] The page for [ip] fails, mail me at [email]')
  const issue = url.searchParams.get('body') ?? ''
  expect(issue).toContain('## What happened')
  expect(issue).toContain('The page for [ip] fails, mail me at [email]')
  expect(issue).toContain('## Steps to reproduce')
  expect(issue).toContain('I will attach the downloaded diagnostic file to this issue.')
  for (const secret of [SECRET_EMAIL, SECRET_IP, 'admin@e2e.test']) expect(url.href, `${secret} is not in the link`).not.toContain(encodeURIComponent(secret))
  expect(outside, 'GitHub was tried once, and nothing else').toHaveLength(1)
  await noVietnamese(page, 'bug report')
  noErrors(errors, /Failed to load resource|ERR_FAILED/)
  await context.close()
})

test('a viewer can report a problem too, and the dialog closes without sending anything', async ({ browser }) => {
  const { context, outside } = await sealed(browser, 'viewer')
  const page = await context.newPage()
  const dlg = await openDialog(page)
  await expect(bundleOf(dlg)).toContainText('"data_mode": "live"')
  await dlg.getByRole('button', { name: 'Close' }).first().click()
  await expect(page.getByRole('dialog')).toHaveCount(0)
  expect(outside).toEqual([])
  await (context as BrowserContext).close()
})
