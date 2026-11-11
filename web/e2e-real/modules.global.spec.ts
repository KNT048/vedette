// Turning modules off and on on the real backend (S-CORE-1, core INV on modules, SYS-5). Global project: a module switch is box-wide, so
// this runs alone, and every test puts the switches back. Steps from e2e/qa/core.spec.ts ("modules").
//   - "External surface" (exposure) is the module that is turned off: nothing depends on it and it keeps a setting of its own (the
//     box-IP check interval), which is the data that must still be there after it is turned on again.
//   - "Vulnerability scan" is turned off to make "Credentialed scan" (off by default, needs it) ask for its dependency.
// What a module that is off answers: SYS-5 says its routes answer 404 "as if they did not exist" (core/server/modules.go), not 409
// `module_off` (that code belongs to the MCP token call and to the email channel of the account page).
import { expect, request, test, type Page } from '@playwright/test'
import { api, authFile, box } from './box'
import { expectAccessible, h1, noErrors, noVietnamese } from './ui'
import { collectErrors, shot } from '../e2e/helpers'

test.use({ storageState: authFile('admin'), actionTimeout: 10_000 })

interface Mod { id: string; enabled: boolean; tier: string; depends: string[] }
const mods = async (c: Awaited<ReturnType<typeof request.newContext>>) => (await api<{ modules: Mod[] }>(c, 'GET', '/modules')).body.modules
const state = async (c: Awaited<ReturnType<typeof request.newContext>>, id: string) => (await mods(c)).find((m) => m.id === id)?.enabled
const toast = (page: Page, re: RegExp) => expect(page.locator('[data-sonner-toast]').filter({ hasText: re }).first()).toBeVisible()
const sw = (page: Page, name: string) => page.getByRole('switch', { name: `Turn on module ${name}` })
async function onModulesPage(page: Page, find: string) {
  await page.goto('/settings/modules')
  await expect(h1(page)).toContainText('modules are on')
  await page.getByRole('textbox', { name: 'Find a module' }).fill(find)
}

test('turn a module off: the page says so, its routes answer 404, its data is kept, turn it on again', async ({ page }) => {
  test.setTimeout(120_000)
  const errors = collectErrors(page)
  const admin = await request.newContext({ baseURL: box().base_url, storageState: authFile('admin') })
  try {
    expect(await state(admin, 'exposure'), 'exposure is on (mid-size bundle)').toBe(true)
    const keep = await api(admin, 'PUT', '/exposure/box-ip/settings', { auto: false, interval_min: 37 })
    expect(keep.status, JSON.stringify(keep.body)).toBe(200)

    await onModulesPage(page, 'External surface')
    await expect(sw(page, 'External surface')).toBeChecked()
    await expectAccessible(page, 'modules')
    await shot(page, 'real', 'modules')
    await sw(page, 'External surface').click()
    const ask = page.getByRole('dialog', { name: 'Turn off External surface?' })
    await expect(ask).toBeVisible()
    await expect(ask.getByText('The module\'s data is kept')).toBeVisible()
    await expect(ask.getByText('No module that is on depends on this one.')).toBeVisible()
    await ask.getByRole('button', { name: 'Cancel' }).click()
    expect(await state(admin, 'exposure'), 'Cancel changes nothing').toBe(true)
    await sw(page, 'External surface').click()
    await ask.getByRole('button', { name: 'Turn off', exact: true }).click()
    await toast(page, /External surface is off\. Modules affected: 0\. Data is kept\./)
    await expect(sw(page, 'External surface')).not.toBeChecked()
    expect(await state(admin, 'exposure')).toBe(false)

    // the routes of the module answer as if they did not exist; the other modules are untouched
    for (const [method, path] of [['GET', '/exposure/targets'], ['POST', '/exposure/box-ip/verify'], ['PUT', '/exposure/box-ip/settings']] as const) {
      const r = await api<{ error: { code: string } }>(admin, method, path, method === 'PUT' ? { auto: false, interval_min: 37 } : undefined)
      expect(r.status, `${method} ${path} while the module is off`).toBe(404)
      expect(r.body).toMatchObject({ error: { code: 'not_found' } })
    }
    expect((await api(admin, 'GET', '/inventory/devices')).status).toBe(200)
    // the page says which module is off and links to the switch; the sidebar entry is gone
    await page.goto('/exposure')
    await expect(page.getByText('External surface module is off')).toBeVisible()
    await expect(page.getByText('Existing data is kept. Turn the module on to get new data here.')).toBeVisible()
    await expect(page.getByRole('navigation').first().getByRole('link', { name: 'External exposure' })).toHaveCount(0)
    await shot(page, 'real', 'module-off-page')
    await page.getByRole('link', { name: 'Open module settings' }).click()
    await expect(page).toHaveURL(/\/settings\/modules/)

    // on again from the same page: the setting made before is still there
    await page.getByRole('textbox', { name: 'Find a module' }).fill('External surface')
    await sw(page, 'External surface').click()
    await toast(page, /External surface is on/)
    await expect(sw(page, 'External surface')).toBeChecked()
    expect(await state(admin, 'exposure')).toBe(true)
    const back = await api<{ box_ip: { auto: boolean; interval_min: number } }>(admin, 'GET', '/exposure/targets')
    expect(back.status).toBe(200)
    expect(back.body.box_ip).toMatchObject({ auto: false, interval_min: 37 })
    await page.goto('/exposure')
    await expect(h1(page)).toBeVisible()
    await expect(page.getByText('External surface module is off')).toHaveCount(0)
    await page.reload()
    await expect(page.getByText('External surface module is off')).toHaveCount(0)

    // both switches are in the audit log
    const log = await api<{ items: { action: string; target: string }[] }>(admin, 'GET', '/core/audit?q=exposure')
    expect(log.body.items.filter((r) => r.target === 'exposure').map((r) => r.action)).toEqual(expect.arrayContaining(['module.enable', 'module.disable']))
    await noVietnamese(page, 'module off')
    noErrors(errors, /status of 404/)
  } finally {
    if ((await state(admin, 'exposure')) === false) await api(admin, 'PATCH', '/modules/exposure', { enabled: true })
    await api(admin, 'PUT', '/exposure/box-ip/settings', { auto: false, interval_min: 60 })
    await admin.dispose()
  }
})

test('turning on a module whose dependency is off asks to turn both on', async ({ page }) => {
  test.setTimeout(120_000)
  const errors = collectErrors(page)
  const admin = await request.newContext({ baseURL: box().base_url, storageState: authFile('admin') })
  try {
    expect(await state(admin, 'scan'), 'the scan module is on (mid-size bundle)').toBe(true)
    expect(await state(admin, 'scan-credentialed')).toBe(false)
    expect((await api(admin, 'PATCH', '/modules/scan-credentialed', { enabled: false })).status).toBe(200)
    expect((await api(admin, 'PATCH', '/modules/scan', { enabled: false })).status).toBe(200)
    // the server: 409 and the full list of what is missing, and nothing was changed
    const refused = await api<{ error: { code: string; missing?: string[] }; missing?: string[] }>(admin, 'PATCH', '/modules/scan-credentialed', { enabled: true })
    expect(refused.status).toBe(409)
    expect(refused.body.error.code).toBe('missing_dependencies')
    expect(refused.body.error.missing ?? refused.body.missing, 'the full list of what is missing').toEqual(['scan'])
    expect(await state(admin, 'scan-credentialed')).toBe(false)

    await onModulesPage(page, 'Credentialed scan')
    await sw(page, 'Credentialed scan').click()
    const dlg = page.getByRole('dialog', { name: 'Turn on the required modules too?' })
    await expect(dlg).toBeVisible()
    await expect(dlg.getByText('Vulnerability scan')).toBeVisible()
    await shot(page, 'real', 'modules-dependencies')
    await page.keyboard.press('Escape')
    await expect(sw(page, 'Credentialed scan')).not.toBeChecked()
    expect(await state(admin, 'scan'), 'Escape turns nothing on').toBe(false)
    await sw(page, 'Credentialed scan').click()
    await dlg.getByRole('button', { name: 'Turn on together' }).click()
    await toast(page, /Credentialed scan is on/)
    await expect(sw(page, 'Credentialed scan')).toBeChecked()
    expect(await state(admin, 'scan')).toBe(true)
    expect(await state(admin, 'scan-credentialed')).toBe(true)
    const log = await api<{ items: { action: string; target: string; detail?: string }[] }>(admin, 'GET', '/core/audit?q=scan-credentialed')
    expect(log.body.items.some((r) => r.action === 'module.enable' && r.target === 'scan-credentialed' && /scan/.test(r.detail ?? ''))).toBe(true)

    // turning the one that is needed off names the module that depends on it, and keeps it on
    await onModulesPage(page, 'Vulnerability scan')
    await sw(page, 'Vulnerability scan').click()
    const off = page.getByRole('dialog', { name: 'Turn off Vulnerability scan?' })
    await expect(off.getByText('Credentialed scan')).toBeVisible()
    await off.getByRole('button', { name: 'Cancel' }).click()
    expect(await state(admin, 'scan')).toBe(true)
    await noVietnamese(page, 'modules dependencies')
    noErrors(errors, /status of 409/)
  } finally {
    await api(admin, 'PATCH', '/modules/scan-credentialed', { enabled: false })
    if (!(await state(admin, 'scan'))) await api(admin, 'PATCH', '/modules/scan', { enabled: true })
    await admin.dispose()
  }
})

test('the core module cannot be turned off, in the page or through the API', async ({ page }) => {
  const admin = await request.newContext({ baseURL: box().base_url, storageState: authFile('admin') })
  const r = await api<{ error: { code: string } }>(admin, 'PATCH', '/modules/core', { enabled: false })
  expect(r.status).toBe(400)
  expect(r.body).toMatchObject({ error: { code: 'core_module' } })
  expect((await api(admin, 'PATCH', '/modules/no-such-module', { enabled: true })).status).toBe(404)
  await onModulesPage(page, 'Core')
  await expect(sw(page, 'Core')).toBeDisabled()
  await expect(sw(page, 'Core')).toBeChecked()
  await admin.dispose()
})
