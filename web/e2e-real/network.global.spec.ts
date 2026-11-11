// Settings -> Box network on the real backend through vedette-host (S-CORE-8, D-56, D-100, D-118, core INV-25). The host is the fake machine
// of cmd/vedette/e2ehost_test.go: the real net.* commands of host/ops over a temporary root, a fake ARP prober and a fake network whose
// addresses follow the netplan file the host writes. Click paths only: apply -> the confirm window -> confirm, and apply -> cancel. The
// 5-minute expiry (the host's timer) stays in the Go tests (modules/core/network_test.go: TestNetworkRevertAndTheTimerGoBackToTheOldSettings).
// Global project: the box's management address is box-wide state; the last test puts it back where it started (192.168.1.50).
// Steps from e2e/qa/wp06-updates-os.spec.ts (the Box network page) and web/src/features/core/network.test.tsx.
import { expect, request, test, type Page } from '@playwright/test'
import { api, authFile, box } from './box'
import { expectAccessible, h1, noErrors, noVietnamese } from './ui'
import { collectErrors, shot } from '../e2e/helpers'

test.use({ storageState: authFile('admin'), actionTimeout: 10_000 })
test.describe.configure({ mode: 'serial' })

interface Net {
  interfaces: { name: string; role: string }[]
  management: { mode: string; address: string | null; gateway?: string | null; dns: string[] }
  pending: null | { expires_at: string; window_s: number; previous_address: string | null }
  ntp: { mode: string; servers: string[] }
}
const as = (role: 'admin' | 'operator' | 'viewer') => request.newContext({ baseURL: box().base_url, storageState: authFile(role) })
const net = async () => { const c = await as('admin'); const r = await api<Net>(c, 'GET', '/core/network'); await c.dispose(); return r }
const toast = (page: Page, re: RegExp) => expect(page.locator('[data-sonner-toast]').filter({ hasText: re }).first()).toBeVisible()
const pendingBox = (page: Page) => page.getByRole('status').filter({ hasText: 'Waiting for you to confirm at' })
const save = (page: Page) => page.getByRole('button', { name: 'Save management settings' })

async function fillManagement(page: Page, v: { address: string; gateway: string; dns: string }) {
  await page.getByLabel('IP address', { exact: true }).fill(v.address)
  await page.getByLabel('Prefix length').fill('24')
  await page.getByLabel('Gateway').fill(v.gateway)
  await page.getByLabel('DNS servers').fill(v.dns)
}

async function audit(action: string) {
  const c = await as('admin')
  const r = await api<{ items: { action: string; user: string }[] }>(c, 'GET', `/core/audit?q=${encodeURIComponent(action)}`)
  await c.dispose()
  return r.body.items.filter((i) => i.action === action)
}

test.afterAll(async () => { // whatever a failed test left: cancel a waiting change, then the address the box started with
  const c = await as('admin')
  if ((await api<Net>(c, 'GET', '/core/network')).body.pending) await api(c, 'POST', '/core/network/management/revert')
  const back = await api(c, 'PUT', '/core/network/management', { mode: 'static', address: '192.168.1.50', prefix: 24, gateway: '192.168.1.1', dns: ['1.1.1.1'], confirm: true })
  if (back.status === 200) await api(c, 'POST', '/core/network/management/confirm')
  await c.dispose()
})

test('the page lists the cards of the host, names vedette-host, and leaves out the virtual links', async ({ page }) => {
  const errors = collectErrors(page)
  const st = await net()
  expect(st.status).toBe(200)
  await page.goto('/settings/network')
  await expect(h1(page)).toBeVisible()
  await expect(page.getByText(/applied by vedette-host/), 'the page names the helper').toBeVisible()
  const table = page.getByRole('table', { name: 'Network interfaces of the box' })
  await expect(table.getByRole('row').filter({ has: page.getByRole('cell', { name: 'eth0', exact: true }) })).toContainText('Management')
  await expect(table.getByRole('cell', { name: 'eth1', exact: true })).toBeVisible()
  await expect(table.getByRole('cell', { name: 'veth1234' }), 'a virtual link is not a card').toHaveCount(0)
  expect(st.body.interfaces.map((i) => i.name)).toEqual(['eth0', 'eth1', 'eth2'])
  await expectAccessible(page, 'box network')
  expect(await page.locator('main').innerText()).not.toMatch(/vedette-updater|\bupdater\b/i)
  await shot(page, 'real', 'network')
  await noVietnamese(page, 'network')
  noErrors(errors, /status of 4\d\d/)
})

test('a viewer and an operator read the page and cannot change it', async ({ browser }) => {
  for (const role of ['viewer', 'operator'] as const) {
    const c = await as(role)
    expect((await api(c, 'GET', '/core/network')).status, role).toBe(200)
    const put = await api<{ error: { code: string } }>(c, 'PUT', '/core/network/management', { mode: 'static', address: '192.168.1.99', prefix: 24, gateway: '192.168.1.1', dns: ['1.1.1.1'], confirm: true })
    expect(put.status, role).toBe(403)
    const ctx = await browser.newContext({ baseURL: box().base_url, storageState: await c.storageState(), locale: 'vi-VN', timezoneId: 'Asia/Ho_Chi_Minh' })
    const page = await ctx.newPage()
    await page.goto('/settings/network')
    await expect(save(page)).toBeDisabled()
    await expect(page.getByRole('combobox', { name: 'Role of eth1' })).toBeDisabled()
    await ctx.close()
    await c.dispose()
  }
  expect((await net()).body.pending).toBeNull()
})

test('apply an address: the confirm dialog asks first (Cancel changes nothing), then a 5-minute window shows, and Confirm keeps the change', async ({ page }) => {
  test.setTimeout(90_000)
  const errors = collectErrors(page)
  const before = (await net()).body
  await page.goto('/settings/network')
  await fillManagement(page, { address: '192.168.1.60', gateway: '192.168.1.1', dns: '1.1.1.1' })
  await save(page).click()
  const dlg = page.getByRole('dialog', { name: 'Change the management address?' })
  await expect(dlg).toContainText('Open https://192.168.1.60:8443 within 5 minutes and confirm')
  await expect(dlg).toContainText('You will need to sign in again at the new address')
  await shot(page, 'real', 'network-confirm-dialog')
  await dlg.getByRole('button', { name: 'Cancel' }).click()
  await expect(page.getByRole('dialog')).toHaveCount(0)
  const unchanged = (await net()).body
  expect(unchanged.pending, 'Cancel in the dialog sent nothing to the host').toBeNull()
  expect(unchanged.management).toEqual(before.management)
  expect(await audit('network.management'), 'a question changes nothing, not even the audit log').toHaveLength(0)

  await save(page).click()
  await dlg.getByRole('button', { name: 'Apply and start the 5-minute timer' }).click()
  const banner = pendingBox(page)
  await expect(banner).toContainText('Waiting for you to confirm at 192.168.1.60')
  await expect(banner).toContainText('the box returns to 192.168.1.50') // the address it replaces
  const left = await banner.getByText(/^\d:\d\d$/).innerText()
  const secs = Number(left.split(':')[0]) * 60 + Number(left.split(':')[1])
  expect(secs, `time left ${left}`).toBeGreaterThan(280)
  expect(secs).toBeLessThanOrEqual(300)
  await expect(save(page), 'no second change while one waits').toBeDisabled()
  await shot(page, 'real', 'network-pending')
  const waiting = (await net()).body
  expect(waiting.pending).toMatchObject({ window_s: 300, previous_address: '192.168.1.50' })
  expect(waiting.management.address).toBe('192.168.1.60')

  await page.reload() // the countdown survives a reload: it is the box's, not the page's
  await expect(pendingBox(page)).toContainText('Waiting for you to confirm at 192.168.1.60')
  await pendingBox(page).getByRole('button', { name: 'Confirm: I opened the new address' }).click()
  await toast(page, /New address confirmed\./)
  await expect(pendingBox(page)).toHaveCount(0)
  const kept = (await net()).body
  expect(kept.pending).toBeNull()
  expect(kept.management).toMatchObject({ mode: 'static', address: '192.168.1.60', gateway: '192.168.1.1', dns: ['1.1.1.1'] })
  await expect(page.getByLabel('IP address', { exact: true })).toHaveValue('192.168.1.60')
  expect(await audit('network.management')).toHaveLength(1)
  expect(await audit('network.management_confirmed')).toHaveLength(1)
  expect((await audit('network.management'))[0].user).toBe('admin@e2e.test')
  await shot(page, 'real', 'network-confirmed')
  noErrors(errors, /status of 4\d\d/)
})

test('apply a second address and cancel it: the box goes back to the one it had, at once', async ({ page }) => {
  test.setTimeout(90_000)
  const errors = collectErrors(page)
  await page.goto('/settings/network')
  await fillManagement(page, { address: '192.168.1.70', gateway: '192.168.1.1', dns: '1.1.1.1' })
  await save(page).click()
  await page.getByRole('dialog').getByRole('button', { name: 'Apply and start the 5-minute timer' }).click()
  await expect(pendingBox(page)).toContainText('Waiting for you to confirm at 192.168.1.70')
  expect((await net()).body.management.address).toBe('192.168.1.70')
  await pendingBox(page).getByRole('button', { name: 'Cancel and go back now' }).click()
  await expect(pendingBox(page)).toHaveCount(0)
  await expect(page.getByLabel('IP address', { exact: true })).toHaveValue('192.168.1.60')
  const back = (await net()).body
  expect(back.pending).toBeNull()
  expect(back.management.address).toBe('192.168.1.60')
  expect(await audit('network.management_reverted')).toHaveLength(1)
  // nothing waits any more: confirming now is refused in words
  const c = await as('admin')
  const late = await api<{ error: { code: string } }>(c, 'POST', '/core/network/management/confirm')
  await c.dispose()
  expect(late.status).toBe(409)
  expect(late.body.error.code).toBe('nothing_pending')
  await shot(page, 'real', 'network-reverted')
  noErrors(errors, /status of 4\d\d/)
})

test('a mistake is told in words and sends nothing: a gateway outside the range, an address that is not one', async ({ page }) => {
  const errors = collectErrors(page)
  await page.goto('/settings/network')
  await fillManagement(page, { address: '192.168.1.80', gateway: '10.9.9.1', dns: '1.1.1.1' })
  await save(page).click()
  await expect(page.getByRole('alert').filter({ hasText: /gateway/i })).toBeVisible()
  await expect(page.getByRole('dialog')).toHaveCount(0)
  await fillManagement(page, { address: 'not-an-address', gateway: '192.168.1.1', dns: '1.1.1.1' })
  await save(page).click()
  await expect(page.getByRole('alert').filter({ hasText: /address/i })).toBeVisible()
  expect((await net()).body.pending).toBeNull()
  expect((await net()).body.management.address).toBe('192.168.1.60')
  noErrors(errors, /status of 4\d\d/)
})

test('time servers and DNS are applied at once: no countdown, and the page shows them after a reload', async ({ page }) => {
  const errors = collectErrors(page)
  await page.goto('/settings/network')
  await page.getByLabel('Time source').selectOption('custom')
  await page.getByLabel('NTP servers').fill('ntp1.example.com') // a name the fake chronyc lists: the host reads the sources back
  await page.getByRole('button', { name: 'Save', exact: true }).click()
  await toast(page, /Time servers saved\./)
  await expect(pendingBox(page)).toHaveCount(0)
  expect((await net()).body.ntp).toMatchObject({ mode: 'custom', servers: ['ntp1.example.com'] })
  await page.getByLabel('DNS servers').fill('9.9.9.9')
  await save(page).click()
  await toast(page, /Management settings saved\./)
  await expect(page.getByRole('dialog')).toHaveCount(0)
  await expect(pendingBox(page)).toHaveCount(0)
  await page.reload()
  await expect(page.getByLabel('NTP servers')).toHaveValue('ntp1.example.com')
  await expect(page.getByLabel('DNS servers')).toHaveValue('9.9.9.9')
  noErrors(errors, /status of 4\d\d/)
})

test('the box is put back on the address it started with', async () => {
  const c = await as('admin')
  const put = await api(c, 'PUT', '/core/network/management', { mode: 'static', address: '192.168.1.50', prefix: 24, gateway: '192.168.1.1', dns: ['1.1.1.1'], confirm: true })
  expect(put.status, JSON.stringify(put.body)).toBe(200)
  expect((await api(c, 'POST', '/core/network/management/confirm')).status).toBe(200)
  await api(c, 'PUT', '/core/network/ntp', { mode: 'default', servers: [] })
  await c.dispose()
  expect((await net()).body.management.address).toBe('192.168.1.50')
})
