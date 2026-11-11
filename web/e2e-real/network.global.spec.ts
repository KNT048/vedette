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

/** Only the known symptom may satisfy a test.fail: when it is not what the page shows, the expectation is switched off and the test is red. */
const knownSymptom = (known: boolean) => { if (!known) test.fail(false) }
/** What the page showed in the click paths below, for the test.fail markers that follow them. */
const shown = { savedToastOnApply: false, cancelToast: false }

test.afterAll(async () => { // whatever a failed test left: cancel a waiting change, then the address and the time servers the box started with
  const c = await as('admin')
  if ((await api<Net>(c, 'GET', '/core/network')).body.pending) await api(c, 'POST', '/core/network/management/revert')
  const back = await api(c, 'PUT', '/core/network/management', { mode: 'static', address: '192.168.1.50', prefix: 24, gateway: '192.168.1.1', dns: ['1.1.1.1'], confirm: true })
  if (back.status === 200) await api(c, 'POST', '/core/network/management/confirm')
  expect((await api(c, 'PUT', '/core/network/ntp', { mode: 'default', servers: [] })).status, 'NTP put back').toBe(200)
  expect((await api(c, 'PUT', '/core/network/span', { enabled: false, interface: null, extract: { dns: true, tls_sni: true, http_host: false, flows: true }, filters: [], cpu_percent: 25, memory_mb: 512 })).status, 'SPAN off').toBe(200)
  // eth1 back to unused, so a later global spec (sensor-active, slice 7) starts from the box as it came
  const roles = Object.fromEntries((await api<Net>(c, 'GET', '/core/network')).body.interfaces.map((i) => [i.name, i.name === 'eth1' ? 'unused' : i.role]))
  expect((await api(c, 'PUT', '/core/network/interfaces', { roles })).status, 'eth1 unused').toBe(200)
  await c.dispose()
})

test('the page lists the cards of the host, names vedette-host, and leaves out the virtual links', async ({ page }) => {
  const errors = collectErrors(page)
  const st = await net()
  expect(st.status).toBe(200)
  await page.goto('/settings/network')
  await expect(h1(page)).toBeVisible()
  await expect(page.getByText(/applied by vedette-host/), 'the page names the helper').toBeVisible()
  await expect(page.getByText('If the box restarts before you confirm, it comes back on the old address.'), 'D-100: the help next to Save').toBeVisible()
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

test('before any management address is saved the host refuses other network changes in words (management_not_set, D-118)', async ({ page }) => {
  const errors = collectErrors(page)
  const said = "Vedette has not set up this box's network yet. Save the management address first, then change the other settings."
  await page.goto('/settings/network')
  await page.getByLabel('Time source').selectOption('custom')
  await page.getByLabel('NTP servers').fill('ntp1.example.com')
  await page.getByRole('button', { name: 'Save', exact: true }).click()
  await expect(page.getByRole('alert').filter({ hasText: said })).toBeVisible()
  expect((await net()).body.ntp.mode, 'nothing was changed').toBe('default')
  await shot(page, 'real', 'network-management-not-set')
  noErrors(errors, /status of 4\d\d/)
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
  shown.savedToastOnApply = await page.locator('[data-sonner-toast]').filter({ hasText: 'Management settings saved.' }).first().waitFor({ timeout: 3_000 }).then(() => true, () => false)
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
  shown.cancelToast = await page.locator('[data-sonner-toast]').filter({ hasText: /went back|old settings|old address|cancel/i }).first().waitFor({ timeout: 2_000 }).then(() => true, () => false)
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
  await expect(page.getByRole('alert').filter({ hasText: 'The gateway must be inside the address range you entered.' })).toBeVisible()
  await expect(page.getByRole('dialog')).toHaveCount(0)
  await fillManagement(page, { address: 'not-an-address', gateway: '192.168.1.1', dns: '1.1.1.1' })
  await save(page).click()
  await expect(page.getByRole('alert').filter({ hasText: 'The IP address must be an IPv4 address like 192.168.10.250.' })).toBeVisible()
  expect((await net()).body.pending).toBeNull()
  expect((await net()).body.management.address).toBe('192.168.1.60')
  noErrors(errors, /status of 4\d\d/)
})

test('SPAN: eth1 gets the role, the port, what is read and an exclusion are saved and survive a reload, and the switch guide shows steps', async ({ page }) => {
  test.setTimeout(90_000)
  const errors = collectErrors(page)
  await page.goto('/settings/network')
  await page.getByRole('combobox', { name: 'Role of eth1' }).selectOption('span')
  await toast(page, /Interface roles saved\./)
  expect((await net()).body.interfaces.find((i) => i.name === 'eth1')?.role).toBe('span')
  const want = async (name: string, on: boolean) => { const sw = page.getByRole('switch', { name }); if ((await sw.isChecked()) !== on) await sw.click() }
  await want('Capture mirrored traffic', true)
  await page.getByLabel('Capture port').selectOption('eth1')
  await want('DNS queries', true)
  await want('TLS server names', true)
  await want('HTTP hosts', true)
  await want('Connection metadata', false)
  await expect(page.getByTestId('span-reading')).toHaveText('Reading: DNS queries, TLS server names, HTTP hosts.')
  await page.getByLabel('Network range', { exact: true }).fill('abc')
  await page.getByRole('button', { name: 'Add exclusion' }).click()
  await expect(page.getByText(/abc/).first()).toBeVisible() // the error names what was typed
  await page.getByLabel('Network range', { exact: true }).fill('10.0.5.0/24')
  await page.getByRole('button', { name: 'Add exclusion' }).click()
  await expect(page.getByRole('list', { name: 'Exclusions' }).getByText('10.0.5.0/24')).toBeVisible()
  await page.getByRole('button', { name: 'Save SPAN settings' }).click()
  await toast(page, /SPAN settings saved\./)
  const span = (await net()).body as unknown as { span: { enabled: boolean; interface: string; extract: Record<string, boolean>; filters: { type: string; value: string }[] } }
  expect(span.span).toMatchObject({ enabled: true, interface: 'eth1', extract: { dns: true, tls_sni: true, http_host: true, flows: false }, filters: [{ type: 'cidr', value: '10.0.5.0/24' }] })
  await page.reload()
  await expect(page.getByRole('switch', { name: 'Capture mirrored traffic' })).toBeChecked()
  await expect(page.getByLabel('Capture port')).toHaveValue('eth1')
  await expect(page.getByRole('switch', { name: 'HTTP hosts' })).toBeChecked()
  await expect(page.getByRole('switch', { name: 'Connection metadata' })).not.toBeChecked()
  await expect(page.getByRole('list', { name: 'Exclusions' }).getByText('10.0.5.0/24')).toBeVisible()
  await shot(page, 'real', 'network-span')
  // the guide for a switch: pick one, see its steps for eth1
  await page.getByLabel('Switch or device').selectOption({ index: 1 })
  await expect(page.getByText('Port names and numbers are examples.')).toBeVisible()
  await expect(page.getByText('the destination is the port plugged into eth1')).toBeVisible()
  await expect(page.getByRole('heading', { level: 3 }).filter({ hasText: /\S/ }).last()).toBeVisible()
  noErrors(errors, /status of 4\d\d/)
})

test('DHCP: the confirm dialog says where to find the new address instead of showing one (D-118), and Cancel changes nothing', async ({ page }) => {
  const errors = collectErrors(page)
  const before = (await net()).body
  await page.goto('/settings/network')
  await page.getByLabel('How the box gets its address').selectOption('dhcp')
  await save(page).click()
  const dlg = page.getByRole('dialog', { name: 'Change the management address?' })
  await expect(dlg).toContainText('Your DHCP server picks the new address: find it there (or in your router\'s client list), open it on port 8443 within 5 minutes and confirm, or the box returns to the old settings.')
  await expect(dlg).toContainText('If you cannot find the new address, do nothing: after 5 minutes the box goes back to the old address by itself.')
  await expect(dlg).not.toContainText(/\d+\.\d+\.\d+\.\d+/)
  await shot(page, 'real', 'network-dhcp-dialog')
  await dlg.getByRole('button', { name: 'Cancel' }).click()
  await expect(page.getByRole('dialog')).toHaveCount(0)
  const after = (await net()).body
  expect(after.pending).toBeNull()
  expect(after.management).toEqual(before.management)
  noErrors(errors, /status of 4\d\d/)
})

// test.fail (D-171): starting the 5-minute window toasts "Management settings saved." although nothing is kept until the person confirms. Issue #242.
test('applying a new address does not say "saved" while the box still waits for the confirm', async () => {
  test.fail(true, 'GUI: "Management settings saved." when the 5-minute window starts (issue #242, .ai/deferred/feat-e2e-real-harness.md)')
  knownSymptom(shown.savedToastOnApply)
  expect(shown.savedToastOnApply, 'a "saved" toast at the start of the window').toBe(false)
})

// test.fail (D-171): Cancel and go back now gives no toast of its own (Confirm does). Issue #243.
test('cancelling a waiting change tells the person the box went back', async () => {
  test.fail(true, 'GUI: Cancel and go back now shows no toast (issue #243, .ai/deferred/feat-e2e-real-harness.md)')
  knownSymptom(!shown.cancelToast)
  expect(shown.cancelToast, 'a toast after cancelling').toBe(true)
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
  const ntp = await api(c, 'PUT', '/core/network/ntp', { mode: 'default', servers: [] })
  expect(ntp.status, JSON.stringify(ntp.body)).toBe(200)
  await c.dispose()
  expect((await net()).body.management.address).toBe('192.168.1.50')
})
