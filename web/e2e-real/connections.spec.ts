// Settings -> Connections on the real backend (D-93, D-94, D-127, S-AI-7, S-RESP-4). The devices are the loopback fakes of the box process
// (cmd/vedette/e2edevices_test.go): an HTTPS, an SSH and an MCP server reachable under their own names. The form matrix is that of
// e2e/qa/wp06-connections.spec.ts; what only a real box shows is new: Test reaches the fake and the fake saw the credential, the first test pins
// the certificate or host key, a changed key is refused before anything is sent, "Forget pinned key" lets the next test pin again, the real
// address policy refuses loopback and link-local, the secret never comes back, and a viewer or operator cannot read or change connections.
// One device per kind is shared and rotated by the pin test, so the tests run in order in one worker.
import { expect, request, test, type Locator, type Page } from '@playwright/test'
import { api, authFile, box, device, deviceSeen, rotateDevice, uniq } from './box'
import { expectAccessible, h1, noErrors, noVietnamese } from './ui'
import { collectErrors, shot } from '../e2e/helpers'

test.use({ storageState: authFile('admin'), actionTimeout: 10_000 })
test.describe.configure({ mode: 'serial' })

const BRANDS = /forti|pfsense|cisco|mikrotik|palo ?alto|juniper|ubiquiti|unifi|aruba|sophos|opnsense|checkpoint|sonicwall|huawei|tp-?link|omada/i
const KINDS = [
  { label: 'HTTP API', value: 'http', auth: ['none', 'token', 'basic'] },
  { label: 'SSH / CLI', value: 'ssh', auth: ['ssh-key', 'basic'] },
  { label: 'NETCONF / RESTCONF', value: 'netconf-restconf', auth: ['basic', 'token'] },
  { label: 'Automation platform', value: 'automation', auth: ['token', 'basic'] },
  { label: 'MCP server (URL)', value: 'mcp-http', auth: ['none', 'token', 'basic'] },
]
interface Conn { id: string; name: string; status: string; pin: { kind: string; value: string } | null; auth: { type: string; last4?: string }; tools: { name: string; enabled: boolean; access: string }[] }

const card = (page: Page, name: string) => page.getByRole('listitem').filter({ has: page.getByRole('heading', { level: 2, name }) })
const open = async (page: Page) => { await page.goto('/settings/connections'); await expect(h1(page)).toHaveText('Connections') }
const list = async (page: Page) => (await api<{ items: Conn[] }>(page.request, 'GET', '/core/connections')).body.items

/** Adds a connection through the dialog and waits until its card is on the page. */
async function add(page: Page, f: { name: string; kind: string; target: string; auth: string; username?: string; secret?: string; allow: string }) {
  await page.getByRole('button', { name: /Add connection/ }).first().click()
  const dlg = page.getByRole('dialog')
  await dlg.locator('#cn-name').fill(f.name)
  await dlg.locator('#cn-kind').selectOption(f.kind)
  await dlg.locator('#cn-target').fill(f.target)
  await dlg.locator('#cn-auth').selectOption(f.auth)
  if (f.username !== undefined) await dlg.locator('#cn-username').fill(f.username)
  if (f.secret !== undefined) await dlg.locator('#cn-secret').fill(f.secret)
  await dlg.locator('#cn-allow').fill(f.allow)
  await dlg.getByRole('button', { name: /^Add connection$/ }).last().click()
  await expect(card(page, f.name)).toBeVisible()
}
const test_ = (c: Locator) => c.getByRole('button', { name: /^Test connection/ }).click()

test('the form shows only the fields of the kind and the sign-in, switching clears, and an empty submit says what is missing', async ({ page }) => {
  const errors = collectErrors(page)
  await open(page)
  await shot(page, 'real-connections', 'list')
  await page.getByRole('button', { name: /Add connection/ }).first().click()
  const dlg = page.getByRole('dialog')
  const options = await dlg.locator('#cn-kind option').allTextContents()
  expect(options.length).toBe(6)
  await expect(dlg.locator('#cn-kind option[value="mcp-stdio"]')).toBeDisabled()
  for (const o of options) expect(o, 'vendor name in a kind label').not.toMatch(BRANDS)
  for (const k of KINDS) {
    await dlg.locator('#cn-kind').selectOption(k.value)
    expect(await dlg.innerText(), `${k.value}: brand in the dialog`).not.toMatch(BRANDS)
    await expect(dlg.locator('#cn-target'), `${k.value}: no sample address in the field`).toHaveValue('')
    const enabled = await dlg.locator('#cn-auth option:not([disabled])').evaluateAll((os) => os.map((o) => (o as HTMLOptionElement).value))
    expect(enabled.sort(), `${k.value}: enabled sign-in types`).toEqual([...k.auth].sort())
    await expect(dlg.locator('#cn-allow')).toHaveValue('')
    for (const a of k.auth) {
      await dlg.locator('#cn-auth').selectOption(a)
      await expect(dlg.locator('#cn-secret'), `${k.value}/${a}: secret`).toHaveCount(a === 'none' ? 0 : 1)
      await expect(dlg.locator('#cn-username'), `${k.value}/${a}: user name`).toHaveCount(k.value === 'ssh' || a === 'basic' ? 1 : 0)
    }
  }
  await dlg.locator('#cn-kind').selectOption('ssh')
  await dlg.locator('#cn-target').fill('10.0.0.5:22')
  await dlg.locator('#cn-secret').fill('super-secret-key-1234')
  await dlg.locator('#cn-username').fill('ops')
  await dlg.locator('#cn-allow').fill('uname -a')
  await dlg.locator('#cn-kind').selectOption('http')
  await expect(dlg.locator('#cn-target')).toHaveValue('')
  await expect(dlg.locator('#cn-allow')).toHaveValue('')
  await dlg.locator('#cn-kind').selectOption('ssh')
  await expect(dlg.locator('#cn-secret')).toHaveValue('')
  await expect(dlg.locator('#cn-username')).toHaveValue('')
  await dlg.getByRole('button', { name: /^Add connection$/ }).last().click()
  await expect(dlg.getByText('Give the connection a name.')).toBeVisible()
  await expect(dlg.getByText('Enter the user name.')).toBeVisible()
  await shot(page, 'real-connections', 'empty-submit')
  await noVietnamese(page, 'connections dialog')
  noErrors(errors, /status of (4|5)\d\d/)
})

test('an address the policy never allows is refused with the reason, and nothing is saved', async ({ page }) => {
  await open(page)
  const before = (await list(page)).length
  for (const [target, why] of [['https://127.0.0.1', /loopback address/], ['https://localhost', /loopback address/], ['https://169.254.169.254', /Vedette never connects to/]] as const) {
    await page.getByRole('button', { name: /Add connection/ }).first().click()
    const dlg = page.getByRole('dialog')
    await dlg.locator('#cn-name').fill(uniq('refused'))
    await dlg.locator('#cn-kind').selectOption('http')
    await dlg.locator('#cn-target').fill(target)
    await dlg.locator('#cn-auth').selectOption('none')
    await dlg.locator('#cn-allow').fill(`${target}/api/`)
    await dlg.getByRole('button', { name: /^Add connection$/ }).last().click()
    await expect(dlg, target).toContainText(why)
    await shot(page, 'real-connections', `refused-${target.replace(/\W+/g, '-')}`)
    await dlg.getByRole('button', { name: /Cancel|Close/ }).first().click()
  }
  expect((await list(page)).length, 'connections saved after three refusals').toBe(before)
})

test('HTTP API: the first Test reaches the device with the token, pins the certificate, and the secret never comes back', async ({ page }) => {
  const errors = collectErrors(page)
  const dev = device('http')
  const name = uniq('http')
  await open(page)
  await add(page, { name, kind: 'http', target: dev.target, auth: 'token', secret: dev.secret, allow: `${dev.target}/api/` })
  const c = card(page, name)
  await expect(c).toContainText('Not tested')
  await expect(c).toContainText('never tested')
  await expect(c).toContainText('The first test trusts whatever answers')
  const seen0 = ((await deviceSeen('http')).requests ?? []).length
  await test_(c)
  await expect(c.getByRole('status')).toContainText(/Connected\./)
  await expect(c.getByRole('status')).toContainText('The certificate is now pinned.')
  await expect(c).toContainText('Working')
  await expect(c).toContainText(/Pinned certificate key: [0-9a-f]{64}/)
  const seen = (await deviceSeen('http')).requests ?? []
  expect(seen.length, 'the device was asked').toBeGreaterThan(seen0)
  expect(seen.at(-1)?.authorization, 'the token reached the device in the Authorization header').toBe(`Bearer ${dev.secret}`)
  const [row] = (await list(page)).filter((x) => x.name === name)
  expect(row?.status).toBe('ok')
  expect(row?.pin?.kind).toBe('tls_sha256')
  const raw = (await page.request.get('/api/v1/core/connections')).text()
  expect(await raw, 'the secret in the list').not.toContain(dev.secret!)
  expect(row?.auth.last4).toBe(dev.secret!.slice(-4))
  await shot(page, 'real-connections', 'http-pinned')
  await expectAccessible(page, 'connections list with a pinned device')
  noErrors(errors, /status of (4|5)\d\d/)
})

test('SSH: Test signs in with the user and password, pins the host key, and a disabled connection cannot be tested', async ({ page }) => {
  const dev = device('ssh')
  const name = uniq('ssh')
  await open(page)
  await add(page, { name, kind: 'ssh', target: dev.target, auth: 'basic', username: dev.username, secret: dev.secret, allow: 'show version' })
  const c = card(page, name)
  const before = (await deviceSeen('ssh')).logins ?? 0
  await test_(c)
  await expect(c.getByRole('status')).toContainText('The host key is now pinned.')
  await expect(c).toContainText(/Pinned host key: ssh-ed25519 SHA256:/)
  await expect(c).toContainText(`signs in as ${dev.username}`)
  expect((await deviceSeen('ssh')).logins, 'sign-ins the device saw').toBeGreaterThan(before)
  const sw = c.getByRole('switch', { name: `Connection enabled: ${name}` })
  await sw.click()
  await expect(c.getByRole('button', { name: /^Test connection/ })).toBeDisabled()
  await sw.click()
  await expect(c.getByRole('button', { name: /^Test connection/ })).toBeEnabled()
  await shot(page, 'real-connections', 'ssh-pinned')
})

test('MCP server: Test finds the tools, they start as write, and the administrator can mark one as read', async ({ page }) => {
  const dev = device('mcp')
  const name = uniq('mcp')
  await open(page)
  await add(page, { name, kind: 'mcp-http', target: dev.target, auth: 'token', secret: dev.secret, allow: `${dev.target}/` })
  const c = card(page, name)
  await test_(c)
  await expect(c.getByRole('status')).toContainText(/Connected\. 2 tools found/)
  const tools = c.getByRole('list', { name: `Tools of ${name}` })
  await expect(tools.getByRole('listitem')).toHaveCount(2)
  await expect(tools).toContainText('list_resources')
  await expect(tools).toContainText('run_action')
  const sel = c.getByLabel(`Access of list_resources on ${name}`)
  await expect(sel).toHaveValue('write')
  await sel.selectOption('read')
  await expect.poll(async () => (await list(page)).find((x) => x.name === name)?.tools.find((t) => t.name === 'list_resources')?.access, { message: 'the access of list_resources on the box' }).toBe('read')
  await page.reload()
  await expect(card(page, name).getByLabel(`Access of list_resources on ${name}`)).toHaveValue('read')
  await expect(card(page, name).getByLabel(`Access of run_action on ${name}`)).toHaveValue('write')
  const calls = (await deviceSeen('mcp')).calls ?? []
  expect(calls.map((x) => x.rpc)).toEqual(expect.arrayContaining(['initialize', 'tools/list']))
  expect(calls.some((x) => x.rpc === 'tools/call'), 'Test calls no tool').toBe(false)
  await shot(page, 'real-connections', 'mcp-tools')
})

test('a device that shows another certificate is refused before anything is sent; "Forget pinned key" lets the next test pin it', async ({ page }) => {
  const dev = device('http')
  const name = uniq('rot')
  await open(page)
  await add(page, { name, kind: 'http', target: dev.target, auth: 'none', allow: `${dev.target}/api/` })
  const c = card(page, name)
  await test_(c)
  await expect(c.getByRole('status')).toContainText('The certificate is now pinned.')
  await rotateDevice('http')
  const sent = ((await deviceSeen('http')).requests ?? []).length
  await test_(c)
  await expect(c.getByRole('alert')).toContainText(/is not the one pinned at the first test\. Nothing was sent\..*Forget pinned key/)
  expect(((await deviceSeen('http')).requests ?? []).length, 'requests the device got after the refusal').toBe(sent)
  await expect(c).toContainText('Failed')
  await shot(page, 'real-connections', 'pin-mismatch')
  await c.getByRole('button', { name: `Edit ${name}` }).click()
  const dlg = page.getByRole('dialog')
  await expect(dlg.getByRole('group', { name: 'Pinned key' })).toContainText(/[0-9a-f]{64}/)
  await dlg.getByRole('switch', { name: 'Forget pinned key' }).click()
  await dlg.getByRole('button', { name: 'Save' }).click()
  await expect(dlg).toBeHidden()
  await expect(c).toContainText('The first test trusts whatever answers')
  await test_(c)
  await expect(c.getByRole('status')).toContainText('The certificate is now pinned.')
  await expect(c).toContainText('Working')
})

test('delete asks first and removes the connection; an operator and a viewer can neither read nor change connections', async ({ page }) => {
  const dev = device('http')
  const name = uniq('del')
  await open(page)
  await add(page, { name, kind: 'http', target: dev.target, auth: 'none', allow: `${dev.target}/api/` })
  const id = (await list(page)).find((x) => x.name === name)!.id
  for (const role of ['operator', 'viewer'] as const) {
    const ctx = await request.newContext({ baseURL: box().base_url, storageState: authFile(role) })
    try {
      expect((await api(ctx, 'GET', '/core/connections')).status, `${role} reads connections`).toBe(403)
      expect((await api(ctx, 'POST', `/core/connections/${id}/test`)).status, `${role} tests a connection`).toBe(403)
      expect((await api(ctx, 'DELETE', `/core/connections/${id}`)).status, `${role} deletes a connection`).toBe(403)
    } finally { await ctx.dispose() }
  }
  await card(page, name).getByRole('button', { name: `Delete ${name}` }).click()
  const dlg = page.getByRole('dialog')
  await expect(dlg).toContainText(`Delete ${name}?`)
  await dlg.getByRole('button', { name: /Cancel/ }).click()
  await expect(card(page, name)).toBeVisible()
  await card(page, name).getByRole('button', { name: `Delete ${name}` }).click()
  await page.getByRole('dialog').getByRole('button', { name: /^Delete/ }).last().click()
  await expect(card(page, name)).toHaveCount(0)
  expect((await list(page)).some((x) => x.id === id)).toBe(false)
})
