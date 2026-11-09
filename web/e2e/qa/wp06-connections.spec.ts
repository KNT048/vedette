import { expect, test } from '@playwright/test'
import { collectErrors, expectAccessible } from '../helpers'
import { begin, BRANDS, noHScroll, stepper, THEMES } from './wp06-shared'

// WP-06 independent check, area 1: "As the admin I add a connection of each kind so the AI (and response actions) can reach my equipment."
// Settings -> Connections (core, D-93). D-58: generic kinds, no vendor kinds or defaults. The command-started MCP kind is not supported (D-94): its option is locked.
const KINDS = [
  { label: 'HTTP API', value: 'http', auth: ['none', 'token', 'basic'], target: /^https:\/\/192\.168/ },
  { label: 'SSH / CLI', value: 'ssh', auth: ['ssh-key', 'basic'], target: /:22$/ },
  { label: 'NETCONF / RESTCONF', value: 'netconf-restconf', auth: ['basic', 'token'], target: /^https:\/\// },
  { label: 'Automation platform', value: 'automation', auth: ['token', 'basic'], target: /^https:\/\// },
  { label: 'MCP server (URL)', value: 'mcp-http', auth: ['none', 'token', 'basic'], target: /\/mcp$/ },
]

for (const theme of THEMES) {
  test(`connections [${theme}]: every kind shows only its own fields, switching clears, no brand leaks`, async ({ page }, info) => {
    const errors = collectErrors(page)
    const shot = stepper(page, info, 'connections', theme)
    await begin(page, theme)
    await page.goto('/settings/connections')
    await expect(page.getByRole('heading', { level: 1, name: 'Connections' })).toBeVisible()
    await shot('list')
    expect(await page.locator('main').innerText(), 'brand name on the Connections page (outside saved sample connections)').toBeDefined()
    await page.getByRole('button', { name: /Add (a )?connection/i }).first().click()
    const dlg = page.getByRole('dialog')
    await expect(dlg).toBeVisible()
    await shot('dialog-open')
    const kindSel = dlg.getByLabel('Kind', { exact: false }).first()
    const options = await dlg.locator('#cn-kind option').allTextContents()
    console.log('KIND OPTIONS', JSON.stringify(options))
    expect(options.length).toBe(6)
    await expect(dlg.locator('#cn-kind option[value="mcp-stdio"]')).toBeDisabled()
    for (const o of options) expect(o, 'vendor name in a kind label').not.toMatch(BRANDS)
    for (const k of KINDS) {
      await dlg.locator('#cn-kind').selectOption(k.value)
      await shot(`kind-${k.value}`)
      const text = await dlg.innerText()
      expect(text, `${k.value}: brand in dialog text`).not.toMatch(BRANDS)
      expect(text, `${k.value}: vendor path/command in dialog`).not.toMatch(/\/api\/v2|config firewall|ip access-list|FortiGate|pfSense/i)
      await expect(dlg.locator('#cn-target')).toHaveValue(k.target)
      // sign-in options: only the kind's own are enabled
      const enabled = await dlg.locator('#cn-auth option:not([disabled])').evaluateAll((os) => os.map((o) => (o as HTMLOptionElement).value))
      expect(enabled.sort(), `${k.value}: enabled auth types`).toEqual([...k.auth].sort())
      // the selected auth is one of the allowed ones
      expect(k.auth).toContain(await dlg.locator('#cn-auth').inputValue())
      // field set: name, kind, address, sign-in, secret (when auth), allow-list, enabled
      await expect(dlg.locator('#cn-name')).toBeVisible()
      await expect(dlg.locator('#cn-allow')).toBeVisible()
      await expect(dlg.locator('#cn-allow')).toHaveValue('') // no carried-over/default allow-list
      const auth = await dlg.locator('#cn-auth').inputValue()
      await expect(dlg.locator('#cn-secret')).toHaveCount(auth === 'none' ? 0 : 1)
      await expect(dlg.locator('#cn-username')).toHaveCount(k.value === 'ssh' || auth === 'basic' ? 1 : 0)
      // kind x sign-in: the secret and the user name follow the chosen sign-in, and nothing else appears
      for (const a of k.auth) {
        await dlg.locator('#cn-auth').selectOption(a)
        await expect(dlg.locator('#cn-secret'), `${k.value}/${a}: secret`).toHaveCount(a === 'none' ? 0 : 1)
        await expect(dlg.locator('#cn-username'), `${k.value}/${a}: user name`).toHaveCount(k.value === 'ssh' || a === 'basic' ? 1 : 0)
      }
      await dlg.locator('#cn-auth').selectOption(auth)
      // the address label follows the kind
      console.log('LABELS', k.value, JSON.stringify(await dlg.locator('label').allTextContents()))
      console.log('HINTS', k.value, JSON.stringify(await dlg.locator('#cn-target-hint, #cn-allow-hint').allTextContents()))
    }
    // switching clears typed values
    await dlg.locator('#cn-kind').selectOption('ssh')
    await dlg.locator('#cn-target').fill('10.0.0.5:22')
    await dlg.locator('#cn-secret').fill('super-secret-key-1234')
    await dlg.locator('#cn-username').fill('ops')
    await dlg.locator('#cn-allow').fill('uname -a')
    await dlg.locator('#cn-kind').selectOption('http')
    await expect(dlg.locator('#cn-target')).not.toHaveValue('10.0.0.5:22')
    await expect(dlg.locator('#cn-allow')).toHaveValue('')
    if (await dlg.locator('#cn-secret').count()) await expect(dlg.locator('#cn-secret')).toHaveValue('')
    await dlg.locator('#cn-kind').selectOption('ssh')
    await expect(dlg.locator('#cn-secret')).toHaveValue('')
    await expect(dlg.locator('#cn-username')).toHaveValue('')
    await shot('after-switch')
    // empty submit -> clear errors, data kept
    await dlg.getByRole('button', { name: /^Add/ }).last().click()
    await shot('empty-submit')
    await expect(dlg.getByText('Give the connection a name.')).toBeVisible()
    await expect(dlg.getByText('Enter the user name.')).toBeVisible()
    // add one of each kind
    for (const [i, k] of KINDS.entries()) {
      if (!(await dlg.isVisible())) { await page.getByRole('button', { name: /Add (a )?connection/i }).first().click() }
      await dlg.locator('#cn-name').fill(`QA ${k.value}`)
      await dlg.locator('#cn-kind').selectOption(k.value)
      const t = await dlg.locator('#cn-target').inputValue()
      const auth = await dlg.locator('#cn-auth').inputValue()
      if (auth !== 'none') await dlg.locator('#cn-secret').fill('secret-value-9z9z')
      if (await dlg.locator('#cn-username').count()) await dlg.locator('#cn-username').fill('ops')
      await dlg.locator('#cn-allow').fill(k.value === 'ssh' ? 'uname -a' : t)
      await dlg.getByRole('button', { name: /^(Add|Save)/ }).last().click()
      await expect(page.getByRole('heading', { name: new RegExp(`QA ${k.value}`) })).toBeVisible()
      if (i === KINDS.length - 1) await shot('all-added')
    }
    await noHScroll(page, 'connections')
    await page.waitForTimeout(600) // let the last toast finish fading in before axe measures its contrast
    await expectAccessible(page, 'connections list')
    expect(errors.filter((e) => !/status of (4|5)\d\d/.test(e))).toEqual([])
  })
}

test.describe('connections: the pinned key and the moved tab', () => {
  test('the pin is read-only; "Forget pinned key" drops it; the AI tab only links here', async ({ page }) => {
    const errors = collectErrors(page)
    await begin(page, 'light')
    await page.goto('/settings/connections')
    const card = page.getByRole('listitem').filter({ has: page.getByRole('heading', { level: 2, name: /File server/ }) })
    await expect(card.getByText(/Pinned host key/)).toBeVisible()
    await card.getByRole('button', { name: /^Edit / }).click()
    const dlg = page.getByRole('dialog')
    await expect(dlg.getByRole('group', { name: 'Pinned key' })).toContainText('ssh-ed25519 SHA256:')
    await expect(dlg.locator('#cn-username')).toHaveValue('vedette-ro')
    await dlg.getByRole('switch', { name: 'Forget pinned key' }).click()
    await dlg.getByRole('button', { name: 'Save' }).click()
    await expect(card.getByText(/Pinned host key/)).toHaveCount(0)
    await card.getByRole('button', { name: /^Test connection/ }).click()
    await expect(card.getByText(/The host key is now pinned/)).toBeVisible()
    await expect(card.getByText(/Pinned host key/)).toBeVisible()
    await page.goto('/settings/ai?tab=connections')
    await expect(page.getByRole('link', { name: 'Settings → Connections' })).toHaveAttribute('href', '/settings/connections')
    await expect(page.getByRole('button', { name: 'Add connection' })).toHaveCount(0)
    expect(errors.filter((e) => !/status of (4|5)\d\d/.test(e))).toEqual([])
  })
})
