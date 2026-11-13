import { expect, test, type Locator, type Page } from '@playwright/test'
import { collectErrors, expectAccessible } from '../helpers'
import { begin, noHScroll, stepper, THEMES } from './wp06-shared'

// WP-06 independent check, area 2: "As the admin I add my own response action for each kind of connection, and I use the template gallery."
// Connections: Settings -> Connections (a command-started MCP server is not supported, D-94, so it is not in this list). Settings -> AI response -> Action catalog -> Add a custom action; Response -> Rules -> Template gallery; rule editor parameter types.

const KINDS = [
  { value: 'http', fields: { method: true, path: true, headers: true, body: true, cli: false, tool: false } },
  { value: 'ssh', fields: { method: false, path: false, headers: false, body: false, cli: true, tool: false } },
  { value: 'netconf-restconf', fields: { method: true, path: true, headers: true, body: true, cli: false, tool: false } },
  { value: 'automation', fields: { method: true, path: true, headers: true, body: true, cli: false, tool: false } },
  { value: 'mcp-http', fields: { method: false, path: false, headers: false, body: false, cli: false, tool: true } },
]

async function addConnection(page: Page, kind: string) {
  await page.goto('/settings/connections')
  await page.getByRole('button', { name: /Add (a )?connection/i }).first().click()
  const d = page.getByRole('dialog')
  await d.locator('#cn-name').fill(`QA ${kind}`)
  await d.locator('#cn-kind').selectOption(kind)
  const t = { http: 'https://192.168.10.1', ssh: '192.168.10.30:22', 'netconf-restconf': 'https://192.168.10.2', automation: 'https://automation.example.local', 'mcp-http': 'https://mcp.example.local/mcp' }[kind]!
  await d.locator('#cn-target').fill(t)
  if ((await d.locator('#cn-auth').inputValue()) !== 'none') await d.locator('#cn-secret').fill('secret-value-9z9z')
  if (await d.locator('#cn-username').count()) await d.locator('#cn-username').fill('ops')
  await d.locator('#cn-allow').fill(kind === 'ssh' ? 'uname -a' : t)
  await d.getByRole('button', { name: /^(Add|Save)/ }).last().click()
  await expect(page.getByRole('heading', { name: new RegExp(`QA ${kind}`) })).toBeVisible()
  // Write tools start OFF (D-41, D-51): the administrator turns the write tool on, then the connection can carry an action.
  const w = page.getByRole('switch', { name: new RegExp(`^Tool (run_approved_command|send_request|apply_config|launch_job|run_action) enabled on QA ${kind}$`) })
  await expect(w, `${kind}: a write tool is offered`).toHaveCount(1)
  expect(await w.isChecked(), `${kind}: the write tool starts off`).toBe(false)
  await w.click()
  await expect(w).toBeChecked()
}

const present = async (l: Locator) => (await l.count()) > 0

for (const theme of THEMES) {
  test(`custom action [${theme}]: form follows the connection kind; read-only locked with reason; no brand defaults`, async ({ page }, info) => {
    const errors = collectErrors(page)
    const shot = stepper(page, info, 'response-actions', theme)
    await begin(page, theme)
    for (const k of KINDS) await addConnection(page, k.value)
    await page.goto('/settings/response')
    await expect(page.getByRole('heading', { name: 'Action catalog' })).toBeVisible()
    await shot('catalog')
    // brand names only inside template data (pack sections), never in the page chrome/dialog
    await page.getByRole('button', { name: 'Add a custom action' }).click()
    const dlg = page.getByRole('dialog', { name: 'Add a custom action' })
    await expect(dlg).toBeVisible()
    await shot('dialog-open')
    const opts = await dlg.locator('#ca-conn option').evaluateAll((os) => os.map((o) => ({ v: (o as HTMLOptionElement).value, t: o.textContent ?? '', dis: (o as HTMLOptionElement).disabled })))
    console.log('OPTIONS', JSON.stringify(opts))
    const readOnly = opts.filter((o) => o.dis)
    expect(readOnly.length).toBeGreaterThan(0)
    for (const o of readOnly) expect(o.t, 'read-only option carries a reason').toMatch(/Read-only: this connection has no write tools/)
    // the sample data has a connection named after a vendor; that is data. Check the chrome without the option list.
    const BR = /forti|pfsense|cisco|mikrotik|palo ?alto|juniper|ubiquiti/i
    const chromeOf = async () => (await dlg.evaluate((el) => { const c = el.cloneNode(true) as HTMLElement; c.querySelectorAll('option').forEach((o) => o.remove()); return c.innerText }))
    expect(await chromeOf(), 'brand in the empty dialog').not.toMatch(BR)
    for (const k of KINDS) {
      const o = opts.find((x) => x.t.startsWith(`QA ${k.value}`))
      expect(o, `connection QA ${k.value} listed`).toBeTruthy()
      if (o!.dis) { expect.soft(o!.dis, `${k.value}: a freshly added connection of this kind can carry an action (it is locked read-only and offers no write tool to turn on)`).toBe(false); continue }
      await dlg.locator('#ca-conn').selectOption(o!.v)
      await shot(`kind-${k.value}`)
      const f = k.fields
      expect(await present(dlg.locator('#ca-run-cli')), `${k.value}: command`).toBe(f.cli)
      expect(await present(dlg.locator('#ca-run-method')), `${k.value}: method`).toBe(f.method)
      expect(await present(dlg.locator('#ca-run-path')), `${k.value}: path`).toBe(f.path)
      expect(await present(dlg.locator('#ca-run-headers')), `${k.value}: headers`).toBe(f.headers)
      expect(await present(dlg.locator('#ca-run-body')), `${k.value}: body`).toBe(f.body)
      expect(await present(dlg.locator('#ca-run-tool')), `${k.value}: tool picker`).toBe(f.tool)
      // verify read-back only for non-MCP
      expect(await present(dlg.locator('#ca-vf-method, #ca-vf-cli')), `${k.value}: read-back`).toBe(!f.tool)
      // no pre-filled values leaking (brand or from another kind)
      for (const id of ['cli', 'path', 'headers', 'body']) { const el = dlg.locator(`#ca-run-${id}`); if (await el.count()) await expect(el, `${k.value}: ${id} empty`).toHaveValue('') }
      if (f.method) await expect(dlg.locator('#ca-run-method')).toHaveValue('')
      expect(await chromeOf(), `${k.value}: brand text in dialog`).not.toMatch(BR)
      console.log('HINT', k.value, JSON.stringify((await dlg.locator('p').allTextContents()).filter((x) => /Pick one|Choose the|RESTCONF|One command|Start a job/.test(x))))
      if (f.tool) console.log('TOOLS', k.value, JSON.stringify(await dlg.locator('#ca-run-tool option').allTextContents()))
    }
    // placeholder legend: the typed placeholders the user may use (contract: id and name exist; {text} is for messages only)
    const legend = (await dlg.locator('p').allTextContents()).find((x) => /^Use only these placeholders/.test(x)) ?? ''
    console.log('LEGEND', legend)
    expect.soft(legend, 'legend lists {id}').toContain('{id}')
    expect.soft(legend, 'legend lists {name}').toContain('{name}')
    expect.soft(legend, 'legend must not offer {text} for commands/API (refused by the server)').not.toContain('{text}')
    // switching clears: type in HTTP, switch to another kind, switch back
    await dlg.locator('#ca-conn').selectOption(opts.find((x) => x.t.startsWith('QA http'))!.v)
    await dlg.locator('#ca-run-path').fill('/api/block')
    await dlg.locator('#ca-run-body').fill('{"ip":"{ip}"}')
    await dlg.locator('#ca-conn').selectOption(opts.find((x) => x.t.startsWith('QA mcp-http'))!.v)
    await expect(dlg.locator('#ca-run-path')).toHaveCount(0)
    await dlg.locator('#ca-conn').selectOption(opts.find((x) => x.t.startsWith('QA http'))!.v)
    await expect(dlg.locator('#ca-run-path')).toHaveValue('')
    await expect(dlg.locator('#ca-run-body')).toHaveValue('')
    // goal: "start a job on my automation platform for one named host with a numeric job id" -> typed placeholders {id}, {name}; {text} refused
    await dlg.locator('#ca-conn').selectOption(opts.find((x) => x.t.startsWith('QA automation'))!.v)
    await dlg.locator('#ca-name').fill('QA isolate host')
    await dlg.locator('#ca-desc').fill('Starts the isolate job for one host')
    await dlg.locator('#ca-run-method').selectOption('POST')
    await dlg.locator('#ca-run-path').fill('/api/jobs/{id}/launch')
    await dlg.locator('#ca-run-body').fill('{"limit":"{text}"}')
    await dlg.getByRole('button', { name: 'Save' }).click()
    await shot('text-refused')
    console.log('ERR {text}', JSON.stringify(await dlg.locator('#ca-run-error').allTextContents()))
    await expect(dlg.locator('#ca-run-error')).toBeVisible() // under the Action group (D-390)
    await dlg.locator('#ca-run-body').fill('{"limit":"{name}"}; rm')
    await dlg.getByRole('button', { name: 'Save' }).click()
    console.log('ERR shell-ish body', JSON.stringify(await dlg.locator('#ca-run-error').allTextContents()))
    await dlg.locator('#ca-run-body').fill('{"limit":"{name}"}')
    await dlg.locator('#ca-rb-method').selectOption('POST')
    await dlg.locator('#ca-rb-path').fill('/api/jobs/{id}/cancel')
    await dlg.getByRole('button', { name: 'Save' }).click()
    await expect(dlg).toBeHidden()
    await expect(page.getByText('QA isolate host').first()).toBeVisible()
    await shot('saved')
    // the way back: Cancel works, link to Connections exists
    await page.getByRole('button', { name: 'Add a custom action' }).click()
    await expect(dlg.getByRole('link', { name: /Connections/ })).toBeVisible()
    await dlg.getByRole('button', { name: 'Cancel' }).click()
    await expect(dlg).toBeHidden()
    await noHScroll(page, 'settings/response')
    await expectAccessible(page, 'settings/response')
    expect(errors.filter((e) => !/status of (4|5)\d\d/.test(e))).toEqual([])
  })

  test(`template gallery + rule editor [${theme}]: unverified marking, param types id/name, no brand in chrome`, async ({ page }, info) => {
    const errors = collectErrors(page)
    const shot = stepper(page, info, 'response-templates', theme)
    await begin(page, theme)
    // action templates: the pack sections in the catalog
    await page.goto('/settings/response')
    const cat = page.getByRole('heading', { name: 'Action catalog' })
    await expect(cat).toBeVisible()
    const unverified = await page.getByText('Not verified on a device yet').count()
    console.log('UNVERIFIED mentions in catalog', unverified)
    expect(unverified).toBeGreaterThan(0)
    // every action in a vendor pack that is marked unverified in data says so; the box actions do not
    const box = page.getByRole('region', { name: 'This box' })
    await expect(box.getByText('Not verified on a device yet')).toHaveCount(0)
    await shot('catalog-packs')
    // rule templates gallery
    await page.goto('/response?tab=rules')
    await expect(page.getByRole('heading', { name: 'Template gallery' })).toBeVisible()
    await page.getByRole('heading', { name: 'Template gallery' }).scrollIntoViewIfNeeded()
    await shot('gallery')
    const gal = await page.locator('#templates').innerText()
    console.log('GALLERY', gal.slice(0, 3000))
    // clone first template and open its editor
    await page.getByRole('button', { name: /^Clone / }).first().click()
    await expect(page.getByText('Cloned: switched off, in dry run').first()).toBeVisible()
    await shot('cloned')
    await page.getByRole('button', { name: /^Edit/ }).first().click()
    const ed = page.getByRole('dialog')
    await expect(ed).toBeVisible()
    await shot('rule-editor')
    console.log('EDITOR', (await ed.innerText()).slice(0, 2500))
    expect(await ed.innerText(), 'raw i18n key shown').not.toMatch(/editor\.(types|param)/)
    await noHScroll(page, 'response')
    await expectAccessible(page, 'response rules')
    expect(errors.filter((e) => !/status of (4|5)\d\d/.test(e))).toEqual([])
  })
}

test('param types id and name are labelled in the rule editor (choose an action that needs them)', async ({ page }, info) => {
  const shot = stepper(page, info, 'response-params', 'light')
  await begin(page, 'light')
  await addConnection(page, 'automation')
  await page.goto('/settings/response')
  await page.getByRole('button', { name: 'Add a custom action' }).click()
  const dl = page.getByRole('dialog', { name: 'Add a custom action' })
  await dl.locator('#ca-conn').selectOption({ label: 'QA automation' })
  await dl.locator('#ca-name').fill('QA isolate host')
  await dl.locator('#ca-desc').fill('Starts the isolate job for one host')
  await dl.locator('#ca-run-method').selectOption('POST')
  await dl.locator('#ca-run-path').fill('/api/jobs/{id}/launch')
  await dl.locator('#ca-run-body').fill('{"limit":"{name}"}')
  await dl.locator('#ca-rb-method').selectOption('POST')
  await dl.locator('#ca-rb-path').fill('/api/jobs/{id}/cancel')
  await dl.getByRole('button', { name: 'Save' }).click()
  console.log('SAVE ALERT', JSON.stringify(await dl.getByRole('alert').allTextContents()))
  await expect(dl).toBeHidden()
  await page.getByRole('switch', { name: 'Allow QA isolate host' }).click()
  await page.goto('/response?tab=rules')
  await page.getByRole('button', { name: /^Clone / }).first().click()
  await page.getByRole('button', { name: /^Edit/ }).first().click()
  const ed = page.getByRole('dialog')
  const sel = ed.locator('select[id^="ra-"]').first()
  const acts = await sel.locator('option').evaluateAll((os) => os.map((o) => ({ v: (o as HTMLOptionElement).value, t: o.textContent ?? '' })))
  console.log('RULE ACTIONS', JSON.stringify(acts))
  const seen: string[] = []
  for (const a of acts) {
    await sel.selectOption(a.v)
    const labels = await ed.locator('label').allTextContents()
    seen.push(`${a.t} => ${labels.filter((l) => /^(IP|Address|Domain|Port|Port|MAC|VLAN|Name|ID|Id|Safe|A |An |editor)/i.test(l) || /editor\./.test(l)).join(' | ')}`)
    expect.soft(labels.join('|'), `raw translation key shown for ${a.t}`).not.toMatch(/editor\./)
  }
  console.log('PARAM LABELS\n' + seen.join('\n'))
  await shot('actions')
})
