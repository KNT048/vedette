import { createRequire } from 'node:module'
import { expect, type Page } from '@playwright/test'

const require = createRequire(import.meta.url)
const AXE = require.resolve('axe-core/axe.min.js')

/** Clear browser data on a page that does not redirect by itself (/login), avoiding the "execution context destroyed" error. */
async function resetStorage(page: Page) {
  await page.goto('/login')
  await page.waitForLoadState('domcontentloaded')
  await page.evaluate(() => localStorage.clear())
}

/** Open the first page as a new user: clear data, go through "Use sample data". */
export async function startWithSample(page: Page) {
  await resetStorage(page)
  await page.goto('/')
  await expect(page).toHaveURL(/\/setup/)
  await page.getByRole('checkbox', { name: 'I have read, understood and agree to the terms of use' }).click() // The terms of use come first
  await page.getByRole('button', { name: 'Continue' }).click()
  await page.getByRole('button', { name: 'Use sample data' }).click()
  await expect(page.getByRole('heading', { level: 1, name: /^Today/ })).toBeVisible()
}

/** Record console and page errors so a test can assert there are none. */
export function collectErrors(page: Page) {
  const errors: string[] = []
  // 4xx API responses are intentional (not signed in, not found, wrong input...); the browser logs them as resource errors by itself.
  // JS errors, 5xx and every other error are still caught.
  page.on('console', (m) => { if (m.type() === 'error' && !/status of 4\d\d/.test(m.text())) errors.push(m.text()) })
  page.on('pageerror', (e) => errors.push(e.message))
  return errors
}

/** axe-core in a real browser, with the colour contrast check. Only serious/critical findings block. */
export async function axeViolations(page: Page): Promise<string[]> {
  await page.addScriptTag({ path: AXE })
  return page.evaluate(async () => {
    // @ts-expect-error axe is loaded into window with addScriptTag
    const r = await window.axe.run(document, { resultTypes: ['violations'] })
    return (r.violations as { id: string; impact: string; help: string; nodes: { target: string[] }[] }[])
      .filter((v) => v.impact === 'serious' || v.impact === 'critical')
      .map((v) => `${v.id} (${v.impact}): ${v.help} → ${v.nodes.slice(0, 3).map((n) => n.target.join(' ')).join(' | ')}`)
  })
}

export async function expectAccessible(page: Page, label: string) {
  await page.addScriptTag({ path: AXE })
  const violations = await page.evaluate(async () => {
    // @ts-expect-error axe is loaded into window with addScriptTag
    const r = await window.axe.run(document, { resultTypes: ['violations'] })
    return (r.violations as { id: string; impact: string; help: string; nodes: { target: string[] }[] }[])
      .filter((v) => v.impact === 'serious' || v.impact === 'critical')
      .map((v) => `${v.id} (${v.impact}): ${v.help} → ${v.nodes.slice(0, 3).map((n) => n.target.join(' ')).join(' | ')}`)
  })
  expect(violations, `${label}\n${violations.join('\n')}`).toEqual([])
}

/** Clean install the way a real first user does it (no sample data): fill step 1 (organisation + admin); the test continues through the other steps itself. */
export async function startClean(page: Page, org = 'Acme Test Ltd') {
  await resetStorage(page)
  await page.goto('/setup')
  await page.getByRole('checkbox', { name: 'I have read, understood and agree to the terms of use' }).click() // The terms of use come first
  await page.getByRole('button', { name: 'Continue' }).click()
  await page.getByLabel('Setup code', { exact: true }).fill('setup-code-demo') // The code the mock accepts
  await page.getByLabel('Organization name', { exact: true }).fill(org)
  await page.getByLabel('Administrator name', { exact: true }).fill('Alex Admin')
  await page.getByLabel('Sign-in email', { exact: true }).fill('admin@acme.example')
  await page.getByLabel('Password', { exact: true }).fill('a-long-password-123')
  await page.getByLabel('Repeat password', { exact: true }).fill('a-long-password-123')
}

/** Take a screenshot to look at by eye; the qa-shots/ folder is not committed. */
export async function shot(page: Page, mod: string, name: string) {
  await page.screenshot({ path: `qa-shots/${mod}/${name}.png`, fullPage: true })
}

/** A setup bundle turns on v1 modules only. A spec that needs a preview module turns it on as a
 *  customer does, from its own row in Settings → Modules (names as listed there, e.g. 'Vulnerability scan', 'Internal traps',
 *  'Logs', 'AI assistant', 'Reports'); a dependency dialog is accepted. */
export async function turnOnModules(page: Page, names: string[]) {
  await page.goto('/settings/modules')
  for (const name of names) {
    const sw = page.getByRole('switch', { name: new RegExp(`^Turn (on|off) module ${name}$`) })
    await expect(sw).toBeVisible()
    if (await sw.isChecked()) continue
    await sw.click()
    const deps = page.getByRole('dialog', { name: 'Turn on the required modules too?' })
    if (await deps.isVisible().catch(() => false)) await deps.getByRole('button', { name: 'Turn on together' }).click()
    await expect(sw).toBeChecked()
  }
}

/** Every preview module (scan, honeypot, logs, ai, reports): what the mid-size bundle used to turn on. */
export const PREVIEW_NAMES = ['Vulnerability scan', 'Internal traps', 'Logs', 'AI assistant', 'Reports']
