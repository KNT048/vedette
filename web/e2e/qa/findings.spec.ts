// QA as a real user for the findings module (English-only UI): IT operator, director (viewer), first-time clean install.
// The list groups the open findings by device (and by fix); every CVE in it opens its own finding page.
// Independent spec that builds its own data; run: pnpm exec playwright test -c playwright.qa.config.ts e2e/qa/findings.spec.ts
import { expect, test, type Page } from '@playwright/test'
import { collectErrors, expectAccessible, shot } from '../helpers'

const DB = 'vedette-mock-db-v4'
const DIACRITICS = /[àáảãạăằắẳẵặâầấẩẫậèéẻẽẹêềếểễệìíỉĩịòóỏõọôồốổỗộơờớởỡợùúủũụưừứửữựỳýỷỹỵđ]/i
// Sample findings the steps use: the NAS has the CVE with a confirmed Vedette recommendation; WordPress and Windows Server have none.
const NAS = '/findings/fv-nas02-ps-1' // NAS-PHOTOS, CVE-2022-27593, exploited in the wild, confirmed by a safe check
const WP = '/findings/fv-web01-wp-1' // WEB01, CVE-2026-119977, public exploit available
const WIN = '/findings/fv-srvad-win-1' // SRV-AD, CVE-2025-29824, exploited in the wild

/** First-time setup with sample data (a local copy of the helper: English labels). */
async function sample(page: Page) {
  await page.goto('/setup')
  await page.evaluate(() => localStorage.clear())
  await page.goto('/setup')
  await expect(page).toHaveURL(/\/setup/)
  await page.getByRole('checkbox', { name: 'I have read, understood and agree to the terms of use' }).click() // The terms of use come first
  await page.getByRole('button', { name: 'Continue' }).click()
  await page.getByRole('button', { name: 'Use sample data' }).click()
  await expect(page).not.toHaveURL(/\/setup/)
  await expect(page.getByRole('heading', { level: 1 }).first()).toBeVisible()
}
/** Clean install: create the organisation + admin, one network range, do NOT mark the scan commitment, skip the channel. */
async function clean(page: Page) {
  await page.goto('/setup')
  await page.evaluate(() => localStorage.clear())
  await page.goto('/setup')
  await page.getByRole('checkbox', { name: 'I have read, understood and agree to the terms of use' }).click() // The terms of use come first
  await page.getByRole('button', { name: 'Continue' }).click()
  await page.getByLabel('Setup code', { exact: true }).fill('setup-code-demo') // The code the mock accepts
  await page.getByLabel('Organization name', { exact: true }).fill('Test Company')
  await page.getByLabel('Administrator name', { exact: true }).fill('Test Admin')
  await page.getByLabel('Sign-in email', { exact: true }).fill('admin@test.example')
  await page.getByLabel('Password', { exact: true }).fill('a-long-test-password-123')
  await page.getByLabel('Repeat password', { exact: true }).fill('a-long-test-password-123')
  await page.getByRole('button', { name: 'Continue' }).click()
  await page.getByLabel(/^Range 1/).fill('10.142.0.0/24')
  await page.getByRole('button', { name: 'Continue' }).click()
  await page.getByRole('button', { name: 'Finish setup' }).click()
  await expect(page).not.toHaveURL(/\/setup/)
}
/** Edit the mock store in the browser directly (simulates a system state), then reload. */
async function patchDb(page: Page, patch: Record<string, unknown>) {
  await page.evaluate(([k, p]) => {
    const db = JSON.parse(localStorage.getItem(k as string) ?? '{}')
    Object.assign(db, p)
    localStorage.setItem(k as string, JSON.stringify(db))
  }, [DB, patch] as const)
  await page.reload()
}
/** Switch the session to another account before every page load: a late write of the page already open cannot put the old one back. */
async function loginAs(page: Page, userId: 'u-admin' | 'u-op' | 'u-view') {
  await page.addInitScript(([k, u]) => {
    try {
      const raw = localStorage.getItem(k)
      if (raw) { const db = JSON.parse(raw); db.core_session = { userId: u }; localStorage.setItem(k, JSON.stringify(db)) }
    } catch { /* no storage: the page keeps its session */ }
  }, [DB, userId] as const)
  await page.reload()
}
async function theme(page: Page, t: 'light' | 'dark') {
  await page.evaluate((v) => localStorage.setItem('vedette-theme', v), t)
  await page.reload()
}
const noHScroll = async (page: Page, where: string) =>
  expect(await page.evaluate(() => document.documentElement.scrollWidth - document.documentElement.clientWidth), `${where}: horizontal scroll`).toBeLessThanOrEqual(1)
const english = async (page: Page, where: string) => {
  const text = await page.evaluate(() => document.body.innerText)
  expect(text.match(DIACRITICS)?.[0] ?? null, `${where}: Vietnamese text left in the UI`).toBeNull()
}
/** The headline count of the list ("16 open findings"). */
async function openCount(page: Page) {
  await page.goto('/findings')
  const h = page.getByRole('heading', { level: 1 })
  await expect(h).toHaveText(/^\d+ open findings?$/)
  return Number((await h.innerText()).split(' ')[0])
}

test.describe('findings: IT operator', () => {
  test.beforeEach(async ({ page }) => { await sample(page); await loginAs(page, 'u-op') })

  test('list: headline matches the rows, status filter, By fix, Handled, an older ?cve= link, open a CVE, Back, reload', async ({ page }) => {
    const errors = collectErrors(page)
    const open = await openCount(page)
    const panel = page.getByRole('tabpanel', { name: 'By device' })
    const summary = panel.getByRole('status').filter({ hasText: /open findings? on \d+ devices?/ })
    const devices = panel.getByRole('article') // one card per device: table rows on a wide screen, a list on a phone
    // The headline, the line above the list and the device rows tell the same numbers
    await expect(summary).toHaveText(new RegExp(`^${open} open findings? on \\d+ devices?$`))
    const onDevices = Number((await summary.innerText()).match(/on (\d+) device/)![1])
    await expect(devices).toHaveCount(onDevices)

    // One status: the number on the toggle is what the list then holds; the URL keeps it
    const exploited = panel.getByRole('button', { name: /^Exploited in the wild \d+$/ })
    const n = Number((await exploited.innerText()).match(/\d+$/)![0])
    await exploited.click()
    await expect(exploited).toHaveAttribute('aria-pressed', 'true')
    await expect(page).toHaveURL(/status=exploited/)
    await expect(summary).toHaveText(new RegExp(`^${n} open findings? on`))
    await panel.getByRole('button', { name: 'Show all statuses' }).click()
    await expect(summary).toHaveText(new RegExp(`^${open} open findings? on`))

    // By fix and Handled are tabs of the same screen
    await page.getByRole('tab', { name: 'By fix' }).click()
    await expect(page.getByRole('tabpanel', { name: 'By fix' }).getByRole('button', { name: /^Update Photo Station to 6\.0\.22 1 device, 1 finding$/ })).toBeVisible()
    await page.getByRole('tab', { name: 'Handled' }).click()
    await expect(page.getByRole('tabpanel', { name: 'Handled' }).getByText('CVE-2025-21333').first()).toBeVisible()

    // An older link to one CVE opens By device searched for it: only the NAS is left
    await page.goto('/findings?cve=cve-2022-27593')
    await expect(page).toHaveURL(/tab=device/)
    await expect(panel.getByRole('searchbox', { name: 'Search devices, software or CVEs' })).toHaveValue('CVE-2022-27593')
    await expect(devices).toHaveCount(1)
    await expect(devices.first()).toContainText('NAS-PHOTOS')
    await panel.getByRole('searchbox', { name: 'Search devices, software or CVEs' }).fill('')
    await expect(devices).toHaveCount(onDevices)

    // Every CVE in the list opens its own finding; Back returns to the list; the page survives a reload
    await panel.getByRole('link', { name: 'CVE-2022-27593' }).click()
    await expect(page).toHaveURL(new RegExp(`${NAS}$`))
    await expect(page.getByRole('heading', { level: 1 })).toContainText('NAS-PHOTOS')
    await page.goBack()
    await expect(page).toHaveURL(/\/findings(\?|$)/)
    await page.goto(NAS)
    await page.reload()
    await expect(page.getByRole('heading', { level: 1 })).toHaveText('NAS-PHOTOS has a confirmed vulnerability (CVE-2022-27593) that is being exploited in the wild')
    await english(page, 'NAS finding')
    expect(errors).toEqual([])
  })

  test('status change: note required for false positive, Esc/Cancel, kept text, history, reopen, persists after reload, the list follows', async ({ page }) => {
    const before = await openCount(page)
    await page.goto(WP)
    await page.getByRole('button', { name: 'Mark as handled' }).click()
    const dlg = page.getByRole('dialog')
    await expect(dlg).toBeVisible()
    await expect(dlg).toContainText('Acts on 1 finding (1 CVE) on one device: WEB01.')
    await page.keyboard.press('Escape')
    await expect(dlg).toHaveCount(0)
    await page.getByRole('button', { name: 'Mark as handled' }).click()
    await dlg.getByRole('radio', { name: /False positive/ }).click()
    await dlg.getByRole('button', { name: 'Mark 1 finding' }).click()
    await expect(dlg.getByText(/at least 3 characters/)).toBeVisible()
    await dlg.getByLabel(/Note/).fill('ab')
    await dlg.getByRole('button', { name: 'Mark 1 finding' }).click()
    await expect(dlg.getByText(/at least 3 characters/)).toBeVisible()
    await expect(dlg.getByLabel(/Note/)).toHaveValue('ab') // the typed text is kept
    await dlg.getByLabel(/Note/).fill('WordPress already updated, checked by hand')
    await dlg.getByRole('button', { name: 'Mark 1 finding' }).click()
    await expect(dlg).toHaveCount(0)
    await expect(page.getByRole('heading', { level: 1 })).toHaveText('WEB01: CVE-2026-119977 marked as false positive')
    await expect(page.getByTestId('closed-notice').getByText('WordPress already updated, checked by hand')).toBeVisible()
    await expect(page.getByRole('region', { name: 'History' }).getByText('WordPress already updated, checked by hand')).toBeVisible()
    await page.reload()
    await expect(page.getByRole('heading', { level: 1 })).toContainText('false positive')
    expect(await openCount(page)).toBe(before - 1)
    await page.getByRole('tab', { name: 'Handled' }).click()
    await expect(page.getByRole('tabpanel', { name: 'Handled' }).getByText('CVE-2026-119977').first()).toBeVisible()
    await page.goto(WP)
    await page.getByRole('button', { name: 'Reopen finding' }).click()
    await expect(page.getByRole('heading', { level: 1 })).toHaveText('WEB01 has a confirmed vulnerability (CVE-2026-119977) with a public exploit available')
    await page.getByRole('button', { name: 'Mark as handled' }).click()
    await dlg.getByRole('button', { name: 'Mark 1 finding' }).click() // Patched is the default
    await expect(page.getByRole('heading', { level: 1 })).toHaveText('WEB01: CVE-2026-119977 is patched')
  })

  test('the NAS finding: recommendation confirmed by Vedette maintainers, real NAS IP, switch firewall vendor, "Applied" writes the log', async ({ page }) => {
    await page.goto(NAS)
    await expect(page.getByText('Confirmed by Vedette maintainers', { exact: true }).first()).toBeVisible()
    await expect(page.getByText(/Photo Station 6\.1\.2/).first()).toBeVisible()
    await expect(page.getByText('show firewall vip | grep -f 192.168.10.21')).toBeVisible()
    await expect(page.locator('body')).not.toContainText('{IP}')
    await expect(page.locator('body')).not.toContainText('<IP-NAS>')
    await page.getByRole('button', { name: /MikroTik/ }).click()
    await expect(page.getByText(/dst-address=192\.168\.10\.21/).first()).toBeVisible()
    await page.getByRole('button', { name: 'Applied', exact: true }).last().click()
    await expect(page.getByText(/Recorded as applied by it@acme.example/)).toBeVisible()
    await expect(page.getByText('Applied: MikroTik configuration')).toBeVisible()
    await page.reload()
    await expect(page.getByText('Applied: MikroTik configuration')).toBeVisible()
    await expect(page.getByText('Files with a .deadbolt extension')).toBeVisible()
    await expect(page.getByText(/grep -i deadbolt/).first()).toBeVisible()
    await english(page, 'NAS recommendation')
  })

  test('WordPress has no confirmed recommendation: says so, "Ask my AI" gives a labelled answer that survives reload; explain', async ({ page }) => {
    await page.goto(WP)
    await expect(page.getByText('No confirmed recommendation yet')).toBeVisible()
    await page.getByRole('button', { name: 'Ask my AI', exact: true }).click()
    await expect(page.getByText(/AI-generated/).locator('visible=true').first()).toBeVisible() // the no-pack note's "AI-generated" mention is behind its ⓘ; the label on the answer must show
    await page.getByRole('button', { name: 'Explain', exact: true }).click()
    await expect(page.getByRole('button', { name: /^(Explain|Ask my AI) again$/ })).toHaveCount(2)
    await page.reload()
    await expect(page.getByRole('button', { name: /^(Explain|Ask my AI) again$/ })).toHaveCount(2)
    await english(page, 'WordPress AI output')
  })

  test('AI off or not configured: buttons locked with the reason and a way to Settings, no errors', async ({ page }) => {
    const errors = collectErrors(page)
    await patchDb(page, { ai_config: { configured: false, provider: 'anthropic', base_url: 'https://api.anthropic.com', model: 'claude-haiku-5-5', key_last4: '', tier: 'med', monthly_budget: 60000, redact_pii: true } })
    await page.goto(WIN)
    await expect(page.getByRole('button', { name: 'Ask my AI', exact: true })).toBeDisabled()
    await expect(page.getByRole('button', { name: 'Explain', exact: true })).toBeDisabled()
    await expect(page.getByText('The AI assistant is off, or no AI profile is assigned to this job.').first()).toBeVisible()
    await expect(page.getByRole('link', { name: 'Open AI assistant settings' }).first()).toHaveAttribute('href', '/settings/ai#ai-profiles') // the exact place
    expect(errors).toEqual([])
  })

  test('links: device, CVE page, rescan; the device page lists its findings; a missing finding says so', async ({ page }) => {
    await page.goto(NAS)
    await expect(page.getByRole('link', { name: 'Rescan this device' })).toHaveAttribute('href', '/devices/a-nas02')
    await expect(page.getByRole('region', { name: 'Device' }).getByRole('link', { name: 'NAS-PHOTOS' })).toHaveAttribute('href', '/devices/a-nas02')
    await page.getByRole('link', { name: /Open CVE-2022-27593 page/ }).click()
    await expect(page).toHaveURL(/\/cve\/CVE-2022-27593/)
    await page.goto('/devices/a-nas02?tab=findings')
    await page.getByRole('tabpanel').getByRole('link', { name: 'CVE-2022-27593' }).click()
    await expect(page).toHaveURL(new RegExp(`${NAS}$`))
    await expect(page.getByRole('heading', { level: 1 })).toContainText('NAS-PHOTOS')
    await page.goto('/findings/does-not-exist')
    await expect(page.getByText(/No such finding/)).toBeVisible()
    await expect(page.getByRole('navigation', { name: 'Breadcrumb' }).getByRole('link', { name: 'Findings' })).toBeVisible() // the parent in the breadcrumb
  })

  test('keyboard: dialog keeps focus, Esc closes it and returns focus to the button', async ({ page }) => {
    await page.goto(WP)
    const btn = page.getByRole('button', { name: 'Mark as handled' })
    await expect(page.getByRole('heading', { level: 1 })).toContainText('WEB01') // the page has settled before the keyboard starts
    await btn.focus()
    await page.keyboard.press('Enter')
    await expect(page.getByRole('dialog')).toBeVisible()
    for (let i = 0; i < 12; i++) await page.keyboard.press('Tab')
    expect(await page.evaluate(() => !!document.activeElement?.closest('[role="dialog"]')), 'focus left the dialog').toBe(true)
    await page.keyboard.press('Escape')
    await expect(page.getByRole('dialog')).toHaveCount(0)
    await expect(btn).toBeFocused()
  })
})

test.describe('findings: director (viewer)', () => {
  test('can read; every write button is locked with a reason', async ({ page }) => {
    await sample(page)
    await loginAs(page, 'u-view')
    await page.goto(NAS)
    const mark = page.getByRole('button', { name: 'Mark as handled' })
    await expect(mark).toBeDisabled()
    await expect(mark).toHaveAttribute('title', /Operator/)
    const applied = page.getByRole('button', { name: 'Applied', exact: true })
    await expect(applied.first()).toBeVisible()
    for (const b of await applied.all()) await expect(b).toBeDisabled()
    await page.goto(WP)
    await expect(page.getByRole('button', { name: 'Ask my AI', exact: true })).toBeDisabled()
    await expect(page.getByText(/Operator/).first()).toBeVisible()
    await page.goto('/findings')
    for (const b of await page.getByRole('button', { name: /^Mark (these )?as handled: / }).all()) await expect(b).toBeDisabled()
  })
})

test.describe('findings: clean install', () => {
  test('no sample findings: the empty screen says what to do first; a sample finding link says it does not exist', async ({ page }) => {
    const errors = collectErrors(page)
    await clean(page)
    await page.goto('/findings')
    await expect(page.locator('header:has(h1)').first()).toContainText('No open findings')
    await expect(page.locator('body')).not.toContainText('NAS')
    await expect(page.getByRole('link', { name: 'Open Devices' }).first()).toHaveAttribute('href', '/devices')
    await expect(page.getByRole('link', { name: 'Open Settings, Scanning' }).first()).toHaveAttribute('href', '/settings/scanning')
    await page.getByRole('tab', { name: 'Handled' }).click()
    await expect(page.locator('body')).not.toContainText('CVE-2025-21333')
    await english(page, 'clean findings')
    await page.goto(NAS)
    await expect(page.getByText(/No such finding/)).toBeVisible()
    expect(errors).toEqual([])
  })
})

test.describe('findings: screenshots and accessibility', () => {
  for (const t of ['light', 'dark'] as const) {
    test(`screens in ${t}`, async ({ page }, info) => {
      test.setTimeout(120_000)
      const errors = collectErrors(page)
      await sample(page)
      await theme(page, t)
      const tag = `${info.project.name}-${t}`
      for (const [path, name] of [['/findings', 'list'], ['/findings?tab=fix', 'by-fix'], [NAS, 'nas'], [WP, 'wordpress'], ['/devices/a-nas02?tab=findings', 'device']] as const) {
        await page.goto(path)
        await expect(page.getByRole('heading', { level: 1 }).first()).toBeVisible()
        await expect(page.getByRole('status').filter({ hasText: /^Loading$/ })).toHaveCount(0)
        await shot(page, 'findings', `${name}-${tag}`)
        await noHScroll(page, `${path} ${tag}`)
        await english(page, `${path} ${tag}`)
        await expectAccessible(page, `${path} ${tag}`)
      }
      await page.goto(WP)
      await page.getByRole('button', { name: 'Mark as handled' }).click()
      await expect(page.getByRole('dialog')).toBeVisible()
      await shot(page, 'findings', `dialog-${tag}`)
      await expectAccessible(page, `dialog ${tag}`)
      expect(errors).toEqual([])
    })
  }
})
