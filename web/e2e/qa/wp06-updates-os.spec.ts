import { expect, test } from '@playwright/test'
import { collectErrors, expectAccessible } from '../helpers'
import { begin, noHScroll, stepper, THEMES } from './wp06-shared'

// WP-06 independent check, area 8: "As the admin I update the operating system of the box and want to know what does it."
// Settings -> Updates -> Operating system: the privileged helper is named `vedette-host` (D-55), never `vedette-updater`.
for (const theme of THEMES) {
  test(`updates OS [${theme}]: helper called vedette-host everywhere, never vedette-updater`, async ({ page }, info) => {
    const errors = collectErrors(page)
    const shot = stepper(page, info, 'updates-os', theme)
    await begin(page, theme)
    await page.goto('/settings/updates')
    await expect(page.getByRole('heading', { level: 1 })).toBeVisible()
    await shot('updates')
    const osHeading = page.getByRole('heading', { name: /Operating system/i }).first()
    await osHeading.scrollIntoViewIfNeeded()
    await shot('os-section')
    let text = await page.locator('main').innerText()
    expect(text, 'helper named in the OS section').toMatch(/vedette-host/)
    expect(text).not.toMatch(/vedette-updater|updater/i)
    // run an install: the run log lines come from vedette-host
    const install = page.getByRole('button', { name: /Install (security|all|\d)/i }).first()
    console.log('INSTALL BUTTONS', JSON.stringify(await page.getByRole('button', { name: /Install/i }).allInnerTexts()))
    if (await install.count()) {
      await install.click()
      const dlg = page.getByRole('dialog')
      if (await dlg.count()) {
        await shot('install-confirm')
        console.log('CONFIRM', await dlg.innerText())
        expect(await dlg.innerText()).not.toMatch(/updater/i)
        const go = dlg.getByRole('button', { name: /Install|Start|Confirm|Run/i }).last()
        await go.click()
      }
      await page.waitForTimeout(2500)
      await shot('install-running')
      text = await page.locator('main').innerText()
      console.log('AFTER INSTALL', text.slice(text.indexOf('Operating system'), text.indexOf('Operating system') + 1800))
      expect(text).not.toMatch(/updater/i)
    }
    // other places that talk about the helper: Box network, Privacy (flow 6)
    for (const p of ['/settings/network', '/settings/privacy', '/settings/general', '/settings/data']) {
      await page.goto(p)
      await expect(page.getByRole('heading', { level: 1 }).first()).toBeVisible()
      expect(await page.locator('main').innerText(), `${p}`).not.toMatch(/vedette-updater|\bupdater\b/i)
    }
    await page.goto('/settings/network')
    await shot('network')
    await expect(page.getByText(/applied by vedette-host/), 'Box network names the helper').toBeVisible()
    expect(await page.locator('main').innerText()).not.toMatch(/updater/i)
    await noHScroll(page, 'network')
    await expectAccessible(page, 'box network')
    expect(errors.filter((e) => !/status of (4|5)\d\d/.test(e))).toEqual([])
  })
}
