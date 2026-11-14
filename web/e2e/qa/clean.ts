import { expect, type Page } from '@playwright/test'

/** Open the app as a new user who picks the sample data. */
export async function sampleStart(page: Page) {
  await page.goto('/')
  await page.evaluate(() => localStorage.clear())
  await page.goto('/')
  await expect(page).toHaveURL(/\/setup/)
  await page.getByRole('checkbox', { name: 'I have read, understood and agree to the terms of use' }).click() // D-544: the terms of use come first
  await page.getByRole('button', { name: 'Continue' }).click()
  await page.getByRole('button', { name: 'Use sample data' }).click()
  await expect(page.getByRole('heading', { level: 1 }).first()).toBeVisible()
}

/** Finish the first-run setup as a real user (no sample data), bundle "Mid-size business" (has external surface and traps). */
export async function finishClean(page: Page) {
  await page.goto('/')
  await page.evaluate(() => localStorage.clear())
  await page.goto('/setup')
  await page.getByRole('checkbox', { name: 'I have read, understood and agree to the terms of use' }).click() // D-544: the terms of use come first
  await page.getByRole('button', { name: 'Continue' }).click()
  await page.getByLabel('Setup code').fill('setup-code-demo') // D-75: the code the mock accepts
  await page.getByLabel('Organization name').fill('Test Company')
  await page.getByLabel('Administrator name').fill('Alex Admin')
  await page.getByLabel('Sign-in email').fill('admin@testco.example')
  await page.getByLabel('Password', { exact: true }).fill('a-very-long-password-123')
  await page.getByLabel('Repeat password').fill('a-very-long-password-123')
  await page.getByRole('button', { name: 'Continue' }).click()
  await page.getByRole('textbox', { name: 'Range 1' }).fill('192.168.10.0/24')
  await page.getByRole('button', { name: 'Continue' }).click()
  await page.getByRole('radio', { name: /Mid-size business/ }).click()
  await page.getByRole('button', { name: 'Finish setup' }).click()
  await expect(page.getByRole('heading', { level: 1 }).first()).toBeVisible()
}

/** The IP the box currently egresses through (mock-only control, see features/exposure/README.md). */
export const setEgress = (page: Page, ip: string | null) =>
  page.evaluate((v) => { if (v) localStorage.setItem('vedette-mock-egress', v); else localStorage.removeItem('vedette-mock-egress') }, ip)

export const DIACRITICS = /[ăâđêôơưàáạảãèéẹẻẽìíịỉĩòóọỏõùúụủũỳýỵỷỹ]/i
