// The Devices list fits a laptop window: no sideways scroll in the table at 1280, 1366 and 1440 px, with long names, maker, model,
// OS and several sources. Run: pnpm exec playwright test -c playwright.qa.config.ts e2e/qa/devices-fit.spec.ts --project=desktop
import { expect, test, type Page } from '@playwright/test'
import { sampleStart } from './clean'

const DB = 'vedette-mock-db-v4'
const day = (n: number) => new Date(Date.now() - n * 864e5).toISOString()
const obs = (value: string, source: string, confidence = 0.9) => ({ value, source, confidence, seen_at: day(0) })
const long = (i: number) => ({
  id: `a-long${i}`, site: 'hq', ip: `192.168.30.${200 + i}`, mac: `3c:52:82:1a:00:0${i}`, kind: 'server',
  hostname: `finance-department-file-server-building-two-rack-${i}.corp.example.internal`,
  vendor: obs('Hewlett Packard Enterprise', 'snmp'), model: obs('ProLiant DL380 Gen10 Plus Rack Server', 'snmp'),
  os: obs('Windows Server 2025 Standard Evaluation 10.0.26100.1742', 'osquery'),
  software: [], services: [], first_seen: day(40), last_seen: day(i), approved: true, fragile: i === 1, origin: 'discovered',
})

async function seed(page: Page) {
  await sampleStart(page)
  await page.goto('/devices')
  await expect(page.getByRole('heading', { level: 1 })).toHaveText(/^\d+ devices?,/)
  await page.evaluate(([k, rows]) => {
    const db = JSON.parse(localStorage.getItem(k as string) ?? '{}')
    db.inv_assets = [...(db.inv_assets ?? []), ...(rows as unknown[])]
    localStorage.setItem(k as string, JSON.stringify(db))
  }, [DB, [1, 2, 3].map(long)] as const)
  await page.reload()
  await expect(page.getByRole('table')).toBeVisible()
}

for (const width of [1280, 1366, 1440]) {
  test(`devices table fits without sideways scroll at ${width}`, async ({ page }, info) => {
    test.skip(info.project.name !== 'desktop')
    await page.setViewportSize({ width, height: 800 })
    await seed(page)
    const table = page.getByRole('table', { name: 'Device list' })
    await expect(table.getByRole('link', { name: /finance-department-file-server/ }).first()).toBeVisible()
    await table.getByRole('link', { name: /finance-department-file-server/ }).first().scrollIntoViewIfNeeded()
    await page.mouse.wheel(0, 200)
    if (process.env.SHOTS) await page.screenshot({ path: `${process.env.SHOTS}/${width}.png` })
    const box = await table.locator('xpath=..').evaluate((el) => ({ sw: el.scrollWidth, cw: el.clientWidth }))
    expect(box.sw - box.cw, 'table container scrolls sideways').toBeLessThanOrEqual(1)
    expect(await page.evaluate(() => document.documentElement.scrollWidth - document.documentElement.clientWidth)).toBeLessThanOrEqual(1)
    for (const h of ['Name', 'Risk', 'IP', 'Type', 'Sources', 'Last seen']) await expect(table.getByRole('columnheader', { name: h })).toBeVisible()
  })
}
