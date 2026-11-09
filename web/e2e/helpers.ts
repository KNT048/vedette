import { createRequire } from 'node:module'
import { expect, type Page } from '@playwright/test'

const require = createRequire(import.meta.url)
const AXE = require.resolve('axe-core/axe.min.js')

/** Xoá dữ liệu trình duyệt trên một trang không tự chuyển hướng (/login), tránh lỗi "execution context destroyed". */
async function resetStorage(page: Page) {
  await page.goto('/login')
  await page.waitForLoadState('domcontentloaded')
  await page.evaluate(() => localStorage.clear())
}

/** Mở trang lần đầu như người dùng mới: xoá dữ liệu, đi qua "Dùng dữ liệu mẫu". */
export async function startWithSample(page: Page) {
  await resetStorage(page)
  await page.goto('/')
  await expect(page).toHaveURL(/\/setup/)
  await page.getByRole('button', { name: 'Use sample data' }).click()
  await expect(page.getByRole('heading', { level: 1, name: /^Today/ })).toBeVisible()
}

/** Ghi lại lỗi console/trang để test khẳng định không có. */
export function collectErrors(page: Page) {
  const errors: string[] = []
  // Phản hồi 4xx của API là có chủ đích (chưa đăng nhập, không có, nhập sai…); trình duyệt tự ghi chúng thành lỗi tài nguyên.
  // Lỗi JS, 5xx và mọi lỗi khác vẫn bị bắt.
  page.on('console', (m) => { if (m.type() === 'error' && !/status of 4\d\d/.test(m.text())) errors.push(m.text()) })
  page.on('pageerror', (e) => errors.push(e.message))
  return errors
}

/** axe-core trên trình duyệt thật, có kiểm tương phản màu. Chỉ chặn mức serious/critical. */
export async function axeViolations(page: Page): Promise<string[]> {
  await page.addScriptTag({ path: AXE })
  return page.evaluate(async () => {
    // @ts-expect-error axe được nạp vào window bằng addScriptTag
    const r = await window.axe.run(document, { resultTypes: ['violations'] })
    return (r.violations as { id: string; impact: string; help: string; nodes: { target: string[] }[] }[])
      .filter((v) => v.impact === 'serious' || v.impact === 'critical')
      .map((v) => `${v.id} (${v.impact}): ${v.help} → ${v.nodes.slice(0, 3).map((n) => n.target.join(' ')).join(' | ')}`)
  })
}

export async function expectAccessible(page: Page, label: string) {
  await page.addScriptTag({ path: AXE })
  const violations = await page.evaluate(async () => {
    // @ts-expect-error axe được nạp vào window bằng addScriptTag
    const r = await window.axe.run(document, { resultTypes: ['violations'] })
    return (r.violations as { id: string; impact: string; help: string; nodes: { target: string[] }[] }[])
      .filter((v) => v.impact === 'serious' || v.impact === 'critical')
      .map((v) => `${v.id} (${v.impact}): ${v.help} → ${v.nodes.slice(0, 3).map((n) => n.target.join(' ')).join(' | ')}`)
  })
  expect(violations, `${label}\n${violations.join('\n')}`).toEqual([])
}

/** Cài sạch như người dùng thật lần đầu (không dữ liệu mẫu): điền bước 1 (tổ chức + quản trị); test tự đi tiếp các bước. */
export async function startClean(page: Page, org = 'Acme Test Ltd') {
  await resetStorage(page)
  await page.goto('/setup')
  await page.getByLabel('Organization name').fill(org)
  await page.getByLabel('Administrator name').fill('Alex Admin')
  await page.getByLabel('Sign-in email').fill('admin@acme.example')
  await page.getByLabel('Password', { exact: true }).fill('a-long-password-123')
  await page.getByLabel('Repeat password').fill('a-long-password-123')
}

/** Chụp màn hình để TỰ XEM bằng mắt (Read ảnh) — thư mục qa-shots/ không commit. */
export async function shot(page: Page, mod: string, name: string) {
  await page.screenshot({ path: `qa-shots/${mod}/${name}.png`, fullPage: true })
}
