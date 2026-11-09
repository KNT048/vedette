import { expect, test } from '@playwright/test'
import { axeViolations, collectErrors, expectAccessible, startWithSample } from './helpers'

// Mọi trang trong thanh bên + các trang chi tiết chính. Kiểm: có tiêu đề, không lỗi console, axe sạch (gồm tương phản).
const PAGES = [
  '/', '/lookup?q=185.220.101.47', '/cve/CVE-2022-27593', '/findings', '/findings/f-1', '/findings/f-2', '/incidents',
  '/devices', '/devices/a-nas02', '/devices/setup', '/exposure', '/scans', '/honeypot', '/logs', '/assistant', '/reports',
  '/settings/general', '/settings/modules', '/settings/channels', '/settings/ai', '/settings/siem', '/settings/users',
  '/settings/audit', '/settings/updates', '/settings/privacy', '/settings/mcp', '/settings/data', '/account', '/honeypot/hits/hit-seed-1', '/incidents/al-4',
]

test('first open: set up with sample data, then the home page', async ({ page, isMobile }) => {
  const errors = collectErrors(page)
  await startWithSample(page)
  // Phones get a list instead of a table (DataTable mobileRow)
  await expect(page.getByRole(isMobile ? 'list' : 'table', { name: 'Newly exploited' })).toBeVisible()
  expect(errors).toEqual([])
})

test('mọi trang mở được, không lỗi, truy cập được', async ({ page }) => {
  test.setTimeout(180_000)
  const errors = collectErrors(page)
  await startWithSample(page)
  const problems: string[] = []
  for (const path of PAGES) {
    await page.goto(path)
    await expect(page.getByRole('heading', { level: 1 }).first(), path).toBeVisible()
    await expect(page.getByRole('status').filter({ hasText: /^Loading$/ }), `${path} still loading`).toHaveCount(0, { timeout: 8000 })
    for (const v of await axeViolations(page)) problems.push(`${path}: ${v}`)
    const text = await page.locator('body').innerText()
    if (/[ăâđêôơưạảấầẩẫậắằẳẵặẹẻẽếềểễệỉịọỏốồổỗộớờởỡợụủứừửữựỳỵỷỹ]/i.test(text.replace(/Kiên/g, ''))) problems.push(`${path}: Vietnamese text on page (D-28)`)
  }
  expect(problems, problems.join('\n')).toEqual([])
  expect(errors).toEqual([])
})

test('người dùng làm việc trong GUI: khai thiết bị, xử lý phát hiện, đăng xuất và đăng nhập lại', async ({ page, isMobile }) => {
  test.skip(isMobile, 'menu tài khoản trên điện thoại được kiểm ở test riêng')
  await startWithSample(page)
  // "Tôi có" từ bảng "Tuần này" thêm thiết bị khai tay
  await page.getByRole('button', { name: 'I have this' }).first().click()
  await expect(page.getByText('Added to your devices').first()).toBeVisible()
  // Phát hiện xác nhận có hướng dẫn "BYN đã xác nhận" và đoạn cấu hình FortiGate
  await page.goto('/findings/f-1')
  await expect(page.getByText(/Confirmed by Vedette/).first()).toBeVisible()
  await expect(page.getByText(/192\.168\.10\.21/).first()).toBeVisible()
  // dữ liệu còn sau khi tải lại trang
  await page.reload()
  await expect(page.getByText(/Confirmed by Vedette/).first()).toBeVisible()
  // đăng xuất, đăng nhập bằng tài khoản chỉ xem
  await page.goto('/')
  await page.getByRole('button', { name: /Account/ }).first().click()
  await page.getByRole('menuitem', { name: 'Sign out' }).click()
  await expect(page).toHaveURL(/\/login/)
  await page.getByLabel('Email').fill('director@acme.example')
  await page.getByLabel('Password').fill('vedette-demo')
  await page.getByRole('button', { name: 'Sign in' }).click()
  await expect(page.getByRole('heading', { level: 1, name: /^Today/ })).toBeVisible()
  await expect(page.getByRole('button', { name: 'I have this' }).first()).toBeDisabled()
})

test('dark theme is readable and accessible', async ({ page, isMobile }) => {
  test.skip(isMobile, 'same as desktop')
  await startWithSample(page)
  await page.getByRole('button', { name: /Account/ }).first().click()
  await page.getByRole('menuitemradio', { name: 'Dark' }).click()
  await expect(page.locator('html')).toHaveAttribute('data-theme', 'dark')
  await expectAccessible(page, 'home dark')
})

test('điện thoại: mở menu, đi tới Thiết bị, bảng cuộn trong khung', async ({ page, isMobile }) => {
  test.skip(!isMobile, 'chỉ cho điện thoại')
  await startWithSample(page)
  await page.getByRole('button', { name: 'Open menu' }).click()
  await page.getByRole('link', { name: 'Devices' }).click()
  await expect(page.getByRole('heading', { level: 1 })).toBeVisible()
  const overflow = await page.evaluate(() => document.documentElement.scrollWidth - document.documentElement.clientWidth)
  expect(overflow, 'trang không được cuộn ngang').toBeLessThanOrEqual(1)
})
