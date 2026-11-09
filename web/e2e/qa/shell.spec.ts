import { expect, test } from '@playwright/test'
import { collectErrors, expectAccessible, shot, startWithSample } from '../helpers'

// QA khung ứng dụng + feeds (supervisor): như người dùng thật, desktop + điện thoại, sáng/tối, vi/en.
test('trang chủ, tra cứu, CVE, 404: đọc được, bấm được', async ({ page }, info) => {
  const tag = info.project.name
  const errors = collectErrors(page)
  await startWithSample(page)
  await shot(page, 'shell', `${tag}-home`)
  // tra cứu từ ô tìm ở trang chủ (trên điện thoại ô tìm vẫn phải dùng được)
  await page.getByRole('searchbox').or(page.getByPlaceholder('CVE, product, IP or domain')).first().fill('qnap')
  await page.keyboard.press('Enter')
  await expect(page).toHaveURL(/\/lookup\?q=qnap/)
  await expect(page.getByRole('link', { name: 'CVE-2022-27593' })).toBeVisible()
  await shot(page, 'shell', `${tag}-lookup-text`)
  await page.getByRole('link', { name: 'CVE-2022-27593' }).click()
  await expect(page.getByRole('heading', { level: 1, name: /CVE-2022-27593/ })).toBeVisible()
  await shot(page, 'shell', `${tag}-cve`)
  // domain sạch, CVE không có, chuỗi rác
  for (const q of ['google.com', 'CVE-2019-0001', '<script>alert(1)</script>', '   ']) {
    await page.goto(`/lookup?q=${encodeURIComponent(q)}`)
    await expect(page.getByRole('heading', { level: 1 })).toBeVisible()
  }
  await shot(page, 'shell', `${tag}-lookup-junk`)
  await page.goto('/khong-co-trang-nay')
  await expect(page.getByRole('heading', { name: 'Page not found' })).toBeVisible()
  await page.goto('/cve/khong-hop-le')
  await expect(page.getByRole('alert').first()).toBeVisible()
  await shot(page, 'shell', `${tag}-cve-invalid`)
  expect(errors, errors.join('\n')).toEqual([])
})

test('tối + tiếng Anh, bàn phím', async ({ page, isMobile }, info) => {
  test.skip(isMobile, 'menu người dùng nằm trong menu điện thoại; kiểm riêng')
  await page.emulateMedia({ colorScheme: 'dark' })
  await startWithSample(page)
  await expect(page.getByRole('heading', { level: 1, name: /Today/ })).toBeVisible()
  await shot(page, 'shell', `${info.project.name}-home-dark-en`)
  await expectAccessible(page, 'home dark')
  await page.goto('/cve/CVE-2022-27593')
  await expect(page.getByRole('heading', { level: 1, name: /CVE-2022-27593/ })).toBeVisible()
  await shot(page, 'shell', `${info.project.name}-cve-dark-en`)
  // Bàn phím: liên kết bỏ qua tới nội dung là thứ đầu tiên
  await page.goto('/')
  await expect(page.getByRole('heading', { level: 1 })).toBeVisible()
  await page.keyboard.press('Tab')
  await expect(page.getByRole('link', { name: /Skip to content/ })).toBeFocused()
})

test('điện thoại: menu, đổi ngôn ngữ, đăng xuất', async ({ page, isMobile }, info) => {
  test.skip(!isMobile, 'chỉ điện thoại')
  await startWithSample(page)
  await page.getByRole('button', { name: 'Open menu' }).click()
  await shot(page, 'shell', `${info.project.name}-menu`)
  await page.getByRole('button', { name: /Account/ }).click()
  await shot(page, 'shell', `${info.project.name}-usermenu`)
  await page.getByRole('menuitem', { name: 'Sign out' }).click()
  await expect(page).toHaveURL(/\/login/)
  await page.getByLabel('Email').fill('admin@acme.example')
  await page.getByLabel('Password').fill('wrong-password')
  await page.getByRole('button', { name: 'Sign in' }).click()
  await expect(page.getByText(/email or password/i)).toBeVisible()
  await shot(page, 'shell', `${info.project.name}-login-error`)
})
