import { defineConfig, devices } from '@playwright/test'

// QA khám phá trên server dev đang chạy (http://localhost:5173, HMR): agent sửa mã là thấy ngay.
// Chạy một file: pnpm exec playwright test -c playwright.qa.config.ts e2e/qa/<module>.spec.ts
export default defineConfig({
  testDir: './e2e',
  timeout: 60_000,
  expect: { timeout: 8_000 },
  workers: 2,
  reporter: [['list']],
  use: { baseURL: 'http://localhost:5173', locale: 'vi-VN', timezoneId: 'Asia/Ho_Chi_Minh', trace: 'retain-on-failure' },
  projects: [
    { name: 'desktop', use: { ...devices['Desktop Chrome'], viewport: { width: 1366, height: 860 } } },
    { name: 'mobile', use: { ...devices['Pixel 7'] } },
  ],
})
