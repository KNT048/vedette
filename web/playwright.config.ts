import { defineConfig, devices } from '@playwright/test'

// E2E chạy trên BẢN BUILD THẬT (vite preview) với mock API trong service worker — đúng thứ người dùng mở.
export default defineConfig({
  testDir: './e2e',
  timeout: 30_000,
  expect: { timeout: 8_000 },
  fullyParallel: true,
  retries: 0,
  reporter: [['list']],
  use: { baseURL: 'http://localhost:4173', locale: 'vi-VN', timezoneId: 'Asia/Ho_Chi_Minh', trace: 'retain-on-failure' },
  projects: [
    { name: 'desktop', use: { ...devices['Desktop Chrome'], viewport: { width: 1366, height: 860 } } },
    { name: 'mobile', use: { ...devices['Pixel 7'] } },
  ],
  webServer: { command: 'pnpm build && pnpm preview --port 4173 --strictPort', url: 'http://localhost:4173', reuseExistingServer: true, timeout: 180_000 },
})
