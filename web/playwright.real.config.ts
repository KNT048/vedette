import { defineConfig, devices } from '@playwright/test'
import { readFileSync } from 'node:fs'

// The real backend (WP-30, D-170): `make e2e-real` starts one box with the release GUI inside it and passes E2E_BOX, the path of its
// ready.json. One box per run (D-172): `setup` (the first-run wizard) -> `seed` (accounts, one storageState per role) -> `parallel`
// (entity-scoped specs) -> `global` (anything that changes box-wide state, one at a time). Desktop only in slice 1.
const manifest = process.env.E2E_BOX
if (!manifest) throw new Error('E2E_BOX is not set: run `make e2e-real` (or, against a box kept up with HOLD=1, set E2E_BOX and E2E_PASSWORD)')
const { base_url: baseURL } = JSON.parse(readFileSync(manifest, 'utf8')) as { base_url: string }

const desktop = { ...devices['Desktop Chrome'], viewport: { width: 1366, height: 860 } }

export default defineConfig({
  testDir: './e2e-real',
  outputDir: 'test-results/real',
  timeout: 60_000,
  globalTimeout: 25 * 60_000,
  expect: { timeout: 8_000 },
  retries: 0,
  workers: Number(process.env.E2E_WORKERS ?? 1),
  reporter: [['list']],
  use: { baseURL, locale: 'vi-VN', timezoneId: 'Asia/Ho_Chi_Minh', trace: 'retain-on-failure' },
  projects: [
    { name: 'setup', testMatch: /(^|\/)setup\.spec\.ts$/, workers: 1, use: desktop },
    { name: 'seed', testMatch: /seed\.setup\.ts$/, workers: 1, dependencies: ['setup'], use: desktop },
    { name: 'parallel', testMatch: /\.spec\.ts$/, testIgnore: [/(^|\/)setup\.spec\.ts$/, /\.global\.spec\.ts$/], dependencies: ['seed'], use: desktop },
    { name: 'global', testMatch: /\.global\.spec\.ts$/, workers: 1, dependencies: ['parallel'], use: desktop },
  ],
})
