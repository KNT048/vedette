import { createHash } from 'node:crypto'
import { readFileSync, rmSync } from 'node:fs'
import path from 'node:path'
import tailwindcss from '@tailwindcss/vite'
import react from '@vitejs/plugin-react'
import type { Plugin } from 'vite'
import { defineConfig } from 'vitest/config'

// Vite copies public/ verbatim; the release build (VITE_API_MOCK=off) must not ship the MSW worker script.
const dropMockWorker: Plugin = {
  name: 'drop-mock-worker',
  apply: 'build',
  closeBundle() {
    if (process.env.VITE_API_MOCK === 'off') rmSync(path.resolve(import.meta.dirname, 'dist/mockServiceWorker.js'), { force: true })
  },
}

// TERMS.md at the repository root is the one source of the terms of use. `virtual:terms` gives the interface its text
// and its version, computed as the Go root package does (vedette.TermsVersion): the Version date and the first 8 hex digits
// of the file's SHA-256. A virtual module, so the dev server serves nothing outside web/.
const TERMS_FILE = path.resolve(import.meta.dirname, '../TERMS.md')
const terms: Plugin = {
  name: 'terms',
  resolveId: (id) => (id === 'virtual:terms' ? '\0virtual:terms' : undefined),
  load(id) {
    if (id !== '\0virtual:terms') return undefined
    this.addWatchFile(TERMS_FILE)
    const raw = readFileSync(TERMS_FILE)
    const version = `${/^Version: (\d{4}-\d{2}-\d{2})$/m.exec(raw.toString('utf8'))?.[1] ?? 'undated'}.${createHash('sha256').update(raw).digest('hex').slice(0, 8)}`
    return `export const TERMS = ${JSON.stringify(raw.toString('utf8'))}\nexport const TERMS_VERSION = ${JSON.stringify(version)}\n`
  },
}

export default defineConfig({
  plugins: [react(), tailwindcss(), dropMockWorker, terms],
  resolve: { alias: { '@': path.resolve(import.meta.dirname, './src') } },
  build: {
    chunkSizeWarningLimit: 900,
    // zod and src/lib/zodConfig.ts in one chunk (issue #201): Zod 4 decides at each schema's creation whether to probe `new Function`, which the
    // CSP blocks and the browser reports in the console. With zodConfig in the entry chunk, the shared chunk that holds zod and the first schemas ran
    // before z.config({ jitless: true }); in one chunk the config runs right after zod itself, before any module that builds a schema.
    rolldownOptions: { output: { codeSplitting: { groups: [{ name: 'zod', test: /[\\/]node_modules[\\/]zod[\\/]|[\\/]src[\\/]lib[\\/]zodConfig\.ts$/, priority: 100 }] } } },
  },
  // Playwright screenshots/results written inside web/ must not trigger HMR (it reloads the CSS continuously during E2E).
  // `make dev-api`: /api goes to the Go backend for the modules in VITE_API_REAL (the others are answered by MSW in the browser, so never reach here).
  // changeOrigin false keeps Host = localhost:5173 = the browser's Origin, which the backend's Origin check (core/server checkOrigin) compares to Host.
  server: { proxy: { '/api': { target: 'http://127.0.0.1:8080', changeOrigin: false } }, watch: { ignored: ['**/qa-shots/**', '**/test-results/**', '**/playwright-report/**'] } },
  test: {
    environment: 'jsdom',
    setupFiles: ['./src/test/setup.ts'],
    css: false,
    include: ['src/**/*.test.{ts,tsx}'],
    testTimeout: 15000,
  },
})
