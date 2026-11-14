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

// D-544: TERMS.md at the repository root is the one source of the terms of use. `virtual:terms` gives the interface its text
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
  build: { chunkSizeWarningLimit: 900 },
  // Ảnh chụp/kết quả Playwright ghi trong web/ không được kích hoạt HMR (gây tải lại CSS liên tục khi đang chạy E2E).
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
