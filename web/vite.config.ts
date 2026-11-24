import { createHash } from 'node:crypto'
import { readdirSync, readFileSync, rmSync } from 'node:fs'
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

// docs/cookbook is the one source of the user cookbook: GitHub shows it, and the Help pages render the same files from the build
// (offline: nothing is fetched from outside the box). `virtual:cookbook` gives the recipes' Markdown and the URL of each image.
// An image is served at assets/cookbook/<name>-<hash>.<ext>: a content hash, so the immutable cache of assets/ stays right after an
// update. The dev server answers those URLs from docs/cookbook/images; the build emits them as files.
const COOKBOOK_DIR = path.resolve(import.meta.dirname, '../docs/cookbook')
function cookbookImages() {
  const dir = path.join(COOKBOOK_DIR, 'images')
  return readdirSync(dir).filter((f) => /\.(webp|png|jpe?g|svg)$/.test(f)).sort().map((f) => {
    const source = readFileSync(path.join(dir, f))
    const ext = path.extname(f)
    return { ref: `images/${f}`, file: path.join(dir, f), source, url: `assets/cookbook/${path.basename(f, ext)}-${createHash('sha256').update(source).digest('hex').slice(0, 8)}${ext}` }
  })
}
const cookbook: Plugin = {
  name: 'cookbook',
  resolveId: (id) => (id === 'virtual:cookbook' ? '\0virtual:cookbook' : undefined),
  load(id) {
    if (id !== '\0virtual:cookbook') return undefined
    const pages = readdirSync(COOKBOOK_DIR).filter((f) => f.endsWith('.md')).sort().map((f) => {
      this.addWatchFile(path.join(COOKBOOK_DIR, f))
      return { file: f, markdown: readFileSync(path.join(COOKBOOK_DIR, f), 'utf8') }
    })
    const images = Object.fromEntries(cookbookImages().map((i) => [i.ref, `/${i.url}`]))
    return `export const PAGES = ${JSON.stringify(pages)}\nexport const IMAGES = ${JSON.stringify(images)}\n`
  },
  configureServer(server) {
    server.middlewares.use((req, res, next) => {
      const hit = req.url?.startsWith('/assets/cookbook/') ? cookbookImages().find((i) => `/${i.url}` === req.url) : undefined
      if (!hit) return next()
      res.setHeader('Content-Type', hit.file.endsWith('.svg') ? 'image/svg+xml' : `image/${path.extname(hit.file).slice(1).replace('jpg', 'jpeg')}`)
      res.end(hit.source)
    })
  },
  generateBundle() {
    for (const i of cookbookImages()) this.emitFile({ type: 'asset', fileName: i.url, source: i.source })
  },
}

export default defineConfig({
  plugins: [react(), tailwindcss(), dropMockWorker, terms, cookbook],
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
