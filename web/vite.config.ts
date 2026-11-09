import path from 'node:path'
import tailwindcss from '@tailwindcss/vite'
import react from '@vitejs/plugin-react'
import { defineConfig } from 'vitest/config'

export default defineConfig({
  plugins: [react(), tailwindcss()],
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
