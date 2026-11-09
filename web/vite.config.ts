import path from 'node:path'
import tailwindcss from '@tailwindcss/vite'
import react from '@vitejs/plugin-react'
import { defineConfig } from 'vitest/config'

export default defineConfig({
  plugins: [react(), tailwindcss()],
  resolve: { alias: { '@': path.resolve(import.meta.dirname, './src') } },
  build: { chunkSizeWarningLimit: 900 },
  // Ảnh chụp/kết quả Playwright ghi trong web/ không được kích hoạt HMR (gây tải lại CSS liên tục khi đang chạy E2E).
  server: { watch: { ignored: ['**/qa-shots/**', '**/test-results/**', '**/playwright-report/**'] } },
  test: {
    environment: 'jsdom',
    setupFiles: ['./src/test/setup.ts'],
    css: false,
    include: ['src/**/*.test.{ts,tsx}'],
    testTimeout: 15000,
  },
})
