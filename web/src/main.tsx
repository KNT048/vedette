import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import './index.css'
import './lib/i18n'
import { initTheme } from './lib/theme'
import { installClientErrors } from './lib/clientErrors'
import { App } from './app/App'

// Sau khi hộp cập nhật, tab đang mở còn trỏ tới chunk cũ đã bị thay → tải lại trang (tối đa 1 lần/10 s, tránh vòng lặp).
window.addEventListener('vite:preloadError', (e) => {
  try {
    if (Date.now() - Number(sessionStorage.getItem('vedette-reload') ?? 0) < 10_000) return
    sessionStorage.setItem('vedette-reload', String(Date.now()))
  } catch { return }
  e.preventDefault()
  location.reload()
})

installClientErrors()

async function start() {
  // /api/v1 do MSW trả lời (D-18, D-22), trừ module nằm trong VITE_API_REAL (đi tới backend Go qua proxy Vite).
  // VITE_API_MOCK=off = mọi module thật: không chạy MSW.
  if (import.meta.env.VITE_API_MOCK !== 'off') {
    try {
      const { worker } = await import('./mocks/browser')
      await worker.start({ onUnhandledFrame: 'bypass', quiet: true })
    } catch {
      // Không có service worker (cửa sổ riêng tư, trình duyệt chặn) thì bản xem thử không chạy được: nói rõ thay vì trang trắng.
      const p = document.createElement('p')
      p.style.cssText = 'max-width:36rem;margin:4rem auto;padding:0 1rem;font:16px/1.5 system-ui,sans-serif'
      p.textContent = 'This preview needs a service worker to serve its sample data, and this browser blocked it. Open the page in a normal (not private) window, or allow service workers for this site, then reload.'
      document.getElementById('root')!.replaceChildren(p)
      return
    }
  }
  initTheme()
  createRoot(document.getElementById('root')!).render(<StrictMode><App /></StrictMode>)
}

void start()
