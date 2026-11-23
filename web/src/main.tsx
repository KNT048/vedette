import './lib/zodConfig' // first: before any schema parses (issue #201)
import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import './index.css'
import './lib/i18n'
import { initTheme } from './lib/theme'
import { installClientErrors } from './lib/clientErrors'
import { App } from './app/App'

// After the box updates, an open tab still points at an old chunk that was replaced → reload the page (at most once per 10 s, to avoid a loop).
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
  // /api/v1 is answered by MSW, except modules in VITE_API_REAL (they go to the Go backend through the Vite proxy).
  // VITE_API_MOCK=off = every module is real: MSW does not run.
  if (import.meta.env.VITE_API_MOCK !== 'off') {
    try {
      const { worker } = await import('./mocks/browser')
      await worker.start({ onUnhandledFrame: 'bypass', quiet: true })
    } catch {
      // No service worker (a private window, a browser that blocks it) and the preview cannot run: say so instead of showing a blank page.
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
