import { useSyncExternalStore } from 'react'

export type ThemePref = 'system' | 'light' | 'dark'
const KEY = 'vedette-theme'
const listeners = new Set<() => void>()

function read(): ThemePref {
  try {
    const v = localStorage.getItem(KEY)
    if (v === 'light' || v === 'dark' || v === 'system') return v
  } catch { /* ignore */ }
  return 'system'
}
let pref: ThemePref = read()

function apply() {
  const dark = pref === 'dark' || (pref === 'system' && typeof matchMedia !== 'undefined' && matchMedia('(prefers-color-scheme: dark)').matches)
  document.documentElement.dataset.theme = dark ? 'dark' : 'light'
}

export function initTheme() {
  apply()
  if (typeof matchMedia !== 'undefined') matchMedia('(prefers-color-scheme: dark)').addEventListener('change', apply)
  // A choice made in another tab of this browser applies here too: every open page shows the one theme the person chose, not the
  // one this tab read when it opened.
  window.addEventListener('storage', (e) => {
    if (e.key !== KEY && e.key !== null) return
    pref = read()
    apply()
    listeners.forEach((l) => l())
  })
}

export function setTheme(p: ThemePref) {
  pref = p
  try { localStorage.setItem(KEY, p) } catch { /* ignore */ }
  apply()
  listeners.forEach((l) => l())
}

export function useTheme(): ThemePref {
  return useSyncExternalStore((l) => { listeners.add(l); return () => listeners.delete(l) }, () => pref)
}
