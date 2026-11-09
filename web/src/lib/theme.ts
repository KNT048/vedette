import { useSyncExternalStore } from 'react'

export type ThemePref = 'system' | 'light' | 'dark'
const KEY = 'vedette-theme'
const listeners = new Set<() => void>()

function read(): ThemePref {
  try {
    const v = localStorage.getItem(KEY)
    if (v === 'light' || v === 'dark' || v === 'system') return v
  } catch { /* bỏ qua */ }
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
}

export function setTheme(p: ThemePref) {
  pref = p
  try { localStorage.setItem(KEY, p) } catch { /* bỏ qua */ }
  apply()
  listeners.forEach((l) => l())
}

export function useTheme(): ThemePref {
  return useSyncExternalStore((l) => { listeners.add(l); return () => listeners.delete(l) }, () => pref)
}
