import { useEffect, useSyncExternalStore } from 'react'

// Where a page belongs in the menu when its path does not say it: a run's page (/runs/<id>) belongs to what the run is about, so a
// public scan's run keeps External exposure lit, a device check's run Devices, and a run opened from Settings › Scanning Settings.
// One page at a time sets it (the page shown), and it is cleared when that page goes.

let place: string | null = null
const listeners = new Set<() => void>()

function set(to: string | null) {
  if (place === to) return
  place = to
  listeners.forEach((l) => l())
}

/** The page shown belongs to the menu entry of `to` (a path such as "/exposure" or "/settings/scanning"); null: by its own path. */
export function useNavPlace(to: string | null) {
  useEffect(() => {
    set(to)
    return () => set(null)
  }, [to])
}

/** The path the menu marks as current instead of the address bar's, or null. */
export function useCurrentNavPlace(): string | null {
  return useSyncExternalStore((l) => { listeners.add(l); return () => listeners.delete(l) }, () => place, () => null)
}
