import { useSyncExternalStore } from 'react'

// The story ID shows when the URL has ?story=1 (remembered for the session); ?story=0 turns it off. Hidden by default during interviews.
const KEY = 'vedette-story'
function read() {
  if (typeof window === 'undefined') return false
  const q = new URLSearchParams(window.location.search).get('story')
  try {
    if (q === '1') sessionStorage.setItem(KEY, '1')
    if (q === '0') sessionStorage.removeItem(KEY)
    return sessionStorage.getItem(KEY) === '1'
  } catch {
    return q === '1'
  }
}
const subscribe = (l: () => void) => { window.addEventListener('popstate', l); return () => window.removeEventListener('popstate', l) }

export function StoryTag({ ids }: { ids: string[] }) {
  const on = useSyncExternalStore(subscribe, read, () => false)
  if (!on) return null
  return <span className="w-fit rounded-sm bg-sunken px-1.5 py-0.5 font-mono text-caption text-muted" data-story={ids.join(',')}>{ids.join(', ')}</span>
}
