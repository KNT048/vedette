import { useEffect } from 'react'
import { Navigate, useLocation } from 'react-router'

// Links from before the tabs (/exposure#open, /exposure/:id#step-verify, …) land on the right tab; the block keeps its hash so the page scrolls to it.
// Any other hash (the skip link's #main) stays as it is.
export function AnchorRedirect({ map }: { map: Record<string, string> }) {
  const { hash, search } = useLocation()
  const tab = map[hash.slice(1)]
  const p = new URLSearchParams(search)
  if (!tab || p.get('tab') === tab) return null
  p.set('tab', tab)
  return <Navigate replace to={{ search: `?${p}`, hash }} />
}

export function ScrollToHash() {
  const { hash } = useLocation()
  useEffect(() => { if (hash.length > 1) document.getElementById(hash.slice(1))?.scrollIntoView() }, [hash])
  return null
}
