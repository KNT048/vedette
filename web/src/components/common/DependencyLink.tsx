import { useEffect, type ReactNode } from 'react'
import { Link, useLocation } from 'react-router'
import { cn } from '@/lib/utils'

/**
 * "Need → place → action is obvious" (docs/UI.md §0): when a step needs a setting that is missing and cannot be created inline,
 * one short reason and a link straight to the exact place: `/settings/<section>?tab=<tab>#<field-id>`, never "see Settings".
 * `label` names the place ("Set up an alert channel in Settings, Alert channels"). The target page focuses the field
 * (useDeepLinkTarget in Layout).
 */
export function DependencyLink({ reason, to, label, className }: { reason: ReactNode; to: string; label: string; className?: string }) {
  return (
    <p className={cn('text-meta text-muted', className)}>
      {reason}{' '}
      <Link to={to} className="font-medium text-accent underline underline-offset-4">{label}</Link>
    </p>
  )
}

const FOCUSABLE = 'a[href], button:not([disabled]), input:not([disabled]), select:not([disabled]), textarea:not([disabled]), [tabindex]:not([tabindex="-1"])'

/** A deep link's `#<id>` lands on that field: scrolled into view and focused (its first focusable element when the id is a block).
 *  Lazy panels render late, so it looks for up to about 2 s. `#main` (the skip link) is left to the browser. */
export function useDeepLinkTarget() {
  const { pathname, search, hash } = useLocation()
  useEffect(() => {
    const id = decodeURIComponent(hash.slice(1))
    if (!id || id === 'main') return
    let tries = 0
    let frame = 0
    const look = () => {
      const el = document.getElementById(id)
      if (!el) { if (++tries < 120) frame = requestAnimationFrame(look); return }
      el.scrollIntoView({ block: 'center' })
      const target = el.matches(FOCUSABLE) ? el : el.querySelector<HTMLElement>(FOCUSABLE)
      if (target) target.focus({ preventScroll: true })
      else { el.tabIndex = -1; el.focus({ preventScroll: true }) }
    }
    frame = requestAnimationFrame(look)
    return () => cancelAnimationFrame(frame)
  }, [pathname, search, hash])
}
