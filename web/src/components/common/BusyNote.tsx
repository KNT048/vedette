import { useEffect, useState, type ReactNode } from 'react'
import { useTranslation } from 'react-i18next'
import { cn } from '@/lib/utils'

/**
 * Says what a long wait is doing (an AI answer, a scan start, a report, a connection test: usually more than 3 s), next to or
 * under the busy Button that started it: "Asking your AI… this can take up to a minute · 12 s". The polite status region is
 * always in the accessibility tree (so the text is announced when it appears): while idle it is visually hidden (sr-only), never
 * display:none (#930 review r1 M4), and takes no room; the seconds are not announced.
 * docs/UI.md §8 (busy state). Jobs the box reports progress for use JobProgress instead (§10).
 */
export function BusyNote({ busy, children, className, id }: { busy: boolean; children: ReactNode; className?: string; id?: string }) {
  return (
    <p id={id} role="status" className={busy ? cn('text-meta text-muted', className) : 'sr-only'}>
      {busy ? <>{children}<Elapsed /></> : null}
    </p>
  )
}

/** Seconds since the wait began, from 3 s on, so a person sees the box is still working. Mounted only while busy. */
function Elapsed() {
  const { t } = useTranslation()
  const [secs, setSecs] = useState(0)
  useEffect(() => {
    const start = Date.now()
    const id = setInterval(() => setSecs(Math.floor((Date.now() - start) / 1000)), 1000)
    return () => clearInterval(id)
  }, [])
  return secs >= 3 ? <span aria-hidden className="tabular-nums"> · {t('busy.elapsed', { count: secs })}</span> : null
}
