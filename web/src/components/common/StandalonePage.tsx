import type { ReactNode } from 'react'
import { Logo } from '@/components/brand/Logo'
import { cn } from '@/lib/utils'

/** A page outside the shell (docs/UI.md §3): sign-in, first-run setup, change password, SSO return, not found. Centred column,
 *  the stacked logo, the page title, then the page's one Card and optional footer links. Without `title` the logo is the h1
 *  (sign-in: its name is "Vedette"). */
export function StandalonePage({ title, subtitle, children, footer, size = 'sm' }: { title?: ReactNode; subtitle?: ReactNode; children: ReactNode; footer?: ReactNode; size?: 'sm' | 'md' | 'lg' }) {
  return (
    <main className="grid min-h-dvh place-items-center bg-paper px-4 py-10">
      <div className={cn('grid w-full gap-6', size === 'sm' ? 'max-w-sm' : size === 'md' ? 'max-w-md' : 'max-w-2xl')}>
        <header className="grid justify-items-center gap-5 text-center">
          {title ? <Logo variant="stacked" className="h-16" /> : <h1><span className="sr-only">Vedette</span><Logo variant="stacked" decorative className="h-20" /></h1>}
          {title ? <h1 className="page-title">{title}</h1> : null}
          {subtitle ? <p className="text-sm text-muted">{subtitle}</p> : null}
        </header>
        {children}
        {footer ? <div className="text-center text-meta text-muted">{footer}</div> : null}
      </div>
    </main>
  )
}
