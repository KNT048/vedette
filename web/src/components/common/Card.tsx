import type { ReactNode } from 'react'
import { cn } from '@/lib/utils'
import { InfoTip } from './InfoTip'

/** The one card (docs/UI.md §5): rule border, 6 px radius, surface, no shadow, 16 px padding; `flush` for a list or table inside.
 *  Title row: text-base 600 with an optional ⓘ and actions on the right. No card in a card. */
export function Card({ title, info, actions, flush, children, className, id }: { title?: ReactNode; info?: ReactNode; actions?: ReactNode; flush?: boolean; children: ReactNode; className?: string; id?: string }) {
  const head = title || actions ? (
    <div className={cn('flex flex-wrap items-center justify-between gap-x-4 gap-y-2', flush ? 'px-4 pt-4' : 'mb-3')}>
      {title ? (
        <div className="flex min-w-0 items-center gap-1">
          <h2 className="text-base font-semibold" id={id ? `${id}-title` : undefined}>{title}</h2>
          {info ? <InfoTip topic={typeof title === 'string' ? title : undefined}>{info}</InfoTip> : null}
        </div>
      ) : <span />}
      {actions ? <div className="flex flex-wrap items-center gap-2">{actions}</div> : null}
    </div>
  ) : null
  return (
    <section id={id} aria-labelledby={title && id ? `${id}-title` : undefined} className={cn('min-w-0 rounded-md border border-rule bg-surface', !flush && 'p-4', className)}>
      {head}
      {children}
    </section>
  )
}
