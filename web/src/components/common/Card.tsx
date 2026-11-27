import { createContext, useContext, type ReactNode } from 'react'
import { cn } from '@/lib/utils'
import { InfoTip } from './InfoTip'

/** The one card (docs/UI.md §5): rule border, 6 px radius, surface, no shadow, 16 px padding; `flush` (no padding) for a divided list
 *  of rows. A DataTable is its own card: never put one in a Card. Title row: text-base 600, optional ⓘ, actions on the right.
 *  `level`: the heading level of the title, 3 inside a Section (h2). No card in a card. */
/** The heading level of a Card set by the Section around it: 3 under a Section's h2, 2 in a Section without a title (a tab panel
 *  whose tab names it), so the page's headings never skip a level. */
export const CardLevel = createContext<2 | 3 | undefined>(undefined)

export function Card({ title, info, actions, flush, level = 2, children, className, id }: { title?: ReactNode; info?: ReactNode; actions?: ReactNode; flush?: boolean; level?: 2 | 3; children: ReactNode; className?: string; id?: string }) {
  const H = (useContext(CardLevel) ?? level) === 3 ? 'h3' : 'h2'
  const head = title || actions ? (
    <div className={cn('flex flex-wrap items-center justify-between gap-x-4 gap-y-2', flush ? 'border-b border-rule px-4 py-3' : 'mb-3')}>
      {title ? (
        <div className="flex min-w-0 items-center gap-1">
          <H className="text-base font-semibold" id={id ? `${id}-title` : undefined}>{title}</H>
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
