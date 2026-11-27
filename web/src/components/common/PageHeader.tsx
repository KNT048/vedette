import { useContext, useEffect, useRef, type ReactNode, type Ref } from 'react'
import { cn } from '@/lib/utils'
import { InfoTip } from './InfoTip'
import { StoryTag } from './StoryTag'
import { ModuleBadge, ModuleLine } from './V1Scope'
import { PageModule } from '@/lib/v1'
import { Breadcrumbs, type Crumb } from './Breadcrumbs'
import { HelpLink } from './HelpLink'
import { CardLevel } from './Card'

/** The first line of each page answers the persona's question (FRONTEND §3, information hierarchy).
 *  Page frame: a ~20 px heading and a short description on one line (the description wraps when there is not enough room); then KpiStrip, PageTabs (`PageFrame.tsx`). */
/*  `meta` is one short line (about 12 words); longer explanation goes into `info` (ⓘ next to the heading, #824). */
/*  `breadcrumbs`: the parents of a detail page (docs/UI.md §3), drawn above the title. */
/** `titleAction` sits right after the title, outside the heading (a Rename button that opens a dialog: a title is never edited in
 *  place, as no item is). */
/*  The header names the page: title, breadcrumbs, one meta line. An action sits next to what it acts on (a list's toolbar, a section's
    `actions`, the notice it answers); a rare or destructive one on the whole page goes to `PageEnd`. `actions` is left for a page that
    has nothing else to put it next to (a print preview's Print). */
export function PageHeader({ title, meta, info, actions, stories, breadcrumbs, titleAction }: { title: ReactNode; meta?: ReactNode; info?: ReactNode; actions?: ReactNode; stories?: string[]; breadcrumbs?: Crumb[]; titleAction?: ReactNode }) {
  const mod = useContext(PageModule) // A preview or leaving module's page says so under its title (#818, #819)
  return (
    <header className="mb-5 flex flex-wrap items-start justify-between gap-x-6 gap-y-3">
      <div className="grid min-w-0 max-w-4xl gap-1">
        {breadcrumbs?.length ? <Breadcrumbs items={breadcrumbs} /> : null}
        <div className="flex flex-wrap items-baseline gap-x-3 gap-y-1">
          <div className="flex flex-wrap items-center gap-1">
            <h1 className="page-title">{title}</h1>
            {titleAction}
            {info ? <InfoTip topic={typeof title === 'string' ? title : undefined}>{info}</InfoTip> : null}
            {mod ? <ModuleBadge id={mod} className="ml-1.5 self-center" /> : null}
          </div>
          {meta ? <div className="text-meta text-muted">{meta}</div> : null}
        </div>
        {mod ? <ModuleLine id={mod} turnOff /> : null}
        {stories ? <StoryTag ids={stories} /> : null}
      </div>
      {/* A main screen links to its guide (docs/cookbook) on the right of its header, after the page's own actions. */}
      <div className="flex flex-wrap items-center gap-x-4 gap-y-2 empty:hidden">
        {actions ? <div className="flex flex-wrap items-center gap-2">{actions}</div> : null}
        <HelpLink />
      </div>
    </header>
  )
}

/** A content block with a heading; not a card: a border only when the content is a table/data block. */
/*  `description` is one short line (about 12 words); how it works, why, examples go into `info` (ⓘ next to the heading, #824). */
/*  Without `title` it is the lead of a tab panel whose tab already names it (docs/UI.md §4): no heading that repeats the tab, its
    one muted line with the ⓘ, its actions on the right; `label` names the region for a screen reader. */
export function Section({ title, label, description, info, actions, children, id, stories }: { title?: ReactNode; label?: string; description?: ReactNode; info?: ReactNode; actions?: ReactNode; children: ReactNode; id?: string; stories?: string[] }) {
  if (!title) {
    return (
      <section className="mb-8" aria-label={label} id={id}>
        {description || info || actions || stories ? (
          <div className="mb-3 flex flex-wrap items-center justify-between gap-3">
            <div className="grid gap-0.5">
              {description || info ? (
                <div className="flex max-w-3xl items-center gap-1 text-meta text-muted">
                  {description ? <p>{description}</p> : null}
                  {info ? <InfoTip topic={label}>{info}</InfoTip> : null}
                </div>
              ) : null}
              {stories ? <StoryTag ids={stories} /> : null}
            </div>
            {actions ? <div className="flex flex-wrap items-center gap-2">{actions}</div> : null}
          </div>
        ) : null}
        <CardLevel value={2}>{children}</CardLevel>
      </section>
    )
  }
  return (
    <section className="mb-8" aria-labelledby={id ? `${id}-title` : undefined} id={id}>
      <div className="mb-3 flex flex-wrap items-end justify-between gap-3">
        <div className="grid gap-0.5">
          <div className="flex items-center gap-1">
            <h2 className="text-base font-semibold" id={id ? `${id}-title` : undefined}>{title}</h2>
            {info ? <InfoTip topic={typeof title === 'string' ? title : undefined}>{info}</InfoTip> : null}
          </div>
          {description ? <p className="max-w-3xl text-meta text-muted">{description}</p> : null}
          {stories ? <StoryTag ids={stories} /> : null}
        </div>
        {actions ? <div className="flex flex-wrap items-center gap-2">{actions}</div> : null}
      </div>
      <CardLevel value={3}>{children}</CardLevel>
    </section>
  )
}

/** The end of a page: the rare or destructive actions on the whole page (turn a module off), below its content, never in the header. */
export function PageEnd({ children }: { children: ReactNode }) {
  return <div data-testid="page-end" className="mt-10 flex flex-wrap items-center gap-3 border-t border-rule pt-4">{children}</div>
}

const NOTICE = {
  danger: 'border-danger/40 bg-danger-soft',
  warn: 'border-warn/50 bg-warn-soft',
  accent: 'border-accent/40 bg-accent-soft',
  off: 'border-rule bg-off-soft',
} as const

/** A frame that reports one state of the page (one style for the whole app): a heading, one explanatory paragraph, an action button on the right (wraps on a phone).
 *  `tone` has the fixed meaning of FRONTEND §3: danger = broken/urgent, warn = needs a person's attention, accent = product information, off = off/none. */
/*  `className` wins over the default classes (cn), for example `mb-0` for an error inside a form that has a `gap`. */
/*  Warnings, errors and status always show (#824): `title` + at most one `children` line; detail goes into `info`. */
export function Notice({ tone, title, children, info, actions, role, className, ref, id, ...rest }: {
  tone: keyof typeof NOTICE; title: ReactNode; children?: ReactNode; info?: ReactNode; actions?: ReactNode; role?: 'alert' | 'status' | 'note'; className?: string; 'data-testid'?: string; ref?: Ref<HTMLDivElement>; id?: string
}) {
  // An error that appears inside a dialog is brought into view (a long form hides it above or below the button just pressed).
  const own = useRef<HTMLDivElement | null>(null)
  useEffect(() => {
    const el = own.current
    if (role === 'alert' && el?.closest('[role="dialog"]')) el.scrollIntoView?.({ block: 'nearest' })
  }, [role, title])
  return (
    <div ref={(el) => { own.current = el; if (typeof ref === 'function') ref(el); else if (ref) (ref as { current: HTMLDivElement | null }).current = el }} id={id} role={role} data-testid={rest['data-testid']} className={cn('mb-5 grid gap-3 rounded-md border px-4 py-3 text-sm md:grid-cols-[minmax(0,1fr)_auto] md:items-center', NOTICE[tone], className)}>
      <div className="grid min-w-0 gap-1">
        <div className="flex items-center gap-1">
          <p className={tone === 'danger' ? 'font-medium text-danger' : 'font-medium'}>{title}</p>
          {info ? <InfoTip topic={typeof title === 'string' ? title : undefined}>{info}</InfoTip> : null}
        </div>
        {children ? <div className="max-w-3xl text-muted">{children}</div> : null}
      </div>
      {actions ? <div className="flex flex-wrap gap-2">{actions}</div> : null}
    </div>
  )
}

/** Deprecated by Card (docs/UI.md §5): kept, without padding, until its pages migrate. */
export function Panel({ children, className = '' }: { children: ReactNode; className?: string }) {
  return <div className={cn('rounded-md border border-rule bg-surface', className)}>{children}</div>
}

/** A list of labels: values, for detail pages. */
export function KeyValue({ items }: { items: { label: string; value: ReactNode }[] }) {
  return (
    <dl className="grid grid-cols-1 gap-x-6 gap-y-2 sm:grid-cols-[minmax(140px,max-content)_1fr]">
      {items.map((it) => (
        <div key={it.label} className="contents">
          <dt className="text-meta text-muted">{it.label}</dt>
          <dd className="text-sm">{it.value}</dd>
        </div>
      ))}
    </dl>
  )
}
