import { useId, type ReactNode } from 'react'
import { Popover } from 'radix-ui'
import { Info } from 'lucide-react'
import { useTranslation } from 'react-i18next'
import { cn } from '@/lib/utils'

/** Long guidance sits behind the ⓘ icon and shows only when the user asks (#824, S-UI-1): each part keeps only a heading + at most one short line.
 *  Click, Enter or Space opens; Esc or a click outside closes (Radix Popover). A screen reader gets the content as the button's description (aria-describedby),
 *  so it need not be opened to be heard. `topic` is the name of the part/field being explained: the button reads "About <topic>".
 *  Warnings that prevent harm, errors and status do not go here: they still show, in one line, and the detail may sit behind the ⓘ. */
export function InfoTip({ topic, children, className }: { topic?: string; children: ReactNode; className?: string }) {
  const { t } = useTranslation()
  const id = useId()
  // Section, Notice, EmptyState, DialogContent, Field, Band and PageHeader pass their heading as `topic`. Only a short name (<= 6 words) goes into the button name;
  // when the heading is a whole sentence the button reads "More about this", so a screen reader does not read that sentence twice.
  const name = topic && topic.trim().split(/\s+/).length <= 6 ? topic : undefined
  const label = name ? t('infoAbout', { topic: name }) : t('infoAboutThis')
  return (
    <Popover.Root>
      <Popover.Trigger
        type="button"
        aria-label={label}
        aria-describedby={id}
        // An ⓘ inside a clickable table row (onRowClick) only opens the popover, not the row.
        onClick={(e) => e.stopPropagation()}
        // A 40 px hit area on a phone, 24 px on a large screen (WCAG 2.5.8); -my keeps the height of the heading line.
        className={cn('-my-2 inline-grid size-10 shrink-0 place-items-center rounded-full align-middle text-muted hover:text-ink data-[state=open]:text-accent sm:-my-1 sm:size-6', className)}
      >
        <Info className="size-4" aria-hidden />
      </Popover.Trigger>
      {/* The hidden copy exists only as the button's description; `hidden` still counts toward the accessible description. <span>: valid inside <legend>/<span> too;
          <p>/<ol> inside a <span> does not make React warn about nesting. Put the InfoTip next to a heading/label, not inside a <p> or <label>. */}
      <span id={id} hidden>{children}</span>
      {/* Portal to <body> even inside a dialog: the Radix Dialog RemoveScroll follows the React tree, so the popover still scrolls with mouse and touch
          (measured on a 390 px phone, the email provider ⓘ, #824). A click/tap inside the popover does not reach the table row behind it. */}
      <Popover.Portal>
        {/* Radix gives the popover role="dialog": it needs a name (axe aria-dialog-name), the same one as its button. */}
        <Popover.Content
          aria-label={label}
          onClick={(e) => e.stopPropagation()}
          side="bottom"
          align="start"
          sideOffset={6}
          collisionPadding={16}
          // z-[60]: above the dialog (z-50) when the ⓘ sits in a dialog. Long content (the Privacy data flow) scrolls inside the popover instead of overflowing the screen.
          // Dark background: the popover has the same background as the dialog below it, so it gets a lighter border and a heavier shadow to show its edge.
          className="z-[60] grid max-h-[min(28rem,var(--radix-popover-content-available-height))] max-w-[min(22rem,calc(100vw-32px))] gap-2 overflow-y-auto overscroll-contain rounded-lg border border-rule bg-surface px-3 py-2.5 text-meta leading-relaxed text-ink shadow-md [overflow-wrap:anywhere] dark:border-ink/30 dark:shadow-lg dark:shadow-sunken [&_a]:underline"
        >
          {children}
        </Popover.Content>
      </Popover.Portal>
    </Popover.Root>
  )
}
