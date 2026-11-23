import { useState, type ComponentProps, type ReactNode } from 'react'
import { Dialog as DialogPrimitive } from 'radix-ui'
import { X } from 'lucide-react'
import { useTranslation } from 'react-i18next'
import { cn } from '@/lib/utils'
import { InfoTip } from '@/components/common/InfoTip'

export const Dialog = DialogPrimitive.Root
export const DialogTrigger = DialogPrimitive.Trigger
export const DialogClose = DialogPrimitive.Close

/** `description`: one short line (about 12 words); a long explanation goes into `info` (ⓘ next to the heading, #824). */
export function DialogContent({ className, children, title, description, info, wide, onCloseAutoFocus, ...props }: ComponentProps<typeof DialogPrimitive.Content> & { title: string; description?: ReactNode; info?: ReactNode; wide?: boolean }) {
  const { t } = useTranslation()
  // A dialog opened by state (no DialogTrigger): Radix does not know where to return focus when it closes.
  // Remember the element that had focus when it opened and return focus to it (WCAG 2.4.3).
  const [opener] = useState(() => (typeof document !== 'undefined' ? (document.activeElement as HTMLElement | null) : null))
  return (
    <DialogPrimitive.Portal>
      <DialogPrimitive.Overlay className="fixed inset-0 z-40 bg-ink/40" />
      <DialogPrimitive.Content
        onCloseAutoFocus={(e) => {
          onCloseAutoFocus?.(e)
          if (!e.defaultPrevented && opener && opener !== document.body && document.contains(opener)) { e.preventDefault(); opener.focus() }
        }}
        className={cn('fixed left-1/2 top-1/2 z-50 grid max-h-[90vh] w-[calc(100vw-32px)] -translate-x-1/2 -translate-y-1/2 gap-4 overflow-y-auto rounded-lg border border-rule bg-surface p-6 shadow-lg', wide ? 'max-w-3xl' : 'max-w-lg', className)}
        {...props}
      >
        <div className="grid gap-1 pr-10">
          <div className="flex items-center gap-1">
            <DialogPrimitive.Title className="text-base font-semibold">{title}</DialogPrimitive.Title>
            {info ? <InfoTip topic={title}>{info}</InfoTip> : null}
          </div>
          {description ? <DialogPrimitive.Description className="text-sm text-muted">{description}</DialogPrimitive.Description> : <DialogPrimitive.Description className="sr-only">{title}</DialogPrimitive.Description>}
        </div>
        {children}
        <DialogPrimitive.Close className="absolute right-2 top-2 grid size-10 place-items-center rounded-md text-muted hover:bg-sunken hover:text-ink sm:right-3 sm:top-3 sm:size-8" aria-label={t('close')}>
          <X className="size-4" />
        </DialogPrimitive.Close>
      </DialogPrimitive.Content>
    </DialogPrimitive.Portal>
  )
}

export function DialogFooter({ className, ...props }: ComponentProps<'div'>) {
  return <div className={cn('flex flex-wrap justify-end gap-2 pt-2', className)} {...props} />
}

/** The phone menu (docs/UI.md §2): a left drawer, 288 px (max 85 vw), full height, focus trapped. A link inside closes it through
 *  `onOpenChange`; `returnFocus=false` then keeps focus on #main (the page change moves it there), Esc returns it to the opener. */
export function DrawerContent({ className, children, title, returnFocus, ...props }: ComponentProps<typeof DialogPrimitive.Content> & { title: string; returnFocus: () => boolean }) {
  const { t } = useTranslation()
  return (
    <DialogPrimitive.Portal>
      <DialogPrimitive.Overlay className="fixed inset-0 z-40 bg-ink/40" />
      <DialogPrimitive.Content
        onCloseAutoFocus={(e) => { if (!returnFocus()) e.preventDefault() }}
        aria-describedby={undefined}
        className={cn('fixed inset-y-0 left-0 z-50 flex w-72 max-w-[85vw] flex-col gap-4 overflow-y-auto border-r border-rule bg-surface px-3 py-4 shadow-lg', className)}
        {...props}
      >
        <DialogPrimitive.Title className="sr-only">{title}</DialogPrimitive.Title>
        {children}
        <DialogPrimitive.Close className="absolute right-2 top-2 grid size-10 place-items-center rounded-md text-muted hover:bg-sunken hover:text-ink" aria-label={t('close')}>
          <X className="size-4" />
        </DialogPrimitive.Close>
      </DialogPrimitive.Content>
    </DialogPrimitive.Portal>
  )
}
