import { useState, type ComponentProps, type ReactNode } from 'react'
import { Dialog as DialogPrimitive } from 'radix-ui'
import { X } from 'lucide-react'
import { useTranslation } from 'react-i18next'
import { cn } from '@/lib/utils'

export const Dialog = DialogPrimitive.Root
export const DialogTrigger = DialogPrimitive.Trigger
export const DialogClose = DialogPrimitive.Close

export function DialogContent({ className, children, title, description, wide, onCloseAutoFocus, ...props }: ComponentProps<typeof DialogPrimitive.Content> & { title: string; description?: ReactNode; wide?: boolean }) {
  const { t } = useTranslation()
  // Hộp thoại mở bằng state (không có DialogTrigger): Radix không biết trả focus về đâu khi đóng.
  // Nhớ phần tử đang focus lúc mở và trả focus về đó (WCAG 2.4.3).
  const [opener] = useState(() => (typeof document !== 'undefined' ? (document.activeElement as HTMLElement | null) : null))
  return (
    <DialogPrimitive.Portal>
      <DialogPrimitive.Overlay className="fixed inset-0 z-40 bg-ink/40" />
      <DialogPrimitive.Content
        onCloseAutoFocus={(e) => {
          onCloseAutoFocus?.(e)
          if (!e.defaultPrevented && opener && opener !== document.body && document.contains(opener)) { e.preventDefault(); opener.focus() }
        }}
        className={cn('fixed left-1/2 top-1/2 z-50 grid max-h-[90vh] w-[calc(100vw-32px)] -translate-x-1/2 -translate-y-1/2 gap-4 overflow-y-auto rounded-md border border-rule bg-surface p-6 shadow-lg', wide ? 'max-w-3xl' : 'max-w-lg', className)}
        {...props}
      >
        <div className="grid gap-1 pr-8">
          <DialogPrimitive.Title className="text-base font-semibold">{title}</DialogPrimitive.Title>
          {description ? <DialogPrimitive.Description className="text-sm text-muted">{description}</DialogPrimitive.Description> : <DialogPrimitive.Description className="sr-only">{title}</DialogPrimitive.Description>}
        </div>
        {children}
        <DialogPrimitive.Close className="absolute right-4 top-4 rounded-md p-1 text-muted hover:bg-sunken hover:text-ink" aria-label={t('close')}>
          <X className="size-4" />
        </DialogPrimitive.Close>
      </DialogPrimitive.Content>
    </DialogPrimitive.Portal>
  )
}

export function DialogFooter({ className, ...props }: ComponentProps<'div'>) {
  return <div className={cn('flex flex-wrap justify-end gap-2 pt-2', className)} {...props} />
}
