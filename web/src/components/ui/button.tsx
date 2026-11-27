import type { ComponentProps } from 'react'
import { Slot } from 'radix-ui'
import { cva, type VariantProps } from 'class-variance-authority'
import { LoaderCircle } from 'lucide-react'
import { cn } from '@/lib/utils'

const buttonVariants = cva(
  // A busy button keeps its full colour (it is working, not unavailable): only a disabled one that is not busy fades
  'inline-flex items-center justify-center gap-2 whitespace-nowrap rounded-md font-medium no-underline transition-colors disabled:pointer-events-none [&:disabled:not([aria-busy=true])]:opacity-50 [&_svg]:size-4 [&_svg]:shrink-0',
  {
    variants: {
      variant: {
        primary: 'bg-accent text-accent-ink hover:bg-accent/90',
        secondary: 'border border-rule bg-surface text-ink hover:bg-sunken',
        ghost: 'text-ink hover:bg-sunken',
        danger: 'bg-danger text-paper hover:bg-danger/90',
        link: 'text-accent underline-offset-4 hover:underline px-0 h-auto',
      },
      size: { sm: 'h-9 px-3 text-meta sm:h-8', md: 'h-10 px-4 text-sm sm:h-9', icon: 'size-10 sm:size-9' },
    },
    defaultVariants: { variant: 'secondary', size: 'md' },
  },
)

export type ButtonProps = ComponentProps<'button'> & VariantProps<typeof buttonVariants> & {
  asChild?: boolean
  /**
   * The action this button started is waiting on the server (a mutation's `isPending`). The button is disabled, says
   * `aria-busy="true"`, and shows a spinner with `busyLabel` ("Saving…") in place of its icon and label; without `busyLabel`
   * (icon-only buttons) the spinner alone takes the icon's place. The width never changes: the button always reserves room for
   * both its label and the busy label. docs/UI.md §8; the busy guard (src/test/busyGuard.test.ts) keeps every button on it.
   */
  busy?: boolean
  /** What the button is doing while busy, a verb in -ing with an ellipsis: "Saving…", "Asking…" (common:busy.* or the feature's). */
  busyLabel?: string
}

export function Button({ className, variant, size, asChild = false, type, busy, busyLabel, disabled, children, ...props }: ButtonProps) {
  // a link or a child element styled as a button: it does not wait, but it keeps `disabled` (#930 review r1 L1)
  if (asChild) return <Slot.Root className={cn(buttonVariants({ variant, size }), className)} {...{ ...props, disabled }}>{children}</Slot.Root>
  // A button that never waits on the server renders its children as they are
  if (busy === undefined) return <button className={cn(buttonVariants({ variant, size }), className)} type={type ?? 'button'} disabled={disabled} {...props}>{children}</button>
  return (
    // busy-guard: the Button itself: its native button is the one that draws the busy state
    <button className={cn(buttonVariants({ variant, size }), className)} type={type ?? 'button'} disabled={disabled || busy}
      aria-busy={busy || undefined} {...props}
      // WCAG 2.5.3 (#930 review r1 L2): while busy, a name given by aria-label starts with the visible busy label
      aria-label={busy && busyLabel && props['aria-label'] ? `${busyLabel} ${props['aria-label']}` : props['aria-label']}>
      {/* One grid cell holds the label, the busy content and (as ::after) the busy label's width, so the button never jumps */}
      <span data-busy-label={busyLabel}
        className={cn('grid items-center justify-items-center', busyLabel && 'after:invisible after:col-start-1 after:row-start-1 after:pl-6 after:content-[attr(data-busy-label)]')}>
        <span className={cn('col-start-1 row-start-1 inline-flex items-center justify-center gap-2', busy && 'invisible')} aria-hidden={busy || undefined}>{children}</span>
        {busy ? (
          <span className="col-start-1 row-start-1 inline-flex items-center justify-center gap-2">
            <LoaderCircle aria-hidden className="animate-spin" />{busyLabel}
          </span>
        ) : null}
      </span>
    </button>
  )
}

export { buttonVariants }
