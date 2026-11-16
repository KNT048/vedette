import type { ComponentProps } from 'react'
import { Switch as SwitchPrimitive } from 'radix-ui'
import { cn } from '@/lib/utils'

export function Switch({ className, ...props }: ComponentProps<typeof SwitchPrimitive.Root>) {
  return (
    <SwitchPrimitive.Root
      className={cn('relative inline-flex h-5 w-9 after:absolute after:-inset-x-1 after:-inset-y-2.5 after:content-[""] shrink-0 items-center rounded-full border border-transparent bg-control transition-colors data-[state=checked]:bg-accent disabled:opacity-50', className)}
      {...props}
    >
      {/* docs/UI.md §1: the thumb is `surface` (white on light, dark on dark), 3:1 on both tracks; white on the dark mint was 2.2:1. */}
      <SwitchPrimitive.Thumb className="block size-4 translate-x-0.5 rounded-full bg-surface shadow-sm transition-transform data-[state=checked]:translate-x-[18px]" />
    </SwitchPrimitive.Root>
  )
}
