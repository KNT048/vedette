import type { ComponentProps } from 'react'
import { Switch as SwitchPrimitive } from 'radix-ui'
import { cn } from '@/lib/utils'

export function Switch({ className, ...props }: ComponentProps<typeof SwitchPrimitive.Root>) {
  return (
    <SwitchPrimitive.Root
      className={cn('relative inline-flex h-5 w-9 after:absolute after:-inset-x-1 after:-inset-y-2.5 after:content-[""] shrink-0 items-center rounded-full border border-transparent bg-off/50 transition-colors data-[state=checked]:bg-accent disabled:opacity-50', className)}
      {...props}
    >
      <SwitchPrimitive.Thumb className="block size-4 translate-x-0.5 rounded-full bg-white shadow-sm transition-transform data-[state=checked]:translate-x-[18px]" />
    </SwitchPrimitive.Root>
  )
}
