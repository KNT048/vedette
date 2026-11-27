import type { ComponentProps } from 'react'
import { Tabs as TabsPrimitive } from 'radix-ui'
import { cn } from '@/lib/utils'

export const Tabs = TabsPrimitive.Root

export function TabsList({ className, ...props }: ComponentProps<typeof TabsPrimitive.List>) {
  return <TabsPrimitive.List className={cn('flex gap-1 border-b border-rule', className)} {...props} />
}

/** The open tab is shown by its underline only. Radix moves focus to a clicked tab by script, which the browser draws as a keyboard
 *  focus ring: a tab clicked with a pointer is marked (`data-pointer`) until it loses focus and draws no ring, so a click never boxes
 *  one tab while the others show an underline; arrow keys and Tab still show the ring. */
export function TabsTrigger({ className, onPointerDown, onBlur, ...props }: ComponentProps<typeof TabsPrimitive.Trigger>) {
  return (
    <TabsPrimitive.Trigger
      className={cn('-mb-px border-b-2 border-transparent px-3 py-2.5 text-sm text-muted hover:text-ink data-[state=active]:border-accent data-[state=active]:font-medium data-[state=active]:text-ink data-pointer:outline-none', className)}
      onPointerDown={(e) => { e.currentTarget.dataset.pointer = ''; onPointerDown?.(e) }}
      onBlur={(e) => { delete e.currentTarget.dataset.pointer; onBlur?.(e) }}
      {...props}
    />
  )
}

export function TabsContent({ className, ...props }: ComponentProps<typeof TabsPrimitive.Content>) {
  return <TabsPrimitive.Content className={cn('pt-4', className)} {...props} />
}
