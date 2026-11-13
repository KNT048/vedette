import type { ComponentProps } from 'react'
import { Checkbox as CheckboxPrimitive, RadioGroup as RadioPrimitive } from 'radix-ui'
import { Check, Minus } from 'lucide-react'
import { cn } from '@/lib/utils'

export function Checkbox({ className, ...props }: ComponentProps<typeof CheckboxPrimitive.Root>) {
  return (
    <CheckboxPrimitive.Root className={cn('group relative grid size-4 shrink-0 place-items-center rounded-[4px] after:absolute after:-inset-2.5 after:content-[""] border border-muted bg-surface data-[state=checked]:border-accent data-[state=checked]:bg-accent data-[state=checked]:text-accent-ink data-[state=indeterminate]:border-accent data-[state=indeterminate]:bg-accent data-[state=indeterminate]:text-accent-ink disabled:opacity-50', className)} {...props}>
      <CheckboxPrimitive.Indicator>
        <Check className="size-3 group-data-[state=indeterminate]:hidden" strokeWidth={3} />
        <Minus className="hidden size-3 group-data-[state=indeterminate]:block" strokeWidth={3} />
      </CheckboxPrimitive.Indicator>
    </CheckboxPrimitive.Root>
  )
}

export function RadioGroup({ className, ...props }: ComponentProps<typeof RadioPrimitive.Root>) {
  return <RadioPrimitive.Root className={cn('grid gap-2', className)} {...props} />
}

export function RadioItem({ className, ...props }: ComponentProps<typeof RadioPrimitive.Item>) {
  return (
    <RadioPrimitive.Item className={cn('relative grid size-4 shrink-0 place-items-center rounded-full after:absolute after:-inset-2.5 after:content-[""] border border-muted bg-surface data-[state=checked]:border-accent disabled:opacity-50', className)} {...props}>
      <RadioPrimitive.Indicator className="block size-2 rounded-full bg-accent" />
    </RadioPrimitive.Item>
  )
}
