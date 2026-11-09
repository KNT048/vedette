import type { ComponentProps } from 'react'
import { DropdownMenu as Menu } from 'radix-ui'
import { cn } from '@/lib/utils'

export const DropdownMenu = Menu.Root
export const DropdownMenuTrigger = Menu.Trigger

export function DropdownMenuContent({ className, sideOffset = 6, ...props }: ComponentProps<typeof Menu.Content>) {
  return (
    <Menu.Portal>
      <Menu.Content sideOffset={sideOffset} className={cn('z-50 min-w-48 rounded-md border border-rule bg-surface p-1 shadow-md', className)} {...props} />
    </Menu.Portal>
  )
}

export function DropdownMenuItem({ className, ...props }: ComponentProps<typeof Menu.Item>) {
  return <Menu.Item className={cn('flex cursor-default items-center gap-2 rounded-[4px] px-2 py-1.5 text-sm outline-none data-[highlighted]:bg-sunken data-[disabled]:opacity-50 [&_svg]:size-4', className)} {...props} />
}

export function DropdownMenuLabel({ className, ...props }: ComponentProps<typeof Menu.Label>) {
  return <Menu.Label className={cn('px-2 py-1.5 text-[13px] text-muted', className)} {...props} />
}

export const DropdownMenuSeparator = ({ className, ...props }: ComponentProps<typeof Menu.Separator>) => <Menu.Separator className={cn('my-1 h-px bg-rule', className)} {...props} />
export const DropdownMenuRadioGroup = Menu.RadioGroup
export function DropdownMenuRadioItem({ className, children, ...props }: ComponentProps<typeof Menu.RadioItem>) {
  return (
    <Menu.RadioItem className={cn('flex cursor-default items-center gap-2 rounded-[4px] px-2 py-1.5 text-sm outline-none data-[highlighted]:bg-sunken', className)} {...props}>
      <span className="grid size-4 place-items-center"><Menu.ItemIndicator><span className="block size-1.5 rounded-full bg-accent" /></Menu.ItemIndicator></span>
      {children}
    </Menu.RadioItem>
  )
}
