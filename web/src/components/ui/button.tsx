import type { ComponentProps } from 'react'
import { Slot } from 'radix-ui'
import { cva, type VariantProps } from 'class-variance-authority'
import { cn } from '@/lib/utils'

const buttonVariants = cva(
  'inline-flex items-center justify-center gap-2 whitespace-nowrap rounded-md font-medium transition-colors disabled:pointer-events-none disabled:opacity-50 [&_svg]:size-4 [&_svg]:shrink-0',
  {
    variants: {
      variant: {
        primary: 'bg-accent text-accent-ink hover:bg-accent/90',
        secondary: 'border border-rule bg-surface text-ink hover:bg-sunken',
        ghost: 'text-ink hover:bg-sunken',
        danger: 'bg-danger text-white hover:bg-danger/90 dark:text-paper',
        link: 'text-accent underline-offset-4 hover:underline px-0 h-auto',
      },
      size: { sm: 'h-9 px-3 text-[13px] sm:h-8', md: 'h-10 px-4 text-sm sm:h-9', icon: 'size-10 sm:size-9' },
    },
    defaultVariants: { variant: 'secondary', size: 'md' },
  },
)

export type ButtonProps = ComponentProps<'button'> & VariantProps<typeof buttonVariants> & { asChild?: boolean }

export function Button({ className, variant, size, asChild = false, type, ...props }: ButtonProps) {
  const Comp = asChild ? Slot.Root : 'button'
  return <Comp className={cn(buttonVariants({ variant, size }), className)} type={asChild ? undefined : (type ?? 'button')} {...props} />
}

export { buttonVariants }
