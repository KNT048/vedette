import { clsx, type ClassValue } from 'clsx'
import { extendTailwindMerge } from 'tailwind-merge'

// docs/UI.md §1: tailwind-merge only knows the default sizes; without this `text-meta` and `text-caption` read as colours, so
// cn('text-meta', 'text-muted') would drop the size. Every new size, radius or shadow name in @theme goes here too.
const twMerge = extendTailwindMerge({ extend: { theme: { text: ['caption', 'meta'] } } })

export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs))
}
