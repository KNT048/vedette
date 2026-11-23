import { cn } from '@/lib/utils'

/** Choose one of a few values (a filter, a time window). Use Tabs only when there is real tab content. */
export function Segmented<T extends string>({ value, onChange, options, label, className }: { value: T; onChange: (v: T) => void; options: { value: T; label: string }[]; label: string; className?: string }) {
  return (
    <div role="group" aria-label={label} className={cn('inline-flex max-w-full flex-wrap rounded-md border border-rule bg-surface p-0.5', className)}>
      {options.map((o) => (
        <button key={o.value} type="button" aria-pressed={o.value === value} onClick={() => onChange(o.value)}
          className={cn('h-9 shrink-0 sm:h-8 whitespace-nowrap rounded-sm border border-transparent px-3 text-meta text-muted hover:text-ink', o.value === value && 'border-accent bg-accent-soft font-medium text-ink')}>
          {o.label}
        </button>
      ))}
    </div>
  )
}
