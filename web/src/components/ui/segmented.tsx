import { cn } from '@/lib/utils'

/** Chọn một trong vài giá trị (bộ lọc, cửa sổ thời gian). Dùng Tabs chỉ khi có nội dung tab thật. */
export function Segmented<T extends string>({ value, onChange, options, label, className }: { value: T; onChange: (v: T) => void; options: { value: T; label: string }[]; label: string; className?: string }) {
  return (
    <div role="group" aria-label={label} className={cn('inline-flex max-w-full overflow-x-auto rounded-md border border-rule bg-surface p-0.5', className)}>
      {options.map((o) => (
        <button key={o.value} type="button" aria-pressed={o.value === value} onClick={() => onChange(o.value)}
          className={cn('h-9 shrink-0 sm:h-8 whitespace-nowrap rounded-[4px] px-3 text-[13px] text-muted hover:text-ink', o.value === value && 'bg-accent-soft font-medium text-ink')}>
          {o.label}
        </button>
      ))}
    </div>
  )
}
