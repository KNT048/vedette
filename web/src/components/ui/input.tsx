import type { ComponentProps } from 'react'
import { cn } from '@/lib/utils'

const field = 'w-full min-w-0 rounded-md border border-rule bg-surface px-3 text-base text-ink sm:text-sm placeholder:text-muted disabled:opacity-60 aria-[invalid=true]:border-danger'

export function Input({ className, ...props }: ComponentProps<'input'>) {
  return <input className={cn(field, 'h-10 sm:h-9', className)} {...props} />
}

export function Textarea({ className, ...props }: ComponentProps<'textarea'>) {
  return <textarea className={cn(field, 'min-h-24 py-2 leading-relaxed', className)} {...props} />
}

/** Select gốc của trình duyệt: truy cập được bằng bàn phím và trình đọc màn hình, không cần JS. */
export function Select({ className, ...props }: ComponentProps<'select'>) {
  return <select className={cn(field, 'h-10 pr-8 sm:h-9', className)} {...props} />
}

export function Label({ className, ...props }: ComponentProps<'label'>) {
  return <label className={cn('text-sm font-medium text-ink', className)} {...props} />
}

/** Ô nhập kèm nhãn, gợi ý và lỗi — dùng cho mọi form. */
export function Field({ label, hint, error, htmlFor, children, className }: { label: string; hint?: string; error?: string; htmlFor: string; children: React.ReactNode; className?: string }) {
  return (
    <div className={cn('grid gap-1.5', className)}>
      <Label htmlFor={htmlFor}>{label}</Label>
      {children}
      {error ? <p className="text-[13px] text-danger" id={`${htmlFor}-error`}>{error}</p> : hint ? <p className="text-[13px] text-muted" id={`${htmlFor}-hint`}>{hint}</p> : null}
    </div>
  )
}
