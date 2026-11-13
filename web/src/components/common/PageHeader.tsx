import type { ReactNode } from 'react'
import { StoryTag } from './StoryTag'

/** Dòng đầu mỗi trang trả lời câu hỏi của persona (FRONTEND §3 "thứ bậc thông tin").
 *  Khung trang D-464: tiêu đề ~20 px và mô tả ngắn chung một dòng (mô tả xuống dòng khi không đủ chỗ); sau đó KpiStrip, PageTabs (`PageFrame.tsx`). */
export function PageHeader({ title, meta, actions, stories }: { title: ReactNode; meta?: ReactNode; actions?: ReactNode; stories?: string[] }) {
  return (
    <header className="mb-5 flex flex-wrap items-start justify-between gap-x-6 gap-y-3">
      <div className="grid min-w-0 max-w-4xl gap-1">
        <div className="flex flex-wrap items-baseline gap-x-3 gap-y-1">
          <h1 className="text-xl font-semibold leading-tight tracking-[-0.01em]">{title}</h1>
          {meta ? <div className="text-[13px] text-muted">{meta}</div> : null}
        </div>
        {stories ? <StoryTag ids={stories} /> : null}
      </div>
      {actions ? <div className="flex flex-wrap items-center gap-2">{actions}</div> : null}
    </header>
  )
}

/** Khối nội dung có tiêu đề; không phải card — viền chỉ khi nội dung là bảng/khối dữ liệu. */
export function Section({ title, description, actions, children, id, stories }: { title: ReactNode; description?: ReactNode; actions?: ReactNode; children: ReactNode; id?: string; stories?: string[] }) {
  return (
    <section className="mb-8" aria-labelledby={id ? `${id}-title` : undefined} id={id}>
      <div className="mb-3 flex flex-wrap items-end justify-between gap-3">
        <div className="grid gap-0.5">
          <h2 className="text-base font-semibold" id={id ? `${id}-title` : undefined}>{title}</h2>
          {description ? <p className="max-w-3xl text-[13px] text-muted">{description}</p> : null}
          {stories ? <StoryTag ids={stories} /> : null}
        </div>
        {actions ? <div className="flex flex-wrap items-center gap-2">{actions}</div> : null}
      </div>
      {children}
    </section>
  )
}

export function Panel({ children, className = '' }: { children: ReactNode; className?: string }) {
  return <div className={`rounded-md border border-rule bg-surface ${className}`}>{children}</div>
}

/** Danh sách nhãn: giá trị, dùng cho trang chi tiết. */
export function KeyValue({ items }: { items: { label: string; value: ReactNode }[] }) {
  return (
    <dl className="grid grid-cols-1 gap-x-6 gap-y-2 sm:grid-cols-[minmax(140px,max-content)_1fr]">
      {items.map((it) => (
        <div key={it.label} className="contents">
          <dt className="text-[13px] text-muted">{it.label}</dt>
          <dd className="text-sm">{it.value}</dd>
        </div>
      ))}
    </dl>
  )
}
