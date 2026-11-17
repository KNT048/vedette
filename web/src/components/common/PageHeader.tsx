import { useContext, type ReactNode, type Ref } from 'react'
import { cn } from '@/lib/utils'
import { InfoTip } from './InfoTip'
import { StoryTag } from './StoryTag'
import { ModuleBadge, ModuleLine } from './V1Scope'
import { PageModule } from '@/lib/v1'
import { Breadcrumbs, type Crumb } from './Breadcrumbs'

/** Dòng đầu mỗi trang trả lời câu hỏi của persona (FRONTEND §3 "thứ bậc thông tin").
 *  Khung trang: tiêu đề ~20 px và mô tả ngắn chung một dòng (mô tả xuống dòng khi không đủ chỗ); sau đó KpiStrip, PageTabs (`PageFrame.tsx`). */
/*  `meta` là một dòng ngắn (≈ 12 từ); giải thích dài hơn vào `info` (ⓘ cạnh tiêu đề, #824). */
/*  `breadcrumbs`: the parents of a detail page (docs/UI.md §3), drawn above the title. */
/** `titleAction` sits right after the title, outside the heading (a Rename button); `editing` replaces the visible title with an
 *  edit-in-place field while the heading stays for screen readers. */
export function PageHeader({ title, meta, info, actions, stories, breadcrumbs, titleAction, editing }: { title: ReactNode; meta?: ReactNode; info?: ReactNode; actions?: ReactNode; stories?: string[]; breadcrumbs?: Crumb[]; titleAction?: ReactNode; editing?: ReactNode }) {
  const mod = useContext(PageModule) // A preview or leaving module's page says so under its title (#818, #819)
  return (
    <header className="mb-5 flex flex-wrap items-start justify-between gap-x-6 gap-y-3">
      <div className="grid min-w-0 max-w-4xl gap-1">
        {breadcrumbs?.length ? <Breadcrumbs items={breadcrumbs} /> : null}
        <div className="flex flex-wrap items-baseline gap-x-3 gap-y-1">
          <div className="flex flex-wrap items-center gap-1">
            <h1 className={editing ? 'sr-only' : 'page-title'}>{title}</h1>
            {editing ?? titleAction}
            {info ? <InfoTip topic={typeof title === 'string' ? title : undefined}>{info}</InfoTip> : null}
            {mod ? <ModuleBadge id={mod} className="ml-1.5 self-center" /> : null}
          </div>
          {meta ? <div className="text-meta text-muted">{meta}</div> : null}
        </div>
        {mod ? <ModuleLine id={mod} turnOff /> : null}
        {stories ? <StoryTag ids={stories} /> : null}
      </div>
      {actions ? <div className="flex flex-wrap items-center gap-2">{actions}</div> : null}
    </header>
  )
}

/** Khối nội dung có tiêu đề; không phải card — viền chỉ khi nội dung là bảng/khối dữ liệu. */
/*  `description` là một dòng ngắn (≈ 12 từ); cách hoạt động, lý do, ví dụ vào `info` (ⓘ cạnh tiêu đề, #824). */
export function Section({ title, description, info, actions, children, id, stories }: { title: ReactNode; description?: ReactNode; info?: ReactNode; actions?: ReactNode; children: ReactNode; id?: string; stories?: string[] }) {
  return (
    <section className="mb-8" aria-labelledby={id ? `${id}-title` : undefined} id={id}>
      <div className="mb-3 flex flex-wrap items-end justify-between gap-3">
        <div className="grid gap-0.5">
          <div className="flex items-center gap-1">
            <h2 className="text-base font-semibold" id={id ? `${id}-title` : undefined}>{title}</h2>
            {info ? <InfoTip topic={typeof title === 'string' ? title : undefined}>{info}</InfoTip> : null}
          </div>
          {description ? <p className="max-w-3xl text-meta text-muted">{description}</p> : null}
          {stories ? <StoryTag ids={stories} /> : null}
        </div>
        {actions ? <div className="flex flex-wrap items-center gap-2">{actions}</div> : null}
      </div>
      {children}
    </section>
  )
}

const NOTICE = {
  danger: 'border-danger/40 bg-danger-soft',
  warn: 'border-warn/50 bg-warn-soft',
  accent: 'border-accent/40 bg-accent-soft',
  off: 'border-rule bg-off-soft',
} as const

/** Khung báo một trạng thái của trang (một kiểu cho cả ứng dụng): tiêu đề, một đoạn giải thích, nút hành động bên phải (xuống dòng trên điện thoại).
 *  `tone` mang nghĩa cố định của FRONTEND §3: danger = hỏng/khẩn, warn = cần người xem, accent = thông tin của sản phẩm, off = tắt/không có. */
/*  `className` thắng lớp mặc định (cn), ví dụ `mb-0` cho lỗi nằm trong một form có `gap`. */
/*  Cảnh báo, lỗi, trạng thái luôn hiện (#824): `title` + tối đa một dòng `children`; chi tiết vào `info`. */
export function Notice({ tone, title, children, info, actions, role, className, ref, id, ...rest }: {
  tone: keyof typeof NOTICE; title: ReactNode; children?: ReactNode; info?: ReactNode; actions?: ReactNode; role?: 'alert' | 'status' | 'note'; className?: string; 'data-testid'?: string; ref?: Ref<HTMLDivElement>; id?: string
}) {
  return (
    <div ref={ref} id={id} role={role} data-testid={rest['data-testid']} className={cn('mb-5 grid gap-3 rounded-md border px-4 py-3 text-sm md:grid-cols-[minmax(0,1fr)_auto] md:items-center', NOTICE[tone], className)}>
      <div className="grid min-w-0 gap-1">
        <div className="flex items-center gap-1">
          <p className={tone === 'danger' ? 'font-medium text-danger' : 'font-medium'}>{title}</p>
          {info ? <InfoTip topic={typeof title === 'string' ? title : undefined}>{info}</InfoTip> : null}
        </div>
        {children ? <div className="max-w-3xl text-muted">{children}</div> : null}
      </div>
      {actions ? <div className="flex flex-wrap gap-2">{actions}</div> : null}
    </div>
  )
}

/** Deprecated by Card (docs/UI.md §5): kept, without padding, until its pages migrate. */
export function Panel({ children, className = '' }: { children: ReactNode; className?: string }) {
  return <div className={cn('rounded-md border border-rule bg-surface', className)}>{children}</div>
}

/** Danh sách nhãn: giá trị, dùng cho trang chi tiết. */
export function KeyValue({ items }: { items: { label: string; value: ReactNode }[] }) {
  return (
    <dl className="grid grid-cols-1 gap-x-6 gap-y-2 sm:grid-cols-[minmax(140px,max-content)_1fr]">
      {items.map((it) => (
        <div key={it.label} className="contents">
          <dt className="text-meta text-muted">{it.label}</dt>
          <dd className="text-sm">{it.value}</dd>
        </div>
      ))}
    </dl>
  )
}
