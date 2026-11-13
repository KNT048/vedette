import { useEffect, useRef, type ReactNode } from 'react'
import { Link, useSearchParams } from 'react-router'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs'

// Khung trang D-464 (S-UI-1): PageHeader → KpiStrip (tuỳ chọn) → PageTabs. Settings giữ menu dọc.

export type Kpi = { value: ReactNode; label: string; to: string }

const COLS = ['', 'sm:grid-cols-1', 'sm:grid-cols-2', 'sm:grid-cols-3', 'sm:grid-cols-4']

/** Tối đa 4 con số trả lời câu hỏi của trang (FRONTEND §3: số to chỉ khi là câu trả lời), mỗi số dẫn tới chỗ xem chi tiết.
 *  Một khung chia ô bằng đường kẻ (như một hàng bảng), không phải 4 card rời; điện thoại 2 × 2. */
export function KpiStrip({ items: all, label }: { items: Kpi[]; label: string }) {
  // Lỗi lập trình: báo khi phát triển, không làm vỡ trang của người dùng.
  if (all.length > 4 && import.meta.env.DEV) console.error(`KpiStrip "${label}": at most 4 items (D-464), got ${all.length}; the rest are dropped`)
  const items = all.slice(0, 4)
  return (
    <ul aria-label={label} className={`mb-5 grid grid-cols-2 gap-px overflow-hidden rounded-md border border-rule bg-rule ${COLS[items.length]}`}>
      {items.map((k) => (
        <li key={k.label} className="bg-surface [&:last-child:nth-child(odd)]:col-span-2 sm:[&:last-child:nth-child(odd)]:col-span-1">
          <Link to={k.to} className="grid h-full gap-0.5 px-3 py-2 hover:bg-sunken focus-visible:-outline-offset-2">
            <span className="text-lg font-semibold leading-tight tabular-nums">{k.value}</span>{' '}
            <span className="text-[13px] text-muted">{k.label}</span>
          </Link>
        </li>
      ))}
    </ul>
  )
}

/** `badge`: việc đang chờ người dùng ở tab đó (số đỏ). `label` là phần đọc sau con số cho trình đọc màn hình, ví dụ "waiting for a decision"
 *  → tên tab "Requests 3 waiting for a decision" (chứa đúng chữ nhìn thấy, WCAG 2.5.3). */
export type PageTab = { id: string; label: string; panel: ReactNode; badge?: { count: number; label: string } }

/** Tab đang mở ở `?tab=<id>`: tải lại và quay lại giữ tab; id lạ hoặc không được phép → tab đầu. */
export function PageTabs({ tabs, label }: { tabs: PageTab[]; label: string }) {
  const [params, setParams] = useSearchParams()
  const raw = params.get('tab')
  const open = tabs.find((x) => x.id === raw) ?? tabs[0]
  const list = useRef<HTMLDivElement>(null)
  // Trên điện thoại tab đang mở có thể nằm ngoài phần đang thấy của hàng tab: cuộn nó vào (chỉ hàng tab, không cuộn trang).
  useEffect(() => {
    const row = list.current
    const el = row?.querySelector<HTMLElement>('[data-state="active"]')
    if (!el || !row) return
    const r = row.getBoundingClientRect()
    const e = el.getBoundingClientRect()
    if (e.left < r.left || e.right > r.right) row.scrollLeft += e.left - r.left - 16
  }, [open?.id])
  if (!open) return null
  if (tabs.length === 1) return <>{open.panel}</>
  return (
    <Tabs
      value={open.id}
      // replace: phím mũi tên đổi tab (WAI-ARIA tự kích hoạt); push sẽ bắt Back đi qua từng tab đã lướt.
      onValueChange={(v) => { const p = new URLSearchParams(params); p.set('tab', v); setParams(p, { replace: true }) }}
    >
      {/* Hàng tab cuộn ngang (overflow) cắt mọi thứ vẽ ra ngoài nó, nên: đường kẻ dưới là bóng inset (không phải border mà gạch chân -mb-px đè lên),
          viền focus vẽ vào trong tab (-outline-offset-2), thanh cuộn ẩn (mép tab bị cắt là dấu hiệu còn tab; mũi tên trái/phải tự cuộn tới tab). */}
      <TabsList ref={list} aria-label={label} className="flex-nowrap overflow-x-auto overscroll-x-contain border-b-0 shadow-[inset_0_-1px_0_var(--color-rule)] [scrollbar-width:none] [&::-webkit-scrollbar]:hidden">
        {tabs.map((x) => (
          <TabsTrigger key={x.id} value={x.id} className="mb-0 inline-flex shrink-0 items-center gap-1.5 whitespace-nowrap focus-visible:-outline-offset-2">
            {x.label}{' '}
            {x.badge && x.badge.count > 0 ? (
              <span className="rounded-full bg-danger px-1.5 text-[11px] font-semibold leading-[18px] text-paper tabular-nums">
                {x.badge.count > 99 ? '99+' : x.badge.count}{' '}
                <span className="sr-only">{x.badge.label}</span>
              </span>
            ) : null}
          </TabsTrigger>
        ))}
      </TabsList>
      {tabs.map((x) => <TabsContent key={x.id} value={x.id}>{x.panel}</TabsContent>)}
    </Tabs>
  )
}
