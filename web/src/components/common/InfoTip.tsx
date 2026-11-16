import { useId, type ReactNode } from 'react'
import { Popover } from 'radix-ui'
import { Info } from 'lucide-react'
import { useTranslation } from 'react-i18next'
import { cn } from '@/lib/utils'

/** Hướng dẫn dài nằm sau biểu tượng ⓘ, chỉ hiện khi người dùng hỏi (#824, S-UI-1): mỗi phần chỉ để tiêu đề + tối đa một dòng ngắn.
 *  Bấm, Enter hoặc Space mở; Esc hoặc bấm ra ngoài đóng (Radix Popover). Trình đọc màn hình nhận nội dung là mô tả của nút (aria-describedby)
 *  nên không cần mở mới nghe được. `topic` là tên phần/ô được giải thích: nút đọc là "About <topic>".
 *  Cảnh báo tránh hại, lỗi và trạng thái không vào đây: chúng vẫn hiện, một dòng, chi tiết thì có thể đặt sau ⓘ. */
export function InfoTip({ topic, children, className }: { topic?: string; children: ReactNode; className?: string }) {
  const { t } = useTranslation()
  const id = useId()
  return (
    <Popover.Root>
      <Popover.Trigger
        type="button"
        aria-label={topic ? t('infoAbout', { topic }) : t('infoAboutThis')}
        aria-describedby={id}
        // Vùng bấm 40 px trên điện thoại, 24 px trên màn lớn (WCAG 2.5.8); -my giữ chiều cao dòng tiêu đề.
        className={cn('-my-2 inline-grid size-10 shrink-0 place-items-center rounded-full align-middle text-muted hover:text-ink data-[state=open]:text-accent sm:-my-1 sm:size-6', className)}
      >
        <Info className="size-4" aria-hidden />
      </Popover.Trigger>
      {/* Bản ẩn chỉ để làm mô tả của nút; `hidden` vẫn được tính vào accessible description. Đặt InfoTip cạnh tiêu đề/nhãn, không trong <p> hay <label>. */}
      <div id={id} hidden>{children}</div>
      <Popover.Portal>
        <Popover.Content
          side="bottom"
          align="start"
          sideOffset={6}
          collisionPadding={16}
          // z-[60]: nằm trên hộp thoại (z-50) khi ⓘ ở trong một hộp thoại. Nội dung dài (luồng dữ liệu Privacy) cuộn trong popover, không tràn màn hình.
          className="z-[60] grid max-h-[min(28rem,var(--radix-popover-content-available-height))] max-w-[min(22rem,calc(100vw-32px))] gap-2 overflow-y-auto overscroll-contain rounded-md border border-rule bg-surface px-3 py-2.5 text-[13px] leading-relaxed text-ink shadow-md [overflow-wrap:anywhere] [&_a]:underline"
        >
          {children}
        </Popover.Content>
      </Popover.Portal>
    </Popover.Root>
  )
}
