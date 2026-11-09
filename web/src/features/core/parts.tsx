import type { TFunction } from 'i18next'
import { useTranslation } from 'react-i18next'
import { ApiError } from '@/lib/api'
import type { Role } from '@/lib/session'
import { useCan } from '@/lib/session'

export const errMsg = (e: unknown, t: TFunction) => (e instanceof ApiError ? e.message : t('common:error.unknown'))

/** Thuộc tính cho nút/ô cần vai `role`: tắt kèm giải thích khi thiếu quyền. */
export function useGate(role: Role) {
  const { t } = useTranslation()
  const ok = useCan(role)
  return { ok, title: ok ? undefined : t('common:needRole', { role: t(`common:role.${role}`) }), disabled: !ok }
}

/** Người xem được mục này nhưng không sửa được: nói rõ cần vai nào. */
export function ReadOnlyNote({ role }: { role: Role }) {
  const { t } = useTranslation('core')
  const ok = useCan(role)
  if (ok) return null
  return <p role="note" className="mb-4 rounded-md border border-rule bg-off-soft px-4 py-2.5 text-sm">{t('readOnly', { role: t(`common:role.${role}`) })}</p>
}

/** Chỉ bản xem thử (mock) có mã này; backend thật không bao giờ gửi `preview_code`, nên ghi chú này biến mất khi build với VITE_API_MOCK=off. */
export function PreviewCode({ code }: { code?: string }) {
  const { t } = useTranslation('core')
  if (import.meta.env.VITE_API_MOCK === 'off' || !code) return null
  return <p data-testid="preview-code" className="rounded-md border border-dashed border-rule bg-sunken px-3 py-2 text-[13px] text-muted">{t('preview.emailCode', { code })}</p>
}

/** Đầu một khối lớn của trang (Cập nhật có ba khối): số thứ tự, tên, một dòng giải thích, nút chính. */
export function Band({ n, title, desc, actions, id }: { n: string; title: string; desc?: string; actions?: React.ReactNode; id?: string }) {
  return (
    <div className="mb-4 flex flex-wrap items-end justify-between gap-3 border-b border-ink/70 pb-2">
      <div className="grid gap-0.5">
        <span className="text-[12px] font-medium uppercase tracking-wide text-muted" aria-hidden>{n}</span>
        <h2 id={id} className="text-lg font-semibold">{title}</h2>
        {desc ? <p className="max-w-3xl text-[13px] text-muted">{desc}</p> : null}
      </div>
      {actions ? <div className="flex flex-wrap items-center gap-2">{actions}</div> : null}
    </div>
  )
}
