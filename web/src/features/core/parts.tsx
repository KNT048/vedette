import type { TFunction } from 'i18next'
import { useTranslation } from 'react-i18next'
import { Notice } from '@/components/common/PageHeader'
import { InfoTip } from '@/components/common/InfoTip'
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
  return <Notice tone="off" role="note" className="mb-4" title={t('readOnly', { role: t(`common:role.${role}`) })} />
}

/** Chỉ bản xem thử (mock) có mã này; backend thật không bao giờ gửi `preview_code`, nên ghi chú này biến mất khi build với VITE_API_MOCK=off. */
export function PreviewCode({ code }: { code?: string }) {
  const { t } = useTranslation('core')
  if (import.meta.env.VITE_API_MOCK === 'off' || !code) return null
  return <p data-testid="preview-code" className="rounded-md border border-dashed border-rule bg-sunken px-3 py-2 text-meta text-muted">{t('preview.emailCode', { code })}</p>
}

/** Đầu một khối lớn của trang (Cập nhật có ba khối): số thứ tự, tên, một dòng giải thích, nút chính. Giải thích dài vào `info` (ⓘ cạnh tên, #824). */
export function Band({ n, title, desc, info, actions, id }: { n: string; title: string; desc?: string; info?: React.ReactNode; actions?: React.ReactNode; id?: string }) {
  // #842 (UI.md §1, FRONTEND §4): no all-caps eyebrow; the step number sits before the title, muted, and the rule is a `rule` line.
  return (
    <div className="mb-4 flex flex-wrap items-end justify-between gap-3 border-b border-rule pb-2">
      <div className="grid gap-0.5">
        <div className="flex items-center gap-1">
          <h2 id={id} className="flex items-baseline gap-2 text-base font-semibold"><span className="tabular-nums text-muted" aria-hidden>{n}</span>{title}</h2>
          {info ? <InfoTip topic={title}>{info}</InfoTip> : null}
        </div>
        {desc ? <p className="max-w-3xl text-meta text-muted">{desc}</p> : null}
      </div>
      {actions ? <div className="flex flex-wrap items-center gap-2">{actions}</div> : null}
    </div>
  )
}
