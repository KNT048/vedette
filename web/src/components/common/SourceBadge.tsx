import { useTranslation } from 'react-i18next'
import { fmtDateTime } from '@/lib/format'

/** Mọi dữ liệu có "nguồn" và "độ tin cậy"/"cập nhật lúc" (FRONTEND §3 "độ tin cậy nhìn thấy"). */
export function SourceBadge({ source, confidence, at }: { source: string; confidence?: number; at?: string }) {
  const { t } = useTranslation()
  const level = confidence === undefined ? null : confidence >= 0.8 ? 'high' : confidence >= 0.5 ? 'medium' : 'low'
  return (
    <span className="inline-flex flex-wrap items-center gap-x-1.5 text-[12px] text-muted">
      <span>{t(`source.${source}`, { defaultValue: source })}</span>
      {level ? <span className={level === 'low' ? 'text-warn' : undefined}>({t(`confidence.${level}`)})</span> : null}
      {at ? <span>{fmtDateTime(at)}</span> : null}
    </span>
  )
}
