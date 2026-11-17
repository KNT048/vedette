import { useTranslation } from 'react-i18next'
import { fmtDateTime } from '@/lib/format'

/** Mọi dữ liệu có "nguồn" và "độ tin cậy"/"cập nhật lúc" (FRONTEND §3 "độ tin cậy nhìn thấy"). `basis` says how Vedette knows it:
 *  stated (the device announced it, over LLDP) or guess (a network scan's OS fingerprint: a guess, never shown as a confidence level). */
export function SourceBadge({ source, confidence, at, basis }: { source: string; confidence?: number; at?: string; basis?: 'stated' | 'guess' }) {
  const { t } = useTranslation()
  const level = confidence === undefined || basis ? null : confidence >= 0.8 ? 'high' : confidence >= 0.5 ? 'medium' : 'low'
  return (
    <span className="inline-flex flex-wrap items-center gap-x-1.5 text-caption text-muted">
      <span className={basis === 'guess' ? 'text-warn' : undefined}>{basis ? t(`basis.${basis}`) : t(`source.${source}`, { defaultValue: source })}</span>
      {level ? <span className={level === 'low' ? 'text-warn' : undefined}>({t(`confidence.${level}`)})</span> : null}
      {at ? <span>{fmtDateTime(at)}</span> : null}
    </span>
  )
}
