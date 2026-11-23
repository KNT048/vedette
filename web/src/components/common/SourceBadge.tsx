import { useTranslation } from 'react-i18next'
import { fmtDateTime } from '@/lib/format'

/** Every piece of data has a "source" and a "confidence"/"updated at" (FRONTEND §3, visible confidence). `basis` says how Vedette knows it:
 *  stated (the device announced it, over LLDP) or guess (a network scan's OS fingerprint: a guess, never shown as a confidence level). */
export function SourceBadge({ source, confidence, at, basis }: { source: string; confidence?: number; at?: string; basis?: 'stated' | 'stated_web' | 'stated_sip' | 'guess' }) {
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
