import { useTranslation } from 'react-i18next'
import { InfoTip } from '@/components/common/InfoTip'
import { cn } from '@/lib/utils'
import { cvssBand, type CvssBand } from './basis'
import type { Cvss } from './types'

const tone: Record<CvssBand, string> = { critical: 'text-danger', high: 'text-danger', medium: 'text-warn', low: 'text-muted', none: 'text-muted' }

/**
 * The CVSS base score with its band, "9.8 Critical" (S-MIT-1, #825): shown next to the exploited status, never instead of it. The version
 * and source are behind the ⓘ (#824: one short line visible). No score known → "No score", never 0. `prefix` adds "CVSS" before it where
 * no column header names it (the finding page, the phone list).
 */
export function CvssScore({ cvss, prefix }: { cvss: Cvss | null | undefined; prefix?: boolean }) {
  const { t } = useTranslation('findings')
  if (!cvss) {
    const label = prefix ? t('cvss.noneLabel') : t('cvss.none')
    return (
      <span className="inline-flex items-center gap-1 whitespace-nowrap text-[13px] text-muted">
        {label}
        <InfoTip topic={label} className="print:hidden">{t('cvss.noneInfo')}</InfoTip>
      </span>
    )
  }
  const band = cvssBand(cvss.score, cvss.version)
  const text = t('cvss.value', { score: cvss.score.toFixed(1), band: t(`cvss.band.${band}`) })
  const label = prefix ? t('cvss.label', { value: text }) : text
  const from = cvss.source === 'nvd' ? t('cvss.fromNvd') : cvss.source === 'cna' ? t('cvss.fromOther') : t('cvss.fromUnknown')
  return (
    <span className="inline-flex items-center gap-1 whitespace-nowrap text-[13px]">
      {prefix ? <span className="text-muted">CVSS</span> : null}
      <span className="font-semibold tabular-nums">{cvss.score.toFixed(1)}</span>
      <span className={cn('font-medium', tone[band])}>{t(`cvss.band.${band}`)}</span>
      <InfoTip topic={label} className="print:hidden">
        <span className="block">{cvss.version ? t('cvss.info', { version: cvss.version, from }) : t('cvss.infoNoVersion', { from })}</span>
        {/* FIRST's terms: a score is shown with its vector, and CVSS is attributed to FIRST */}
        {cvss.vector ? <code className="block font-mono text-[12px] [overflow-wrap:anywhere]">{cvss.vector}</code> : null}
        <span className="block text-muted">{t('cvss.first')}</span>
      </InfoTip>
    </span>
  )
}
