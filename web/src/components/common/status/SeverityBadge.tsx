import { useTranslation } from 'react-i18next'
import { InfoTip } from '@/components/common/InfoTip'
import { cn } from '@/lib/utils'
import { asSeverity, type Band, type SeverityValue } from './severity'

const LOOK: Record<Band, string> = {
  critical: 'border-danger/40 bg-danger-soft text-danger',
  high: 'border-danger/40 bg-danger-soft text-danger',
  medium: 'border-warn/50 bg-warn-soft text-warn',
  low: 'border-rule bg-off-soft text-off',
  none: 'border-rule bg-off-soft text-off',
  info: 'border-rule bg-off-soft text-off',
}
const LEVEL: Record<Band, number> = { critical: 4, high: 3, medium: 2, low: 1, none: 0, info: 0 }

/** The level as four bars, filled in the badge's colour, so Critical and High differ by more than the word (as Tenable gives each
 *  severity its own icon). Decorative: the word carries the meaning. */
export function SeverityMeter({ level, className }: { level: number; className?: string }) {
  return (
    <svg aria-hidden viewBox="0 0 14 10" className={cn('h-2.5 w-3.5 shrink-0', className)} data-level={level}>
      {[0, 1, 2, 3].map((i) => <rect key={i} x={i * 3.5} y={7 - i * 2} width="2.5" height={3 + i * 2} rx="0.5" fill="currentColor" opacity={i < level ? 1 : 0.25} />)}
    </svg>
  )
}

/**
 * A CVE's severity, wherever a CVE is shown: "Critical 9.8". Separate from the status and never instead of it. No score known:
 * "Not scored yet", never 0. The CVSS version and vector are on hover; `detail` puts them, with FIRST's credit, behind an ⓘ
 * (the finding page). `compact` is the smaller badge inside a list of CVEs.
 */
export function SeverityBadge({ severity, detail = false, compact = false, className }: {
  severity: SeverityValue | Band | null | undefined; detail?: boolean; compact?: boolean; className?: string
}) {
  const { t } = useTranslation()
  const v = asSeverity(severity)
  if (!v) return <span data-band="unscored" className={cn('whitespace-nowrap text-meta text-muted', className)}>{t('severityBadge.unscored')}</span>
  const word = t(`severity.${v.band}`)
  const score = typeof v.score === 'number' ? v.score.toFixed(1) : null
  const cvss = score && v.version ? t('severityBadge.cvss', { version: v.version, score }) : null
  const label = score ? `${word} ${score}` : word
  return (
    <span className={cn('inline-flex items-center gap-1', className)}>
      <span data-band={v.band} title={cvss ? [cvss, v.vector].filter(Boolean).join('\n') : undefined}
        className={cn('inline-flex w-fit items-center gap-1.5 whitespace-nowrap rounded-sm border font-medium leading-none', compact ? 'h-5 px-1.5 text-caption' : 'h-6 px-2 text-caption', LOOK[v.band])}>
        <SeverityMeter level={LEVEL[v.band]} />
        <span>{word}</span>
        {score ? <span className="font-semibold tabular-nums">{score}</span> : null}
      </span>
      {detail && cvss ? (
        <InfoTip topic={label} className="print:hidden">
          <span className="block">{cvss}</span>
          {/* FIRST's terms: a score is shown with its vector, and CVSS is credited to FIRST */}
          {v.vector ? <code className="block font-mono text-caption [overflow-wrap:anywhere]">{v.vector}</code> : null}
          <span className="block text-muted">{t('severityBadge.first')}</span>
        </InfoTip>
      ) : null}
    </span>
  )
}
