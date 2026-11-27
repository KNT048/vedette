import { useTranslation } from 'react-i18next'
import { fmtDate } from '@/lib/format'
import { cn } from '@/lib/utils'
import type { Reopened } from '@/features/findings/types'

/**
 * Why a finding that was handled before is open again, from stored fields: "Reopened: the version was set back to 1.30.5 by
 * ana@example.com (24 Nov 2026)", "Reopened: a reading newer than the patched mark still shows the affected version (24 Nov 2026)".
 * `version`: the version the finding is matched on now (its software line's). `proOnly`: the fix is only in Ubuntu Pro (ESM), the one
 * reason a patched mark keeps reopening, said with it.
 */
export function ReopenedLine({ reopened: r, version, proOnly, className }: { reopened: Reopened; version?: string | null; proOnly?: boolean; className?: string }) {
  const { t } = useTranslation()
  const date = fmtDate(r.at)
  const line = r.why === 'detected_again' && r.by
    ? (version ? t('reopened.setBack', { by: r.by, version, date }) : t('reopened.setBackNoVersion', { by: r.by, date }))
    : r.why === 'still_detected' && proOnly ? t('reopened.still_detected_pro', { date }) : t(`reopened.${r.why}`, { date })
  return <span data-testid="reopened-line" className={cn('text-meta text-muted', className)}>{line}</span>
}
