import { useTranslation } from 'react-i18next'
import { Chip, type Tone } from '@/components/common/StatusChip'
import { fmtNumber } from '@/lib/format'
import type { Run, RunStatus } from './types'

/** The eight run states, one word and one colour each for every engine: moving is accent, waiting is neutral, a run that ended with
 *  work not done is amber, a failure is red. */
const tone: Record<RunStatus, Tone> = { queued: 'off', waiting: 'off', running: 'accent', stopping: 'accent', done: 'ok', partial: 'warn', failed: 'danger', stopped: 'warn' }

export function RunStateChip({ status }: { status: RunStatus }) {
  const { t } = useTranslation('scanning')
  return <Chip tone={tone[status]}>{t(`runs.status.${status}`)}</Chip>
}

/** What a run is, in words: "LAN sweep", "Device check", …; a kind this page does not know yet reads as its name. */
export function useKindLabel() {
  const { t } = useTranslation('scanning')
  return (kind: string) => t(`runs.kind.${kind}`, { defaultValue: kind.replaceAll('_', ' ') })
}

/** "6,528 of 65,792", or null when the run does not count its work. */
export function useRunCount() {
  const { t } = useTranslation('scanning')
  return (r: { done: number; total: number }): string | null => (r.total > 0 ? t('runs.count', { done: fmtNumber(r.done), total: fmtNumber(r.total) }) : null)
}

/** Who or what started it: a person's address, "Schedule", or the event that started it. */
export function useStartedBy() {
  const { t } = useTranslation('scanning')
  return (r: Run): string => r.trigger === 'manual' ? r.requested_by
    : r.trigger === 'schedule' ? t('runs.bySchedule')
    : r.trigger_note ? t('runs.byEvent', { what: r.trigger_note }) : t('runs.byBox')
}

/** A plain bar of done over total, for a run or a step that counts its work. */
export function RunBar({ done, total, label }: { done: number; total: number; label: string }) {
  if (total <= 0) return null
  const pct = Math.min(100, Math.round((done / total) * 100))
  return (
    <div role="progressbar" aria-label={label} aria-valuemin={0} aria-valuemax={100} aria-valuenow={pct} className="h-1.5 w-full overflow-hidden rounded-full bg-sunken">
      <div className="h-full bg-accent" style={{ width: `${pct}%` }} />
    </div>
  )
}
