import { useEffect, useState } from 'react'
import { InfoTip } from '@/components/common/InfoTip'
import type { JobProgress as Progress } from '@/lib/progress'
import { useTranslation } from 'react-i18next'
import { cn } from '@/lib/utils'
import { sayDuration } from './duration'
import './JobProgress.css'

/** A report older than this reads "Last report N s ago": the box reports every 5 s at most, and some checks are silent until they end. */
export const QUIET_AFTER_MS = 30_000

/** The OpenVAS step's cap (the box's GreenboneTimeout, 90 min, D-595): its last phase can sit at 98% for half an hour, so the page names the stop time (#915). */
export const OPENVAS_CAP_MS = 90 * 60_000
const OPENVAS_TAIL_PERCENT = 95

/** The clock of the elapsed time and the estimate: one tick a second, local only (no request). */
function useNow(stepMs = 1000) {
  const [now, setNow] = useState(() => Date.now())
  useEffect(() => {
    const id = setInterval(() => setNow(Date.now()), stepMs)
    return () => clearInterval(id)
  }, [stepMs])
  return now
}

/**
 * How far a long job is (#830, S-INV-1 / S-EXP-1): the step in words, a bar (determinate with the tool's percent, indeterminate without),
 * the count behind it ("3 of 8 checks"), the elapsed time, and "about N min left" once the box has an estimate of the step.
 * `progress` null = the job runs but nothing was reported yet: "Starting" and an indeterminate bar.
 * Screen readers: the bar is a progressbar named by the step (no aria-valuenow when indeterminate); only a change of step (or of its note)
 * is announced, never the ticking time or the percent.
 */
export function JobProgress({ progress, className }: { progress: Progress | null; className?: string }) {
  const { t } = useTranslation('progress')
  const now = useNow()
  const step = progress ? t(`phase.${progress.phase}`) : t('starting')
  const percent = progress?.percent == null ? null : Math.round(Math.min(100, Math.max(0, progress.percent)))
  const counted = progress?.done != null && progress.total != null && progress.total > 0
  const count = counted ? t(`count.${progress.unit ?? 'plain'}`, { done: progress.done, total: progress.total, count: progress.total }) : null
  const elapsed = progress ? now - Date.parse(progress.started_at) : null
  const etaMs = progress?.eta ? Date.parse(progress.eta) - now : null
  const finishing = progress?.phase === 'openvas' && ((progress.percent ?? 0) >= OPENVAS_TAIL_PERCENT || (etaMs !== null && etaMs <= 0))
  const stopBy = finishing && progress ? new Intl.DateTimeFormat('en-GB', { hour: '2-digit', minute: '2-digit' }).format(new Date(Date.parse(progress.phase_started_at) + OPENVAS_CAP_MS)) : null
  const left = finishing || etaMs === null || etaMs <= 0 ? null : etaMs < 60_000 ? t('leftSoon') : t('left', { time: sayDuration(t, Math.ceil(etaMs / 60_000) * 60_000) })
  const quietMs = progress ? now - Date.parse(progress.updated_at) : 0
  const quiet = quietMs >= QUIET_AFTER_MS
  return (
    <div className={cn('grid gap-1.5', className)}>
      <div className="flex items-baseline justify-between gap-3">
        {/* The live region holds the step and its note only: they change a few times per job, the time every second. */}
        <p aria-live="polite" aria-atomic="true" className="min-w-0 text-sm">
          <span className="font-medium">{step}</span>
          {progress?.message ? <span className="block text-meta text-muted">{progress.message}</span> : null}
        </p>
        {percent !== null ? <span aria-hidden className="shrink-0 text-sm tabular-nums text-muted">{t('percent', { percent })}</span> : null}
      </div>
      <div
        role="progressbar"
        aria-label={step}
        aria-valuemin={0}
        aria-valuemax={100}
        aria-valuenow={percent ?? undefined}
        aria-valuetext={percent === null ? undefined : [t('percent', { percent }), count].filter(Boolean).join(', ')}
        className="relative h-2 overflow-hidden rounded-full bg-rule"
      >
        {percent === null
          ? <div data-indeterminate className="vp-job-indeterminate absolute inset-y-0 left-0 rounded-full bg-accent" />
          : <div className="h-full rounded-full bg-accent transition-[width] duration-700 ease-out" style={{ width: `${percent}%` }} />}
      </div>
      <div className="flex flex-wrap items-center gap-x-4 gap-y-0.5 text-meta text-muted tabular-nums">
        {count ? <span className="text-ink">{count}</span> : null}
        {elapsed !== null ? <span>{t('elapsed', { time: sayDuration(t, elapsed) })}</span> : null}
        {left ? <span>{left}</span> : null}
        {stopBy ? <span>{t('finishing', { time: stopBy })}</span> : null}
        {quiet ? (
          <span className="inline-flex items-center gap-1">
            {t('quiet', { time: sayDuration(t, quietMs) })}
            <InfoTip topic={t('quietTopic')}>{t('quietHelp')}</InfoTip>
          </span>
        ) : null}
      </div>
    </div>
  )
}
