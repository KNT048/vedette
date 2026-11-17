import { useEffect, useState } from 'react'
import { InfoTip } from '@/components/common/InfoTip'
import type { JobProgress as Progress } from '@/lib/progress'
import { useTranslation } from 'react-i18next'
import { cn } from '@/lib/utils'
import { sayDuration } from './duration'
import './JobProgress.css'
import { fmtTime } from '@/lib/format'

/** A report older than this reads "Last report N s ago": the box reports every 5 s at most, and some checks are silent until they end. */
export const QUIET_AFTER_MS = 30_000

const OPENVAS_TAIL_PERCENT = 95

/** nmap re-estimates a slow step on every report; an end that moves out by more than this means the tool cannot tell how long is left. */
export const SLIP_MS = 60_000

type Kept = { key: string; eta: number | null; slipped: boolean }

/** The estimate of a step never grows: the earliest end the box gave for this step is kept, and once a report moves the end out by more
 *  than SLIP_MS the step shows no estimate any more ("less than a minute left" that turns into "about 5 min left" is worse than none). */
function keep(prev: Kept, key: string, eta: number | null): Kept {
  if (prev.key !== key) return { key, eta, slipped: false }
  if (eta === null || prev.slipped || eta === prev.eta) return prev
  if (prev.eta === null || eta < prev.eta) return { ...prev, eta }
  return eta > prev.eta + SLIP_MS ? { ...prev, slipped: true } : prev
}

function useSteadyEta(progress: Progress | null) {
  const key = progress ? `${progress.started_at}|${progress.phase}|${progress.phase_started_at}` : ''
  const eta = progress?.eta ? Date.parse(progress.eta) : null
  const [kept, setKept] = useState<Kept>(() => ({ key, eta, slipped: false }))
  const next = keep(kept, key, eta)
  if (next !== kept) setKept(next) // derived from the reports seen so far: React re-renders with it before painting
  return next
}

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
 * the count behind it ("3 of 8 checks"), the elapsed time, and "about N min left" once the box has an estimate of the step. The estimate
 * never grows (see keep), and a step the tool calls 100 % while it still runs shows "finishing this step" over an indeterminate bar.
 * `progress` null = the job runs but nothing was reported yet: "Starting" and an indeterminate bar.
 * Screen readers: the bar is a progressbar named by the step (no aria-valuenow when indeterminate); only a change of step (or of its note)
 * is announced, never the ticking time or the percent.
 */
export function JobProgress({ progress, className }: { progress: Progress | null; className?: string }) {
  const { t } = useTranslation('progress')
  const now = useNow()
  const step = progress ? t(`phase.${progress.phase}`) : t('starting')
  const steady = useSteadyEta(progress)
  const openvas = progress?.phase === 'openvas'
  const reported = progress?.percent == null ? null : Math.round(Math.min(100, Math.max(0, progress.percent)))
  // The tool says 100 % while the step still runs (nmap's last service probes or scripts): not a finished step, so no full bar or "100%".
  const wrappingUp = reported === 100 && !openvas
  const percent = wrappingUp ? null : reported
  const counted = progress?.done != null && progress.total != null && progress.total > 0
  const count = counted ? t(`count.${progress.unit ?? 'plain'}`, { done: progress.done, total: progress.total, count: progress.total }) : null
  const elapsed = progress ? now - Date.parse(progress.started_at) : null
  const etaMs = steady.eta === null ? null : steady.eta - now
  const endsMs = progress?.ends_by ? Date.parse(progress.ends_by) : null
  const finishing = openvas && ((progress?.percent ?? 0) >= OPENVAS_TAIL_PERCENT || (etaMs !== null && etaMs <= 0))
  const overdue = finishing && endsMs !== null && now > endsMs
  const stopBy = finishing && endsMs !== null && !overdue ? fmtTime(new Date(endsMs).toISOString()) : null
  const left = finishing || steady.slipped || etaMs === null || etaMs <= 0 ? null : etaMs < 60_000 ? t('leftSoon') : t('left', { time: sayDuration(t, Math.ceil(etaMs / 60_000) * 60_000) })
  // Past its estimate (a minute of grace: reports come every few seconds) or re-estimated later: say so instead of a time.
  const longer = !finishing && (steady.slipped || (etaMs !== null && etaMs <= -SLIP_MS))
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
        {percent !== null ? <span aria-hidden className="shrink-0 text-sm tabular-nums text-muted">{t('percent', { percent })}</span>
          : wrappingUp ? <span className="shrink-0 text-sm text-muted">{t('wrappingUp')}</span> : null}
      </div>
      <div
        role="progressbar"
        aria-label={step}
        aria-valuemin={0}
        aria-valuemax={100}
        aria-valuenow={percent ?? undefined}
        aria-valuetext={percent === null ? (wrappingUp ? t('wrappingUp') : undefined) : [t('percent', { percent }), count].filter(Boolean).join(', ')}
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
        {longer ? <span>{t('longer')}</span> : null}
        {stopBy ? <span>{t('finishing', { time: stopBy })}</span> : null}
        {overdue ? <span>{t('limitReached')}</span> : null}
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
