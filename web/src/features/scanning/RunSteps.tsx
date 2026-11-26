import { useTranslation } from 'react-i18next'
import { Circle, CircleAlert, CircleCheck, CircleMinus, CirclePause, CircleSlash2, CircleX, LoaderCircle, type LucideIcon } from 'lucide-react'
import { fmtDateTime, fmtTime } from '@/lib/format'
import { cn } from '@/lib/utils'
import { RunBar, useRunCount } from './RunParts'
import type { RunStep, StepStatus } from './types'

/** One icon and colour per step state, the way a CI job lists its steps: a check when done, a spinner while it runs, a cross when it
 *  failed, an empty circle while it waits its turn, a crossed circle when it did not run. The words are always there too. */
const look: Record<StepStatus, { icon: LucideIcon; tone: string; spin?: boolean }> = {
  queued: { icon: Circle, tone: 'text-muted' },
  waiting: { icon: CirclePause, tone: 'text-muted' },
  running: { icon: LoaderCircle, tone: 'text-accent', spin: true },
  stopping: { icon: LoaderCircle, tone: 'text-accent', spin: true },
  done: { icon: CircleCheck, tone: 'text-ok' },
  partial: { icon: CircleAlert, tone: 'text-warn' },
  failed: { icon: CircleX, tone: 'text-danger' },
  stopped: { icon: CircleMinus, tone: 'text-warn' },
  skipped: { icon: CircleSlash2, tone: 'text-muted' },
}

/** How long a step took or has run: "12 s", "2 min 10 s", "1 h 5 min"; null under a second (a step that only says what others did). */
export function useStepDuration() {
  const { t } = useTranslation('scanning')
  return (from: string, to: string | null, now = Date.now()): string | null => {
    const s = Math.floor(((to ? new Date(to).getTime() : now) - new Date(from).getTime()) / 1000)
    if (!(s >= 1)) return null
    if (s < 60) return t('runs.step.seconds', { s })
    if (s < 3600) return s % 60 ? t('runs.step.minSec', { m: Math.floor(s / 60), s: s % 60 }) : t('runs.step.minutes', { m: Math.floor(s / 60) })
    const m = Math.floor((s % 3600) / 60)
    return m ? t('runs.step.hourMin', { h: Math.floor(s / 3600), m }) : t('runs.step.hours', { h: Math.floor(s / 3600) })
  }
}

/** When a step ran, in one short line: "14:02 · 2 min 10 s", "14:02 · running for 3 min", or its state when it never started. */
function When({ s }: { s: RunStep }) {
  const { t } = useTranslation('scanning')
  const took = useStepDuration()
  const live = s.status === 'running' || s.status === 'stopping'
  const word = s.status === 'done' ? null : t(`runs.stepStatus.${s.status}`)
  if (!s.started_at) return <span className="text-caption text-muted">{word}</span>
  const d = took(s.started_at, live ? null : s.ended_at)
  const parts = [word, fmtTime(s.started_at), d ? (live ? t('runs.step.runningFor', { d }) : d) : null].filter(Boolean)
  const title = [t('runs.step.startedAt', { at: fmtDateTime(s.started_at) }), s.ended_at ? t('runs.step.endedAt', { at: fmtDateTime(s.ended_at) }) : null].filter(Boolean).join('. ')
  return <span className="text-caption tabular-nums text-muted" title={title}>{parts.join(' · ')}</span>
}

/**
 * The steps of a run in the order they run, each with its state (an icon and its word), when it ran and how long, and its note: while
 * it runs where it is ("finding open ports: 41%"), once it ended what it found, and when it did not run why. `compact` is the same
 * list inside another page (a target's Scans tab).
 */
export function RunSteps({ steps, compact = false, label }: { steps: RunStep[]; compact?: boolean; label: string }) {
  const { t } = useTranslation('scanning')
  const count = useRunCount()
  return (
    <ol aria-label={label} className="divide-y divide-rule">
      {steps.map((s) => {
        const l = look[s.status]
        const Icon = l.icon
        const quiet = s.status === 'queued' || s.status === 'skipped'
        // a step that counts more than one unit (the ranges of a sweep) shows its count and bar; one that counts itself as one step
        // (an exposure scan's) says where it is in its note instead
        const counts = s.total > 1
        return (
          <li key={s.seq} className={cn('grid grid-cols-[1rem_minmax(0,1fr)] gap-x-3', compact ? 'px-3 py-2' : 'px-4 py-3')}>
            <Icon aria-hidden className={cn('mt-0.5 size-4', l.tone, l.spin && 'motion-safe:animate-spin')} />
            <div className="grid min-w-0 gap-1">
              <div className="flex flex-wrap items-baseline justify-between gap-x-3 gap-y-0.5">
                <span className={cn('text-sm [overflow-wrap:anywhere]', quiet ? 'text-muted' : 'font-medium text-ink')}>
                  <span className="sr-only">{t(`runs.stepStatus.${s.status}`)}: </span>{s.name}
                  {counts ? <span className="ml-2 text-caption font-normal tabular-nums text-muted">{count(s)}</span> : null}
                </span>
                <When s={s} />
              </div>
              {counts && (s.status === 'running' || s.status === 'waiting') ? <div className="max-w-xl"><RunBar done={s.done} total={s.total} label={t('runs.progressOf', { title: s.name })} /></div> : null}
              {s.note ? (
                <p className={cn('text-meta [overflow-wrap:anywhere] first-letter:uppercase', s.status === 'failed' ? 'text-danger' : s.status === 'partial' || s.status === 'stopped' ? 'text-warn' : 'text-muted')}>{s.note}</p>
              ) : null}
            </div>
          </li>
        )
      })}
    </ol>
  )
}

/** "3 of 8 steps done", or how many failed when some did. */
export function useStepsLine() {
  const { t } = useTranslation('scanning')
  return (steps: RunStep[]): string => {
    const ended = steps.filter((s) => !['queued', 'waiting', 'running', 'stopping'].includes(s.status)).length
    const failed = steps.filter((s) => s.status === 'failed').length
    const line = t('runs.stepsDone', { done: ended, count: steps.length })
    return failed ? `${line} · ${t('runs.stepsFailed', { count: failed })}` : line
  }
}
