import { useEffect, useRef } from 'react'
import { useTranslation } from 'react-i18next'
import { useQueryClient } from '@tanstack/react-query'
import { toast } from 'sonner'
import { InfoTip } from '@/components/common/InfoTip'
import { JobProgress } from '@/components/progress/JobProgress'
import { Button } from '@/components/ui/button'
import { useCan } from '@/lib/session'
import { useScanRun, useStopScan, useUnqueue } from './api'
import type { ScanRun } from './types'

/** A finished run that failed or was stopped stays on the page this long; a stale one from yesterday is not news. */
const SHOW_FINISHED_MS = 10 * 60_000

/** Where target id stands in the box's queue (INV-36): its place (0 = next) and the target it waits for; null when it does not wait. */
export function queuePlace(run: ScanRun | null | undefined, id: string): { index: number; after: string | null } | null {
  const q = run?.queue ?? []
  const index = q.findIndex((x) => x.target_id === id)
  if (index < 0) return null
  const after = index > 0 ? q[index - 1]!.target_value : run?.status === 'running' ? run.target_value : null
  return { index, after }
}

/** S-EXP-1: the progress of the scan that runs on the box. "Scan now" returns at once; this row polls GET /exposure/scan, shows the phase, lets an operator stop it, and
 *  when it ends brings the new snapshot in (or says why there is none). On a target's page (targetId) it shows that target's run only: another target's
 *  scan is one line, and a scan of this target that waits in the queue shows its place (INV-36). */
export function ScanProgress({ targetId }: { targetId?: string } = {}) {
  const { t } = useTranslation('exposure')
  const operator = useCan('operator')
  const qc = useQueryClient()
  const { data: run } = useScanRun()
  const stop = useStopScan()
  const unqueue = useUnqueue()
  const wasRunning = useRef<string | null>(null)
  const savedFor = useRef<string | null>(null)
  const queueSig = useRef<string>('')
  const status = run?.status
  const phase = run?.phase
  useEffect(() => {
    if (!run) return
    // INV-36: a scan that leaves the queue (it starts, or could not) changes the state of its target
    const sig = `${run.id}:${(run.queue ?? []).map((q) => q.target_id).join(',')}`
    if (queueSig.current && queueSig.current !== sig) {
      void qc.invalidateQueries({ queryKey: ['exposure', 'target'] })
      void qc.invalidateQueries({ queryKey: ['exposure', 'targets'] })
    }
    queueSig.current = sig
    // The other results are saved when OpenVAS starts: show them, with "OpenVAS is scanning", without waiting 90 minutes
    if (run.status === 'running' && run.phase === 'greenbone' && savedFor.current !== run.id) {
      savedFor.current = run.id
      void qc.invalidateQueries({ queryKey: ['exposure'] })
    }
    if (run.status === 'running') { wasRunning.current = run.id; return }
    if (wasRunning.current !== run.id) return
    wasRunning.current = null
    void qc.invalidateQueries({ queryKey: ['exposure'] })
    if (run.status === 'done' && (!targetId || run.target_id === targetId)) toast.success(t(run.openvas_only ? 'progress.doneAgain' : 'progress.done', { value: run.target_value }))
  }, [run, status, phase, qc, t, targetId])
  if (!run) return null
  const place = targetId ? queuePlace(run, targetId) : null
  if (place) {
    const value = run.queue![place.index]!.target_value
    const starting = run.queue![place.index]!.starting
    return (
      <div className="mb-6 flex flex-wrap items-center gap-x-3 gap-y-1 rounded-md border border-rule bg-surface px-4 py-3 text-sm">
        <p role="status" className="font-medium">{place.after ? t('progress.queuedAfter', { value: place.after }) : t('progress.queuedNext')}</p>
        <InfoTip topic={t('progress.queuedTopic')}>{t('progress.queuedInfo')}</InfoTip>
        {operator && !starting ? <Button variant="secondary" size="sm" className="ml-auto" busy={unqueue.isPending} busyLabel={t('common:busy.removing')}
          onClick={() => unqueue.mutate(targetId!, { onSuccess: () => toast.success(t('progress.unqueued', { value })), onError: (e) => toast.error(e instanceof Error ? e.message : String(e)) })}>{t('progress.unqueue')}</Button> : null}
      </div>
    )
  }
  const mine = !targetId || run.target_id === targetId
  if (run.status === 'running' && !mine) {
    return <p role="status" className="mb-6 max-w-3xl text-meta text-muted">{t('progress.other', { value: run.target_value })}</p>
  }
  const waiting = !targetId && run.queue?.length ? <p className="text-meta text-muted">{t('progress.waiting', { count: run.queue.length, list: run.queue.map((q) => q.target_value).join(', ') })}</p> : null
  if (run.status === 'running') {
    // #830: the step's own progress under the row. Only the row is a status region: the step bar announces its step changes itself, never its ticking time.
    return (
      <div className="mb-6 grid gap-3 rounded-md border border-rule bg-surface px-4 py-3 text-sm">
        <div className="flex flex-wrap items-center gap-x-3 gap-y-1">
          <p role="status" className="flex flex-wrap items-center gap-x-3 gap-y-1">
            <span className="font-medium">{t(run.openvas_only ? 'progress.runningAgain' : 'progress.running', { value: run.target_value })}</span>
            {run.progress && run.phase !== 'greenbone' ? null : <span className="text-muted">{t(`progress.phase.${run.phase}`)}</span>}
          </p>
          {run.phase === 'greenbone' ? <InfoTip topic={t('progress.greenboneTopic')}>{t('progress.greenboneInfo')}</InfoTip> : null}
          {operator ? <Button variant="secondary" size="sm" className="ml-auto" busy={stop.isPending} busyLabel={t('common:busy.stopping')} onClick={() => stop.mutate(undefined, { onError: (e) => toast.error(e instanceof Error ? e.message : String(e)) })}>{t('progress.stop')}</Button> : null}
        </div>
        {run.progress ? <JobProgress progress={run.progress} /> : null}
        {waiting}
      </div>
    )
  }
  if (!mine) return null
  const recent = run.finished_at !== null && Date.now() - Date.parse(run.finished_at) < SHOW_FINISHED_MS
  if (run.status === 'done' || !recent) return null
  return (
    <p role="alert" className="mb-6 max-w-3xl text-sm text-warn">
      {run.status === 'stopped' ? t(run.snapshot_id ? 'progress.stoppedKept' : 'progress.stopped', { value: run.target_value }) : (run.error?.message ?? t('progress.failed', { value: run.target_value }))}
      {run.status === 'stopped' && run.stop_reason ? ` ${t('progress.stopReason', { why: run.stop_reason })}` : null}
    </p>
  )
}
