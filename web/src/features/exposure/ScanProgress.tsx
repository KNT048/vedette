import { useEffect, useRef } from 'react'
import { useTranslation } from 'react-i18next'
import { useQueryClient } from '@tanstack/react-query'
import { toast } from 'sonner'
import { Button } from '@/components/ui/button'
import { useCan } from '@/lib/session'
import { useScanRun, useStopScan } from './api'

/** A finished run that failed or was stopped stays on the page this long; a stale one from yesterday is not news. */
const SHOW_FINISHED_MS = 10 * 60_000

/** S-EXP-1: the progress of the scan that runs on the box. "Scan now" returns at once; this row polls GET /exposure/scan, shows the phase, lets an operator stop it, and
 *  when it ends brings the new snapshot in (or says why there is none). */
export function ScanProgress() {
  const { t } = useTranslation('exposure')
  const operator = useCan('operator')
  const qc = useQueryClient()
  const { data: run } = useScanRun()
  const stop = useStopScan()
  const wasRunning = useRef<string | null>(null)
  const status = run?.status
  useEffect(() => {
    if (!run) return
    if (run.status === 'running') { wasRunning.current = run.id; return }
    if (wasRunning.current !== run.id) return
    wasRunning.current = null
    void qc.invalidateQueries({ queryKey: ['exposure'] })
    if (run.status === 'done') toast.success(t('progress.done', { value: run.target_value }))
  }, [run, status, qc, t])
  if (!run) return null
  if (run.status === 'running') {
    return (
      <div role="status" className="mb-6 flex flex-wrap items-center gap-x-3 gap-y-1 rounded-md border border-rule bg-surface px-4 py-3 text-sm">
        <span className="font-medium">{t('progress.running', { value: run.target_value })}</span>
        <span className="text-muted">{t(`progress.phase.${run.phase}`)}</span>
        {operator ? <Button variant="secondary" size="sm" className="ml-auto" disabled={stop.isPending} onClick={() => stop.mutate(undefined, { onError: (e) => toast.error(e instanceof Error ? e.message : String(e)) })}>{t('progress.stop')}</Button> : null}
      </div>
    )
  }
  const recent = run.finished_at !== null && Date.now() - Date.parse(run.finished_at) < SHOW_FINISHED_MS
  if (run.status === 'done' || !recent) return null
  return (
    <p role="alert" className="mb-6 max-w-3xl text-sm text-warn">
      {run.status === 'stopped' ? t('progress.stopped', { value: run.target_value }) : (run.error?.message ?? t('progress.failed', { value: run.target_value }))}
    </p>
  )
}
