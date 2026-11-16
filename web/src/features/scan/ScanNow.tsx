import { useState } from 'react'
import { Link } from 'react-router'
import { useTranslation } from 'react-i18next'
import { toast } from 'sonner'
import { Play, ScanSearch } from 'lucide-react'
import { JobProgress } from '@/components/progress/JobProgress'
import { Button } from '@/components/ui/button'
import { Tooltip } from '@/components/ui/tooltip'
import type { JobProgress as Progress } from '@/lib/progress'
import { useModuleEnabled } from '@/lib/modules'
import { useCan } from '@/lib/session'
import { cn } from '@/lib/utils'
import { isLive, useEngines, useRuns, useScanConfig, useStartRun, useTargets } from './api'
import { errMsg } from './errors'
import { lanTargets, MAX_TARGETS, runHref } from './links'

type Look = { label?: string; variant?: 'primary' | 'secondary'; size?: 'sm' | 'md'; className?: string }

/** Any other job (the exposure deep scan): the caller starts it and owns its state; this gives it the same button and progress. */
export type ScanNowJob = Look & {
  onStart: () => void
  running: boolean
  /** The button's words while it runs (default "Scanning…"). */
  runningLabel?: string
  pending?: boolean
  /** Why it cannot start now, shown under the button; null when it can. */
  blocked?: string | null
  /** The running job's progress; `undefined` shows none here (the page shows it elsewhere, e.g. its own progress row). */
  progress?: Progress | null
  describedBy?: string
}
/** A LAN scan (POST /scans/runs): device ids a person chose (a device page, the Devices list selection) or the whole LAN. */
export type ScanNowLan = Look & { targets: string[] | 'lan'; /** Show the progress under the button while the run it started goes on (default true). */ showProgress?: boolean }

/**
 * #850: Scan now where the person is (S-SCAN-1). The device page ("Check this device now"), the Devices list ("Scan selected",
 * "Scan the LAN now") and an exposure target ("Deep scan now") place it; while the run goes on it shows JobProgress (#834) under
 * the button and a link to the run, never a modal. One scan runs at a time on the box: another one running locks it with the reason.
 */
export function ScanNowButton(props: ScanNowLan | ScanNowJob) {
  return 'onStart' in props ? <JobButton {...props} /> : <LanButton {...props} />
}

function JobButton({ label, runningLabel, variant = 'primary', size, className, onStart, running, pending, blocked, progress, describedBy }: ScanNowJob) {
  const { t } = useTranslation('scan')
  return (
    <div className={cn('grid min-w-0 gap-2', className)}>
      <Button variant={variant} size={size} className="w-fit" onClick={onStart} disabled={!!blocked || running || pending} title={blocked ?? undefined} aria-describedby={describedBy}>
        <Play />{running || pending ? runningLabel ?? t('scanNow.running') : label ?? t('scanNow.deep')}
      </Button>
      {running && progress !== undefined ? <JobProgress progress={progress} /> : null}
    </div>
  )
}

function LanButton({ targets, label, variant = 'primary', size, className, showProgress = true }: ScanNowLan) {
  const { t } = useTranslation('scan')
  const on = useModuleEnabled('scan') === true
  const can = useCan('operator')
  const runs = useRuns(on)
  const cfg = useScanConfig(on)
  const all = useTargets(on && targets === 'lan')
  const start = useStartRun()
  const [mine, setMine] = useState<string | null>(null)
  const live = runs.data?.items.find(isLive)
  const ids = targets === 'lan' ? (all.data ? lanTargets(all.data.items) : []) : targets
  const text = label ?? (targets === 'lan' ? t('scanNow.lan') : targets.length === 1 ? t('scanNow.device') : t('scanNow.selected', { count: targets.length }))
  const blocked = !on ? t('scanNow.moduleOff')
    : !can ? t('common:needRole', { role: t('common:role.operator') })
    : cfg.data && !cfg.data.can_scan ? cfg.data.block_reason
    : live && live.id !== mine ? t('scanNow.otherRunning')
    : runs.data?.engine_busy ? t('start.engineBusy')
    : targets === 'lan' && all.data && ids.length === 0 ? t('scanNow.lanNone')
    : targets !== 'lan' && ids.length === 0 ? t('start.none')
    : ids.length > MAX_TARGETS ? t('start.tooMany', { max: MAX_TARGETS, count: ids.length }) : null
  const ours = live && live.id === mine ? live : null
  return (
    <div className={cn('grid min-w-0 gap-2', className)}>
      <div className="flex flex-wrap items-center gap-x-3 gap-y-1">
        <Button variant={variant} size={size} disabled={!!blocked || !!ours || start.isPending || (targets === 'lan' && !all.data)}
          onClick={() => start.mutate(ids, { onSuccess: (r) => { setMine(r.id); toast.success(t('start.started')) }, onError: (e) => toast.error(errMsg(e)) })}>
          <Play />{ours || start.isPending ? t('scanNow.running') : text}
        </Button>
        {blocked && !ours ? <span className="text-meta text-muted">{blocked}{live && live.id !== mine ? <> <Link to={runHref(live.id)} className="text-accent underline-offset-4 hover:underline">{t('scanNow.openRun')}</Link></> : null}</span> : null}
      </div>
      {ours && showProgress ? (
        <div className="grid gap-2 rounded-md border border-rule bg-surface p-3">
          <div className="flex flex-wrap items-center justify-between gap-2 text-sm">
            <span className="font-medium">{ours.status === 'stopping' ? t('progress.stopping') : t('progress.device', { n: Math.min(ours.done + 1, ours.total), total: ours.total })}</span>
            <Link to={runHref(ours.id)} className="text-meta text-accent underline-offset-4 hover:underline">{t('scanNow.openRun')}</Link>
          </div>
          {ours.status === 'stopping' ? null : <JobProgress progress={ours.progress} />}
        </div>
      ) : null}
    </div>
  )
}

/**
 * #850: the small "1 scan running" of the top bar; it opens the run. Nothing while no scan runs, or while the scan module is off
 * (its read would be 404). The same read as Settings › Scanning (GET /scans/engines, read every 10 s only while one runs).
 */
export function ScansRunningIndicator({ className, compact = false }: { className?: string; compact?: boolean }) {
  const { t } = useTranslation('scan')
  const on = useModuleEnabled('scan') === true
  const q = useEngines(on)
  const running = q.data?.running ?? []
  if (!on || running.length === 0) return null
  const one = running.length === 1 ? running[0]! : null
  const to = one ? (one.engine === 'nuclei' ? runHref(one.run_id) : `/settings/scanning?tab=engines#${one.engine}`) : '/settings/scanning?tab=engines'
  const label = t('running.count', { count: running.length })
  const link = (
    <Link to={to} aria-label={label} className={cn('inline-flex h-8 items-center gap-2 rounded-md border border-rule bg-accent-soft text-meta font-medium text-ink hover:bg-sunken', compact ? 'px-2' : 'px-3', className)}>
      <ScanSearch className="size-4 text-accent" aria-hidden />
      <span aria-hidden className={compact ? 'tabular-nums' : undefined}>{compact ? running.length : label}</span>
    </Link>
  )
  // compact (the phone top bar, the rail): the number only, its name in the shared Tooltip (the link's own label already says it)
  return compact ? <Tooltip content={label} describe={false}>{link}</Tooltip> : link
}
