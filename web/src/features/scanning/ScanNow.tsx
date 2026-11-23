import { useState } from 'react'
import { Link, useLocation } from 'react-router'
import { useTranslation } from 'react-i18next'
import { toast } from 'sonner'
import { Play, ScanSearch } from 'lucide-react'
import { Card } from '@/components/common/Card'
import { JobProgress } from '@/components/progress/JobProgress'
import { Button } from '@/components/ui/button'
import { Tooltip } from '@/components/ui/tooltip'
import type { JobProgress as Progress } from '@/lib/progress'
import { useCan } from '@/lib/session'
import { cn } from '@/lib/utils'
import { useRunDiscovery, useScanning } from './api'
import { ScopeButton } from './Fixes'
import { isHere, runHref, runsHref } from './places'
import { runningLabel } from './runningLabel'

const errMsg = (e: unknown) => (e instanceof Error ? e.message : String(e))

/** The most devices one run takes (contract.ts DiscoveryRunInput.targets max). */
const MAX_RUN_TARGETS = 64

type Look = { label?: string; variant?: 'primary' | 'secondary'; size?: 'sm' | 'md'; className?: string; /** The id of a line that says what the button does. */ describedBy?: string }

/** Any other job (the exposure deep scan): the caller starts it and owns its state; this gives it the same button and progress. */
export type ScanNowJob = Look & {
  onStart: () => void
  running: boolean
  /** The button's words while it runs (default "Scanning…"). */
  runningLabel?: string
  pending?: boolean
  /** Why it cannot start now, shown under the button (and as its title); null when it can. */
  blocked?: string | null
  /** The running job's progress; `undefined` shows none here (the page shows it elsewhere, e.g. its own progress row). */
  progress?: Progress | null
  describedBy?: string
}
/** A LAN check with nmap (POST /scanning/engines/nmap-discovery/run): device ids or IPs (a device page, the Devices list
 *  selection) or the whole LAN scope, which the server resolves (never the box, never outside the scope or the exclusions). */
export type ScanNowLan = Look & { targets: string[] | 'lan'; /** Show the progress under the button while its run goes on, and a link to a run in its way (default true); off where the page shows the runs itself or the button repeats on rows. */ showProgress?: boolean }

/**
 * #850: Scan now where the person is (S-INV-1, S-SCAN-1): "Check this device now" (one device), "Scan selected (N)", "Scan the LAN
 * now", and "Deep scan now" on a public target (job mode). While its run goes on it shows JobProgress (#834) under the button and a
 * link to where the run is seen; never a modal. What it needs and does not have says so where it is, with the way to fix it there
 * (docs/UI.md §0): the scope commitment opens its dialog, network discovery off is turned on from here.
 */
export function ScanNowButton(props: ScanNowLan | ScanNowJob) {
  return 'onStart' in props ? <JobButton {...props} /> : <LanButton {...props} />
}

function JobButton({ label, runningLabel, variant = 'primary', size, className, onStart, running, pending, blocked, progress, describedBy }: ScanNowJob) {
  const { t } = useTranslation('scanning')
  return (
    <div className={cn('grid min-w-0 gap-2', className)}>
      <Button variant={variant} size={size} className="w-fit" onClick={onStart} disabled={!!blocked || running} busy={!!pending} busyLabel={runningLabel ?? t('scanNow.running')} title={blocked ?? undefined} aria-describedby={describedBy}>
        <Play />{label ?? t('scanNow.deep')}
      </Button>
      {blocked && !describedBy ? <span className="text-meta text-muted">{blocked}</span> : null}
      {running && progress !== undefined ? <JobProgress progress={progress} /> : null}
    </div>
  )
}

function LanButton({ targets, label, variant = 'primary', size, className, showProgress = true, describedBy }: ScanNowLan) {
  const { t } = useTranslation('scanning')
  const admin = useCan('admin')
  const q = useScanning()
  const run = useRunDiscovery()
  const [mine, setMine] = useState<string | null>(null)
  const disc = q.data?.engines.find((e) => e.id === 'nmap-discovery')
  const running = q.data?.running ?? []
  // review r1 of #944: one check per device at a time: a run of this one device started anywhere (another row, the device page) is
  // ours too, so every button for that device shows it running
  const ours = running.find((j) => j.id === mine) ?? (targets !== 'lan' && targets.length === 1 ? running.find((j) => j.engine === 'nmap-discovery' && j.target_id === targets[0]) ?? null : null)
  // A busy scanner never blocks a person's ask: the box queues it behind the run in its way and says so (its progress line). The one
  // refusal left is a second LAN sweep while one goes on: that sweep is the answer, so the button points at it instead.
  const sweeping = targets === 'lan' && !ours ? running.find((j) => j.engine === 'nmap-discovery' && j.target_id === null && j.label.startsWith('LAN sweep') && j.id !== mine) ?? null : null
  // the person's own run waits for the scanner: its button says queued, not scanning
  const queued = !!ours?.queued
  const finished = !!mine && !ours && !!q.data && !run.isPending
  const ids = targets === 'lan' ? [] : targets
  const text = label ?? (targets === 'lan' ? t('scanNow.lan') : ids.length === 1 ? t('scanNow.device') : t('scanNow.selected', { count: ids.length }))
  const needsScope = !!q.data && !q.data.safety.scope.confirmed_at
  // the reason it cannot start, and the fix where it is (docs/UI.md §0)
  const blocked = !admin ? t('common:needRole', { role: t('common:role.admin') })
    : !disc ? null
    : needsScope ? t('scanNow.needsScope')
    : !disc.enabled ? t('scanNow.discoveryOff')
    : disc.state === 'unavailable' || disc.state === 'error' ? disc.reason
    : sweeping ? t(sweeping.queued ? 'scanNow.sweepQueued' : 'scanNow.sweepRunning')
    : targets !== 'lan' && ids.length === 0 ? t('scanNow.none')
    : ids.length > MAX_RUN_TARGETS ? t('scanNow.tooMany', { max: MAX_RUN_TARGETS, count: ids.length }) : null
  return (
    <div className={cn('grid min-w-0 gap-2', className)}>
      <div className="flex flex-wrap items-center gap-x-3 gap-y-1">
        <Button variant={variant} size={size} disabled={!q.data || !!blocked} busy={run.isPending || !!ours} busyLabel={t(queued ? 'scanNow.queued' : 'scanNow.running')} aria-describedby={describedBy}
          onClick={() => run.mutate(targets === 'lan' ? undefined : ids, {
            onSuccess: (j) => {
              setMine(j.id)
              if (j.queued) toast.success(t('scanNow.queuedToast'), { description: j.progress?.message ?? undefined })
              else toast.success(t('scanNow.started'))
            },
            onError: (e) => toast.error(errMsg(e)),
          })}>
          <Play />{text}
        </Button>
        {blocked && !ours ? (
          <span className="flex flex-wrap items-center gap-2 text-meta text-muted">
            <span>{blocked}</span>
            {/* a sweep that waits says for what (the box's own line: the run in its way and when it starts) */}
            {sweeping?.queued && sweeping.progress?.message ? <span>{sweeping.progress.message}</span> : null}
            {admin && needsScope ? <ScopeButton /> : null}
            {admin && !needsScope && disc && !disc.enabled ? <Link to="/settings/scanning?tab=engines#engine-nmap-discovery-switch" className="text-accent underline underline-offset-4">{t('scanNow.turnOnDiscovery')}</Link> : null}
            {/* the run in the way opens from the button's own place; a row of a list (showProgress off) leaves it to the page, so a
                list never repeats the same link on every row */}
            {sweeping && showProgress ? <Link to={runHref(sweeping.id)} className="text-accent underline-offset-4 hover:underline">{t('scanNow.openRun')}</Link> : null}
          </span>
        ) : null}
      </div>
      {finished ? <p role="status" className="text-meta text-muted">{t('scanNow.finished')} <Link to={targets === 'lan' || ids.length !== 1 ? '/devices' : `/devices/${encodeURIComponent(ids[0]!)}`} className="text-accent underline-offset-4 hover:underline">{t(targets === 'lan' || ids.length !== 1 ? 'scanNow.seeDevices' : 'scanNow.seeDevice')}</Link></p> : null}
      {ours && showProgress ? (
        <Card className="grid gap-2">
          <div className="flex flex-wrap items-center justify-between gap-2 text-sm">
            <span className="font-medium">{ours.label}</span>
            <Link to={runHref(ours.id)} className="text-meta text-accent underline-offset-4 hover:underline">{t('scanNow.openRun')}</Link>
          </div>
          <JobProgress progress={ours.progress} />
        </Card>
      ) : null}
    </div>
  )
}

/**
 * #850: "1 scan running" in the shell (phone top bar, sidebar foot, `shell.status` slot): one run opens its run page, several open the
 * Runs tab with the runs going on (all runs when some wait). Every engine's runs, the public scans included, from the one read of GET
 * /scanning; the runs that wait for the scanner are counted apart ("1 scan running, 2 queued"). On the page it would open it is a
 * status, not a link to the page you are on.
 */
export function ScansRunningIndicator({ className, compact = false }: { className?: string; compact?: boolean }) {
  const { t } = useTranslation('scanning')
  const here = useLocation()
  const q = useScanning()
  const running = q.data?.running ?? []
  if (running.length === 0) return null
  const label = runningLabel(t, running)
  const to = running.length === 1 ? runHref(running[0]!.id) : runsHref(running.some((j) => j.queued) ? {} : { status: 'running' })
  const look = cn('inline-flex h-8 items-center gap-2 rounded-md border border-rule bg-accent-soft text-meta font-medium text-ink', compact ? 'px-2' : 'px-3', className)
  const body = (
    <>
      <ScanSearch className="size-4 text-accent" aria-hidden />
      <span aria-hidden className={compact ? 'tabular-nums' : undefined}>{compact ? running.length : label}</span>
    </>
  )
  const item = isHere(to, here)
    ? <span role="status" aria-label={label} className={look}>{body}</span>
    : <Link to={to} aria-label={label} className={cn(look, 'hover:bg-sunken')}>{body}</Link>
  // compact (the phone top bar, the rail): the number only, its name in the shared Tooltip (the link's own label already says it)
  return compact ? <Tooltip content={label} describe={false}>{item}</Tooltip> : item
}
