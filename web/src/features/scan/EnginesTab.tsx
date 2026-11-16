import { useEffect, useId, useState, type ReactNode } from 'react'
import { Link, useLocation } from 'react-router'
import { useTranslation } from 'react-i18next'
import { toast } from 'sonner'
import { ChevronDown } from 'lucide-react'
import { Panel, Section } from '@/components/common/PageHeader'
import { QueryState } from '@/components/common/States'
import { Chip, type Tone } from '@/components/common/StatusChip'
import { ScopeBadge } from '@/components/common/V1Scope'
import { JobProgress } from '@/components/progress/JobProgress'
import { Button } from '@/components/ui/button'
import { Dialog, DialogContent, DialogFooter } from '@/components/ui/dialog'
import { Switch } from '@/components/ui/switch'
import { fmtDateTime, fmtRelative } from '@/lib/format'
import { useCan } from '@/lib/session'
import { SnmpSection } from '@/features/inventory/SnmpSection'
import { GreenboneSetting } from '@/features/exposure/GreenbonePanel'
import { useScanRun } from '@/features/exposure/api'
import { isLive, useRuns, useSetEngine, useStopRun } from './api'
import { errMsg } from './errors'
import { NucleiSettings } from './NucleiSettings'
import { runHref } from './links'
import type { Engine, EngineId, EnginesResponse } from './types'

const GROUPS = ['discover', 'identify', 'vulns', 'traps'] as const
const STATE_TONE: Record<Engine['state'], Tone> = { off: 'off', idle: 'ok', queued: 'accent', running: 'accent', error: 'danger', needs_setup: 'warn', not_installed: 'off' }

/** Where an engine's settings live when they are not on its card: the page that owns them. */
const ELSEWHERE: Partial<Record<EngineId, string>> = {
  passive: '/devices/setup?tab=sensor', nmap_discovery: '/devices/setup', nmap_versions: '/devices/setup',
  osquery: '/devices/setup?tab=agents', wazuh: '/devices/setup?tab=agents', zap: '/exposure', honeypot: '/honeypot',
}
/** The engines whose own settings are on their card, behind "Settings". */
const OWN: Partial<Record<EngineId, (admin: boolean) => ReactNode>> = {
  // its API is admin only (GET /inventory/snmp)
  snmp: (admin) => (admin ? <SnmpSection /> : <SnmpAdminOnly />),
  nuclei: () => <NucleiSettings />,
  openvas: () => <GreenboneSetting embedded />,
}

function SnmpAdminOnly() {
  const { t } = useTranslation('scan')
  return <p className="text-[13px] text-muted">{t('engine.adminOnly')}</p>
}

/** A run of this engine going on now: its progress, from the read that owns it (a LAN scan run, or the exposure scan). */
function RunningNow({ e }: { e: Engine }) {
  const { t } = useTranslation('scan')
  const lan = e.module === 'exposure' ? null : e.id
  const runs = useRuns(lan !== null)
  const ex = useScanRun(lan === null)
  const can = useCan('operator')
  const stop = useStopRun()
  if (lan) {
    const live = runs.data?.items.find(isLive)
    if (!live) return null
    return (
      <div className="grid gap-2 rounded-md border border-rule bg-paper p-3">
        <div className="flex flex-wrap items-center gap-x-3 gap-y-1 text-sm">
          <span className="font-medium">{live.status === 'stopping' ? t('progress.stopping') : t('progress.device', { n: Math.min(live.done + 1, live.total), total: live.total })}</span>
          <Link to={runHref(live.id)} className="text-[13px] text-accent underline-offset-4 hover:underline">{t('scanNow.openRun')}</Link>
          {can ? <Button size="sm" variant="danger" className="ml-auto" disabled={live.status === 'stopping' || stop.isPending} onClick={() => stop.mutate(live.id, { onError: (err) => toast.error(errMsg(err)) })}>{t('progress.stop')}</Button> : null}
        </div>
        {live.status === 'stopping' ? null : <JobProgress progress={live.progress} />}
      </div>
    )
  }
  const run = ex.data
  if (run?.status !== 'running') return null
  return (
    <div className="grid gap-2 rounded-md border border-rule bg-paper p-3">
      <div className="flex flex-wrap items-center gap-x-3 gap-y-1 text-sm">
        <span className="font-medium">{t('engine.runningOn', { value: run.target_value })}</span>
        <Link to={`/exposure/${encodeURIComponent(run.target_id)}`} className="text-[13px] text-accent underline-offset-4 hover:underline">{t('engine.openTarget')}</Link>
      </div>
      <JobProgress progress={run.progress} />
    </div>
  )
}

function LastNext({ e }: { e: Engine }) {
  const { t } = useTranslation('scan')
  const always = e.id === 'passive' || e.id === 'honeypot' || e.id === 'osquery'
  const last = e.last_run
  return (
    <dl className="flex flex-wrap gap-x-6 gap-y-1 text-[13px]">
      <div className="flex gap-1.5"><dt className="whitespace-nowrap text-muted">{t('engine.cost')}</dt><dd className="tabular-nums">{t('engine.costValue', { ram: e.cost.ram_mb >= 1000 ? t('engine.gb', { n: (e.cost.ram_mb / 1000).toFixed(1) }) : t('engine.mb', { n: e.cost.ram_mb }), cpu: t(`engine.cpu.${e.cost.cpu}`) })}</dd></div>
      {always ? null : (
        <div className="flex gap-1.5"><dt className="whitespace-nowrap text-muted">{t('engine.last')}</dt>
          <dd>{last ? <time dateTime={last.at} title={fmtDateTime(last.at)}>{t(`engine.outcome.${last.outcome}`, { time: fmtRelative(last.at) })}</time> : t('engine.never')}
            {last?.summary ? <span className="text-muted">{t('engine.summary', { text: last.summary })}</span> : null}</dd></div>
      )}
      {always ? null : <div className="flex gap-1.5"><dt className="whitespace-nowrap text-muted">{t('engine.next')}</dt><dd>{e.next_run ? <time dateTime={e.next_run}>{fmtDateTime(e.next_run)}</time> : t('engine.onDemand')}</dd></div>}
    </dl>
  )
}

function EngineRow({ e, open, onOpen }: { e: Engine; open: boolean; onOpen: (v: boolean) => void }) {
  const { t } = useTranslation('scan')
  const admin = useCan('admin')
  const set = useSetEngine()
  const [confirm, setConfirm] = useState(false)
  const nameId = useId()
  const panelId = useId()
  const own = OWN[e.id]
  const elsewhere = ELSEWHERE[e.id]
  const change = (enabled: boolean) => set.mutate({ id: e.id, enabled }, {
    onSuccess: () => { setConfirm(false); toast.success(t(enabled ? 'engine.toastOn' : 'engine.toastOff', { name: t(`engines.${e.id}.name`) })) },
    onError: (err) => { setConfirm(false); toast.error(errMsg(err)) },
  })
  // a module that is off says so once, with the way to turn it on; its runs mean nothing then
  const modOff = e.toggle_blocked === 'module_off'
  const blocked = !e.can_toggle && e.toggle_blocked ? t(`engine.blocked.${e.toggle_blocked}`) : !admin ? t('common:needRole', { role: t('common:role.admin') }) : null
  return (
    <li id={`engine-${e.id}`} aria-labelledby={nameId} className="grid scroll-mt-24 gap-3 px-4 py-4">
      <div className="grid gap-3 sm:grid-cols-[minmax(0,1fr)_auto] sm:items-start">
        <div className="grid min-w-0 gap-1.5">
          <div className="flex flex-wrap items-center gap-2">
            <h3 id={nameId} className="text-sm font-semibold">{t(`engines.${e.id}.name`)}</h3>
            {e.preview ? <ScopeBadge scope="preview" /> : null}
            <Chip tone={STATE_TONE[e.state]}>{t(`engine.state.${e.state}`)}</Chip>
          </div>
          <p className="text-[13px] text-muted">{t(`engines.${e.id}.finds`)}</p>
          {e.state_detail && !modOff ? <p className={e.state === 'error' ? 'text-[13px] text-danger' : e.state === 'needs_setup' ? 'text-[13px] text-warn' : 'text-[13px]'}>{e.state_detail}</p> : null}
          {modOff ? null : <LastNext e={e} />}
        </div>
        <div className="flex items-center gap-2 sm:justify-end">
          <Switch id={`${e.id}-on`} checked={e.enabled} aria-labelledby={`${nameId} ${e.id}-on-text`} disabled={!!blocked || set.isPending}
            onCheckedChange={(v) => (v || e.state !== 'running' ? change(v) : setConfirm(true))} />
          <span id={`${e.id}-on-text`} className="text-sm">{e.enabled ? t('engine.on') : t('engine.off')}</span>
        </div>
      </div>
      {blocked && (admin || modOff) ? (
        <p className="text-[13px] text-muted">{blocked}{e.toggle_blocked === 'module_off' ? <> <Link to="/settings/modules" className="text-accent underline-offset-4 hover:underline">{t('engine.openModules')}</Link></> : null}</p>
      ) : null}
      {e.state === 'running' ? <RunningNow e={e} /> : null}
      {own ? (
        <div className="grid gap-3">
          <Button variant="ghost" size="sm" className="w-fit" aria-expanded={open} aria-controls={panelId} onClick={() => onOpen(!open)}>
            <ChevronDown className={open ? 'rotate-180' : ''} aria-hidden />{t('engine.settings')}
          </Button>
          {open ? <div id={panelId} className="min-w-0 border-l-2 border-rule pl-4">{own(admin)}</div> : null}
        </div>
      ) : elsewhere ? (
        <Link to={elsewhere} className="w-fit text-[13px] text-accent underline-offset-4 hover:underline">{t(`engines.${e.id}.where`)}</Link>
      ) : null}
      <Dialog open={confirm} onOpenChange={setConfirm}>
        <DialogContent title={t('engine.stopTitle', { name: t(`engines.${e.id}.name`) })} description={t('engine.stopBody')}>
          <DialogFooter>
            <Button onClick={() => setConfirm(false)}>{t('common:cancel')}</Button>
            <Button variant="danger" disabled={set.isPending} onClick={() => change(false)}>{t('engine.stopConfirm')}</Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </li>
  )
}

function Groups({ d }: { d: EnginesResponse }) {
  const { t } = useTranslation('scan')
  const { hash } = useLocation()
  const target = hash.slice(1)
  // a deep link (/settings/scanning#snmp, the engine's settings_href) opens that card's settings and scrolls to it
  const [open, setOpen] = useState<Set<string>>(() => new Set(OWN[target as EngineId] ? [target] : []))
  useEffect(() => {
    if (target) document.getElementById(`engine-${target}`)?.scrollIntoView({ block: 'start' })
  }, [target])
  return (
    <>
      {GROUPS.map((g) => {
        const list = d.items.filter((e) => e.group === g)
        if (!list.length) return null
        return (
          <Section key={g} id={`group-${g}`} title={t(`group.${g}.title`)} description={t(`group.${g}.description`)} info={t(`group.${g}.info`)}>
            <Panel>
              <ul className="divide-y divide-rule">
                {list.map((e) => <EngineRow key={e.id} e={e} open={open.has(e.id)} onOpen={(v) => setOpen((s) => { const n = new Set(s); if (v) n.add(e.id); else n.delete(e.id); return n })} />)}
              </ul>
            </Panel>
          </Section>
        )
      })}
    </>
  )
}

export function EnginesTab({ q }: { q: { data: EnginesResponse | undefined; error: unknown; isPending: boolean; refetch: () => unknown } }) {
  const { hash } = useLocation()
  // a new #engine opens that card: the groups start again from the link
  return <QueryState query={q}>{(d) => <Groups key={hash} d={d} />}</QueryState>
}
