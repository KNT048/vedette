import { useEffect, useId, useState, type ReactNode } from 'react'
import { Link, useLocation } from 'react-router'
import { useTranslation } from 'react-i18next'
import { toast } from 'sonner'
import { Card } from '@/components/common/Card'
import { DependencyLink } from '@/components/common/DependencyLink'
import { Notice, Section } from '@/components/common/PageHeader'
import { Chip, type Tone } from '@/components/common/StatusChip'
import { ScopeBadge } from '@/components/common/V1Scope'
import { JobProgress } from '@/components/progress/JobProgress'
import { Button } from '@/components/ui/button'
import { Dialog, DialogContent, DialogFooter } from '@/components/ui/dialog'
import { Switch } from '@/components/ui/switch'
import { GreenboneSetting } from '@/features/exposure/GreenbonePanel'
import { OsqueryEnrol, WazuhForm } from '@/features/inventory/AgentsSection'
import { useAgents } from '@/features/inventory/api'
import { SnmpDevices } from '@/features/inventory/SnmpCard'
import { NucleiSettings } from '@/features/scan/NucleiSettings'
import { ScheduleEditor } from '@/components/schedule/ScheduleEditor'
import { VulnChecksButton } from '@/features/scan/VulnChecksButton'
import { useStopRun } from '@/features/scan/api'
import { ApiError } from '@/lib/api'
import { fmtDateTime, fmtRelative } from '@/lib/format'
import { useModuleEnabled } from '@/lib/modules'
import { useCan } from '@/lib/session'
import { useSetEngine } from './api'
import { ScopeButton, ScopeDialog, TurnOnModule } from './Fixes'
import { AlertChannels } from './AlertChannels'
import { runHref } from './places'
import { ScanNowButton } from './ScanNow'
import { InfoLine } from '@/components/common/InfoLine'
import type { Engine, EngineId, Scanning } from './types'
import { ExpandToggle } from '@/components/common/ListParts'

const GROUPS = ['discover', 'identify', 'vuln', 'traps'] as const
const STATE_TONE: Record<Engine['state'], Tone> = { off: 'off', needs_setup: 'warn', starting: 'accent', ready: 'ok', running: 'accent', error: 'danger', unavailable: 'off' }

/** Where an engine's own settings live when they are not on its card (docs/UI.md §0: the exact tab and field). #sensors and #agents
 *  are Devices › Setup's old hashes (OldHashToTab drops them): the tab, or a field id of it (#877). */
const PLACE: Partial<Record<EngineId, string>> = {
  passive: '/devices/setup?tab=sensor',
  'nmap-versions': '/settings/scanning?tab=safety#fragile',
  osquery: '/devices/setup?tab=agents', wazuh: '/devices/setup?tab=wazuh',
  zap: '/exposure?tab=targets#targets', honeypot: '/honeypot?tab=trap-ips',
}
/** Devices › Setup is an administrator's page (a forbidden page for the others): its links are not offered to them (#877 r1 L8). */
const ADMIN_PLACE = (to: string) => to.startsWith('/devices/setup')

const errMsg = (e: unknown) => (e instanceof Error ? e.message : String(e))
/** Memory the box reports in MiB, said in decimal GB and MB like every other size on the screens (OpenVAS says "7.5 GB" for the same box). */
const mb = (n: number) => { const bytes = n * 1024 * 1024; return bytes >= 1e9 ? `${(bytes / 1e9).toFixed(1)} GB` : `${Math.round(bytes / 1e6)} MB` }

/** osquery: the token and its install commands, made here (POST /inventory/agents/tokens; §0). */
function OsqueryDialog({ onClose }: { onClose: () => void }) {
  const { t } = useTranslation('scanning')
  const q = useAgents()
  return (
    <Dialog open onOpenChange={(v) => { if (!v) onClose() }}>
      <DialogContent wide title={t('fix.osqueryTitle')} description={t('fix.osqueryDescription')}>
        {q.data ? <OsqueryEnrol data={q.data} /> : <p className="text-meta text-muted">{t('fix.loading')}</p>}
      </DialogContent>
    </Dialog>
  )
}

/** Wazuh: the server connection, tested and saved here (POST /inventory/agents/wazuh/test, PUT /inventory/agents/wazuh; §0). */
function WazuhDialog({ onClose }: { onClose: () => void }) {
  const { t } = useTranslation('scanning')
  return (
    <Dialog open onOpenChange={(v) => { if (!v) onClose() }}>
      <DialogContent title={t('fix.wazuhTitle')} description={t('fix.wazuhDescription')}>
        <WazuhForm current={null} onSaved={() => { toast.success(t('fix.wazuhSaved')); onClose() }} />
      </DialogContent>
    </Dialog>
  )
}

/** The fix of an engine that needs setup, where it is: a dialog when the thing can be made here, else the exact place (§0). */
function SetupFix({ e, d }: { e: Engine; d: Scanning }) {
  const { t } = useTranslation('scanning')
  const admin = useCan('admin')
  const [open, setOpen] = useState<'osquery' | 'wazuh' | null>(null)
  if (e.state !== 'needs_setup' || !admin) return null
  const scopeMissing = !d.safety.scope.confirmed_at || d.safety.scope.lan_ranges.length === 0
  if (e.id === 'nmap-discovery' || (e.id === 'nuclei' && scopeMissing)) return <ScopeButton /> // the others of sensor-active follow it
  if (e.id === 'nuclei') return <DependencyLink reason={t('fix.nucleiWindow')} to="/settings/scanning?tab=safety#win-from" label={t('fix.nucleiWindowLink')} />
  // SNMP is set up on a device's page; the card's reason says so
  if (e.id === 'snmp') return <DependencyLink reason="" to="/devices" label={t('fix.newSnmp')} />
  if (e.id === 'osquery') return (
    <>
      <Button size="sm" onClick={() => setOpen('osquery')}>{t('fix.newOsquery')}</Button>
      {open === 'osquery' ? <OsqueryDialog onClose={() => setOpen(null)} /> : null}
    </>
  )
  if (e.id === 'wazuh') return (
    <>
      <Button size="sm" onClick={() => setOpen('wazuh')}>{t('fix.newWazuh')}</Button>
      {open === 'wazuh' ? <WazuhDialog onClose={() => setOpen(null)} /> : null}
    </>
  )
  if (e.id === 'zap' || e.id === 'openvas') return <DependencyLink reason="" to="/exposure?tab=targets#targets" label={t('fix.target')} />
  if (e.id === 'honeypot') return <DependencyLink reason="" to="/honeypot?tab=trap-ips#trap-ips" label={t('fix.trapIp')} />
  return null
}

/** The runs of this engine going on now (from GET /scanning running[], by engine), with their progress and where they are seen. */
function Runs({ e, d }: { e: Engine; d: Scanning }) {
  const { t } = useTranslation('scanning')
  const can = useCan('operator')
  const stop = useStopRun()
  const [stopping, setStopping] = useState<string | null>(null)
  const jobs = d.running.filter((j) => j.engine === e.id)
  if (!jobs.length) return null
  return (
    <>
      {jobs.map((j) => (
        <Card key={j.id} className="grid gap-2">
          <div className="flex flex-wrap items-center gap-x-3 gap-y-1 text-sm">
            <span className="font-medium">{j.label}</span>
            <Link to={runHref(j.id, 'settings')} className="text-meta text-accent underline-offset-4 hover:underline">{t('scanNow.openRun')}</Link>
            {/* only a LAN vulnerability check has a Stop here; the others are stopped where they are seen */}
            {e.id === 'nuclei' && can ? <Button size="sm" variant="danger" className="ml-auto" onClick={() => setStopping(j.id)}>{t('run.stop')}</Button> : null}
          </div>
          {/* a queued run has not started: its line says what it waits for and when it starts, no step, clock or last report */}
          {j.queued ? <p className="text-meta text-muted">{j.progress?.message ?? t('scanNow.queued')}</p> : <JobProgress progress={j.progress} />}
        </Card>
      ))}
      <Dialog open={!!stopping} onOpenChange={(v) => { if (!v) setStopping(null) }}>
        <DialogContent title={t('run.stopTitle')} description={t('run.stopBody')}>
          <DialogFooter>
            <Button onClick={() => setStopping(null)}>{t('common:cancel')}</Button>
            <Button variant="danger" busy={stop.isPending} busyLabel={t('common:busy.stopping')} onClick={() => stopping && stop.mutate(stopping, { onSuccess: () => setStopping(null), onError: (err) => toast.error(errMsg(err)) })}>{t('run.stopConfirm')}</Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </>
  )
}

function Facts({ e }: { e: Engine }) {
  const { t } = useTranslation('scanning')
  const last = e.last_run
  const always = e.id === 'passive' || e.id === 'osquery' || e.id === 'honeypot'
  const cost = e.cost.ram_mb === null ? t('cost.unknown') : e.cost.ram_mb === 0 ? t('cost.none') : t(`cost.${e.cost.while}`, { size: mb(e.cost.ram_mb) }) + (e.cost.container ? ` ${t('cost.shared', { name: e.cost.container })}` : '')
  return (
    <dl className="flex flex-wrap gap-x-6 gap-y-1 text-meta">
      <div className="flex gap-1.5"><dt className="whitespace-nowrap text-muted">{t('facts.memory')}</dt><dd className="tabular-nums">{cost}</dd></div>
      {e.enabled ? (
        <div className="flex gap-1.5"><dt className="whitespace-nowrap text-muted">{t('facts.last')}</dt>
          <dd>{last ? <><time dateTime={last.at} title={fmtDateTime(last.at)}>{t(`outcome.${last.outcome}`, { time: fmtRelative(last.at) })}</time> <span className="text-muted">{last.text}</span></> : t('facts.never')}</dd></div>
      ) : null}
      {e.enabled && !always ? <div className="flex gap-1.5"><dt className="whitespace-nowrap text-muted">{t('facts.next')}</dt><dd>{e.next_run_at ? <time dateTime={e.next_run_at}>{fmtDateTime(e.next_run_at)}</time> : t('facts.onDemand')}</dd></div> : null}
    </dl>
  )
}

function EngineRow({ e, d, open, onOpen }: { e: Engine; d: Scanning; open: boolean; onOpen: (v: boolean) => void }) {
  const { t } = useTranslation('scanning')
  const admin = useCan('admin')
  const set = useSetEngine()
  const [ask, setAsk] = useState<{ off: boolean; deps?: string } | null>(null)
  // A switch refused for a missing scope opens the scope dialog and is tried again on save; no days links to the field
  const [needScope, setNeedScope] = useState(false)
  const [noDays, setNoDays] = useState(false)
  const nameId = useId()
  const panelId = useId()
  const name = (id: EngineId) => t(`engines.${id}.name`)
  const running = d.running.some((j) => j.engine === e.id || e.affects.includes(j.engine))
  // ZAP and OpenVAS run in External exposure's scans: with that module off, it is turned on from here (§0)
  const exposureOn = useModuleEnabled('exposure')
  const exposureOff = e.module === 'exposure' && exposureOn === false
  const change = (enabled: boolean, withDependencies = false) => set.mutate({ id: e.id, enabled, withDependencies }, {
    onSuccess: () => { setAsk(null); toast.success(t(enabled ? 'toast.on' : 'toast.off', { name: name(e.id) })) },
    onError: (err) => {
      if (err instanceof ApiError && err.code === 'missing_dependencies') {
        const list = ((err.details.missing ?? err.details.lacking ?? []) as string[]).map((m) => t(`common:modules.${m}.name`)).join(', ')
        setAsk({ off: false, deps: list ? t('ask.needs', { list }) : err.message }); return
      }
      setAsk(null)
      if (err instanceof ApiError && (err.code === 'scope_not_confirmed' || err.code === 'no_ranges')) { setNeedScope(true); return }
      if (err instanceof ApiError && err.code === 'no_days') { setNoDays(true); return }
      toast.error(errMsg(err))
    },
  })
  // turning off names what stops with it (affects) and a run that ends; turning on asks only when modules must come too
  const onSwitch = (v: boolean) => (v ? change(true) : e.affects.length || running ? setAsk({ off: true }) : change(false))
  // a module that is off has no settings to show (GreenboneSetting fails without exposure): the card's own reason and switch say
  // what to do instead (#877). SNMP has none here since it is set up on each device's page.
  const own: ReactNode = e.id === 'nuclei' && e.enabled ? <NucleiSettings />
    : e.id === 'openvas' && exposureOn === true ? <GreenboneSetting embedded />
    // the sweep's schedule; the card has its own button to sweep now, so the line has no second one
    : e.id === 'nmap-discovery' && e.enabled ? <ScheduleEditor ownerKey="inventory.sweep" name={t('engines.nmap-discovery.scheduleName')} runNow={false} /> : null
  const place = PLACE[e.id] && (admin || !ADMIN_PLACE(PLACE[e.id]!)) ? PLACE[e.id] : undefined
  return (
    <li id={`engine-${e.id}`} aria-labelledby={nameId} className="grid scroll-mt-24 gap-3 px-4 py-4">
      <div className="grid gap-3 sm:grid-cols-[minmax(0,1fr)_auto] sm:items-start">
        <div className="grid min-w-0 gap-1.5">
          <div className="flex flex-wrap items-center gap-2">
            <h3 id={nameId} className="text-sm font-semibold">{name(e.id)}</h3>
            {e.preview ? <ScopeBadge scope="preview" /> : null}
            <Chip tone={STATE_TONE[e.state]}>{t(`state.${e.state}`)}</Chip>
          </div>
          <p className="text-meta text-muted">{t(`engines.${e.id}.finds`)}</p>
          {e.reason ? <p className={e.state === 'error' ? 'text-meta text-danger' : e.state === 'needs_setup' ? 'text-meta text-warn' : 'text-meta'}>{e.reason}</p> : null}
          <Facts e={e} />
        </div>
        <div className="flex items-center gap-2 sm:justify-end">
          {e.can_toggle ? (
            <>
              <Switch id={`engine-${e.id}-switch`} checked={e.enabled} aria-labelledby={`${nameId} engine-${e.id}-on`} disabled={!admin || set.isPending || (!e.enabled && e.state === 'unavailable')} onCheckedChange={onSwitch} />
              <span id={`engine-${e.id}-on`} className="text-sm">{e.enabled ? t('on') : t('off')}</span>
            </>
          ) : <span className="text-meta text-muted">{e.follows ? t('follows', { name: name(e.follows) }) : t('noSwitch')}</span>}
        </div>
      </div>
      {needScope ? <ScopeDialog open onOpenChange={setNeedScope} onSaved={() => change(true)} /> : null}
      {noDays ? <DependencyLink reason={t('fix.noDays')} to="/settings/scanning?tab=safety#win-from" label={t('fix.noDaysLink')} /> : null}
      <div className="flex flex-wrap items-center gap-3"><SetupFix e={e} d={d} />{exposureOff ? <TurnOnModule module="exposure" name={t('common:modules.exposure.name')} /> : null}</div>
      <Runs e={e} d={d} />
      {e.id === 'snmp' && admin ? <SnmpDevices /> : null}
      {/* the card's Runs already show the run's progress: the button does not repeat it (#877 r1 L12) */}
      {e.id === 'nmap-discovery' && e.state !== 'needs_setup' ? <ScanNowButton targets="lan" variant="secondary" size="sm" showProgress={false} /> : null}
      {e.id === 'nuclei' && e.enabled ? <VulnChecksButton targets="lan" showProgress={false} /> : null}
      {own ? (
        <div className="grid gap-3">
          <ExpandToggle open={open} onToggle={() => onOpen(!open)} controls={panelId} label={t('settingsOf', { name: name(e.id) })}>{t('settings')}</ExpandToggle>
          {open ? <div id={panelId} className="min-w-0 border-l-2 border-rule pl-4">{own}</div> : null}
        </div>
      ) : null}
      {place ? <Link to={place} className="w-fit text-meta text-accent underline-offset-4 hover:underline">{t(`engines.${e.id}.where`)}</Link> : null}
      {e.id === 'nuclei' && e.enabled ? <AlertChannels /> : null}
      <Dialog open={!!ask} onOpenChange={(v) => { if (!v) setAsk(null) }}>
        <DialogContent title={ask?.off ? t('ask.offTitle', { name: name(e.id) }) : t('ask.depsTitle', { name: name(e.id) })}
          description={ask?.off ? [e.affects.length ? t('ask.affects', { list: e.affects.map(name).join(', ') }) : '', running ? t('ask.stops') : ''].filter(Boolean).join(' ') : ask?.deps}>
          <DialogFooter>
            <Button onClick={() => setAsk(null)}>{t('common:cancel')}</Button>
            <Button variant={ask?.off ? 'danger' : 'primary'} busy={set.isPending} busyLabel={t(ask?.off ? 'common:busy.turningOff' : 'common:busy.turningOn')} onClick={() => (ask?.off ? change(false) : change(true, true))}>{ask?.off ? t('ask.offConfirm') : t('ask.depsConfirm')}</Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </li>
  )
}

/** The memory line: the sum is of upper limits, so it says so; when the limits add up to more than the box has, it says what to do
 *  and takes an administrator to the switch of the engine that holds the most while it is on (docs/UI.md §0: need → place → action). */
function BoxMemory({ d }: { d: Scanning }) {
  const { t } = useTranslation('scanning')
  const admin = useCan('admin')
  const { memory_mb: total, reserved_mb: used } = d.box
  if (!total) return null
  if (used <= total) return <InfoLine className="mb-5 text-meta text-muted" topic={t('box.memory', { used: mb(used), total: mb(total) })} info={t('box.memoryInfo')}>{t('box.memory', { used: mb(used), total: mb(total) })}</InfoLine>
  const biggest = d.engines
    .filter((e) => e.enabled && e.can_toggle && e.cost.while === 'on' && (e.cost.ram_mb ?? 0) > 0)
    .sort((a, b) => (b.cost.ram_mb ?? 0) - (a.cost.ram_mb ?? 0))[0]
  const go = (id: EngineId) => {
    const sw = document.getElementById(`engine-${id}-switch`)
    sw?.scrollIntoView({ block: 'center' })
    sw?.focus()
  }
  return (
    // accent, not warn (#890): on a small box with OpenVAS on this shows all the time; it informs, nothing is wrong yet
    <Notice tone="accent" title={t('box.overTitle')}
      actions={biggest && admin ? <Button size="sm" onClick={() => go(biggest.id)}>{t('box.goTo', { name: t(`engines.${biggest.id}.name`) })}</Button> : null}>
      {t(admin ? 'box.over' : 'box.overViewer', { used: mb(used), total: mb(total) })}{' '}
      {biggest ? t('box.biggest', { name: t(`engines.${biggest.id}.name`), size: mb(biggest.cost.ram_mb ?? 0) }) : null}
    </Notice>
  )
}

function Groups({ d }: { d: Scanning }) {
  const { t } = useTranslation('scanning')
  const { hash } = useLocation()
  const admin = useCan('admin')
  const target = hash.startsWith('#engine-') ? hash.slice('#engine-'.length).replace(/-switch$/, '') : hash.slice(1)
  // a deep link to an engine (#snmp or #engine-snmp) opens that card's settings and scrolls to it
  const [open, setOpen] = useState<Set<string>>(() => new Set(target ? [target] : []))
  useEffect(() => {
    if (target && !hash.startsWith('#engine-')) document.getElementById(`engine-${target}`)?.scrollIntoView({ block: 'start' })
  }, [target, hash])
  return (
    <>
      {admin ? null : <Notice tone="off" title={t('adminOnly')} />}
      <BoxMemory d={d} />
      {GROUPS.map((g) => {
        const list = d.engines.filter((e) => e.group === g)
        if (!list.length) return null
        return (
          <Section key={g} id={`group-${g}`} title={t(`group.${g}.title`)} description={t(`group.${g}.description`)} info={t(`group.${g}.info`)}>
            <Card flush>
              <ul className="divide-y divide-rule">
                {list.map((e) => <EngineRow key={e.id} e={e} d={d} open={open.has(e.id)} onOpen={(v) => setOpen((s) => { const n = new Set(s); if (v) n.add(e.id); else n.delete(e.id); return n })} />)}
              </ul>
            </Card>
          </Section>
        )
      })}
    </>
  )
}

export function EnginesTab({ d }: { d: Scanning }) {
  const { hash } = useLocation()
  return <Groups key={hash} d={d} />
}
