import { useState } from 'react'
import { Link } from 'react-router'
import { useTranslation } from 'react-i18next'
import { Section } from '@/components/common/PageHeader'
import { InfoTip } from '@/components/common/InfoTip'
import { Button, buttonVariants } from '@/components/ui/button'
import { Switch } from '@/components/ui/switch'
import { fmtDateTime, fmtRelative } from '@/lib/format'
import { useModuleEnabled } from '@/lib/modules'
import { useCan, useMe } from '@/lib/session'
import { cn } from '@/lib/utils'
import { InstallOnDeviceDialog } from './InstallAgent'
import { SnmpSourceActions, SnmpSourceBody, useSnmpSource } from './SnmpCard'
import { TurnOnModule } from './Inline'
import { useAgentReport, useAgents, useDeviceAction, useDeviceSources, useSettings } from './api'
import { AgentQuietNote } from './AgentQuiet'
import { useScanning, useScanningHistory } from '@/features/scanning/api'
import { ScanNowButton } from '@/features/scanning/ScanNow'
import { firstCheck } from './firstCheck'
import { inRanges } from './AddToScopeDialog'
import { nameOf } from './nameOf'
import { actsAs, kindLabel } from '@/lib/deviceTypes'
import { toast } from 'sonner'
import { errMsg } from './kinds'
import type { DeviceDetail } from './types'

/** The five ways a device is fed (issue #829): scan, passive sensor, SNMP, agent (osquery or Wazuh), the person. */
const FEEDS = ['scan', 'passive', 'snmp', 'agent', 'manual'] as const
type Feed = (typeof FEEDS)[number]
const FEED_OF: Record<string, Feed> = { nmap: 'scan', scan: 'scan', passive: 'passive', snmp: 'snmp', agent: 'agent', manual: 'manual' }

/** Which feeds have reported on the device, and the newest observation of each (software and open ports carry no time). */
function feedsOf(d: DeviceDetail): Map<Feed, string | null> {
  const out = new Map<Feed, string | null>()
  const add = (source: string, at: string | null) => {
    const f = FEED_OF[source]
    if (!f) return
    const cur = out.get(f) ?? null
    out.set(f, at && (!cur || at > cur) ? at : cur)
  }
  for (const o of d.observations) add(o.source, o.seen_at)
  for (const s of d.asset.software) add(s.source, null)
  for (const s of d.asset.services) add(s.source, null)
  return out
}

/** Kinds an agent runs on: computers and servers. Network gear (firewall, switch, router, access point, printer, phone, camera,
 *  NAS and the like) cannot run one; SNMP reads its firmware version. Any other kind (unknown, web) is not decided here. */
const COMPUTER_KINDS = new Set(['pc', 'server'])
const GEAR_KINDS = new Set(['firewall', 'router', 'switch', 'ap', 'printer', 'camera', 'nvr', 'nas', 'iot'])

const IPV4 = /^\d{1,3}(\.\d{1,3}){3}$/

/** A scan observation this much after a device check ended came from a later run (a LAN sweep, most often; which one is not known). */
const AFTER_CHECK_MS = 120_000

/** The times of the network scan, each named for what it is: the last device check (the run the Last checks section lists, from
 *  the same History rows) and, when a network scan heard the device after it, that time; with no check yet, only that time. */
function ScanTimes({ id, seen }: { id: string; seen: string | null }) {
  const { t } = useTranslation('inventory')
  const history = useScanningHistory(id)
  const check = history.data?.items.find((r) => r.kind === 'device') ?? null
  if (!history.data) return seen ? <When at={seen} text={t('sources.lastSeen', { when: fmtRelative(seen) })} /> : null
  const end = check ? Date.parse(check.ended_at ?? check.started_at) : null
  const sweep = seen && (end === null || Date.parse(seen) > end + AFTER_CHECK_MS) ? seen : null
  return (
    <>
      {check ? <When at={check.started_at} text={t('sources.lastCheck', { when: fmtRelative(check.started_at) })} /> : null}
      {sweep ? <When at={sweep} text={t('sources.lastSeenScan', { when: fmtRelative(sweep) })} /> : null}
    </>
  )
}

/** The manual source's time (INV-46): when a person last entered or changed something on the device, not a report. A device added
 *  by hand that nobody changed since reads "added"; after any change, "last changed". */
function ManualTime({ d }: { d: DeviceDetail }) {
  const { t } = useTranslation('inventory')
  const at = d.manual_at
  if (!at) return null
  const added = d.asset.origin === 'manual' && Date.parse(at) <= Date.parse(d.asset.first_seen)
  return <When at={at} text={t(added ? 'sources.added' : 'sources.lastChanged', { when: fmtRelative(at) })} />
}

function When({ at, text }: { at: string; text: string }) {
  return <time className="text-caption text-muted" dateTime={at} title={fmtDateTime(at)}>{text}</time>
}

/** The network scan's words while the switch is on and no check has reached the device: when its first check happens, from the scan
 *  window of Settings › Scanning (never "Not set up" while the switch is on), and why not when something stops it. */
function FirstCheckText({ d }: { d: DeviceDetail }) {
  const { t } = useTranslation('inventory')
  const q = useScanning()
  if (!q.data) return <span className="text-meta text-muted">{t('sources.scan.firstNext')}</span>
  // the checks of new devices run when the scan window opens (the version scans' next run), not when the sweep's schedule comes due
  const sweep = q.data.engines.find((e) => e.id === 'nmap-discovery')
  const disc = sweep ? { enabled: sweep.enabled, next_run_at: q.data.engines.find((e) => e.id === 'nmap-versions')?.next_run_at ?? null } : null
  const f = firstCheck({ ip: d.asset.ip, window: q.data.safety.window, scope: q.data.safety.scope, discovery: disc, now: new Date() })
  const text = f.when === 'waiting' ? t(`sources.scan.waiting.${f.why}`)
    : f.when === 'now' ? t('sources.scan.firstNow')
    : f.when === 'next' ? t('sources.scan.firstNext')
    : f.when === 'day' ? t('sources.scan.firstDay', { day: f.day, time: f.time })
    : t(f.when === 'tonight' ? 'sources.scan.firstTonight' : f.when === 'today' ? 'sources.scan.firstToday' : 'sources.scan.firstTomorrow', { time: f.time })
  return <span className="text-meta text-muted">{text}</span>
}

/** The person's switch of one active source of the box for this device (network scan, SNMP), with what on and off mean in one
 *  line. Admin only; others see it locked with the reason. An agent has no switch: it is installed or uninstalled on the machine.
 *  The SNMP switch is drawn only for a device with SNMP settings (DeviceSources): without them "On" would claim reads that never happen. */
function SourceSwitch({ d, which }: { d: DeviceDetail; which: 'scan' | 'snmp' }) {
  const { t } = useTranslation('inventory')
  const admin = useCan('admin')
  const set = useDeviceSources(d.asset.id)
  const on = (which === 'scan' ? d.asset.scan_source : d.asset.snmp_source) === 'on'
  // a discovered device outside the LAN ranges is read with SNMP only once a person turns it on here (the list is admin-only)
  const lan = useSettings(admin && which === 'snmp' && !on && d.asset.origin !== 'manual').data?.lan_ranges
  const outside = !!lan && IPV4.test(d.asset.ip) && !inRanges(d.asset.ip, lan)
  const id = `device-source-${which}`
  const name = nameOf(d.asset, kindLabel(d.asset.kind))
  const toggle = (v: boolean) => set.mutate({ [which]: v ? 'on' : 'off' }, {
    onSuccess: () => toast.success(t(`sources.saved.${which}.${v ? 'on' : 'off'}`, { name })), onError: (e) => toast.error(errMsg(e)),
  })
  return (
    <div className="flex min-w-0 items-start gap-2">
      <Switch id={id} aria-label={t(`sources.toggle.${which}`)} checked={on} disabled={!admin || set.isPending}
        title={admin ? undefined : t('common:needRole', { role: t('common:role.admin') })} onCheckedChange={toggle} />
      <p className="text-meta text-muted">{t(on ? `sources.meaning.${which}.on` : outside ? 'sources.meaning.snmp.offOutside' : `sources.meaning.${which}.off`)}</p>
    </div>
  )
}

/** S-INV-1 (issue #829): which sources feed this device, and adding SNMP or osquery to it from here. Both can feed it at once.
 *  The network scan and SNMP are switched on or off per device here; a device added by hand starts with both off. */
export function DeviceSources({ d }: { d: DeviceDetail }) {
  const { t } = useTranslation('inventory')
  const me = useMe()
  const admin = me.data?.role === 'admin'
  const snmpOn = useModuleEnabled('sensor-active') === true
  const agentsOn = useModuleEnabled('agent-intake') === true
  const [enrol, setEnrol] = useState(false)
  const canOp = useCan('operator')
  const approve = useDeviceAction(d.asset.id).approve
  const a = d.asset
  const feeds = feedsOf(d)
  // The switch is on and nothing has reached the device yet (no report, no device check): its first check is the next window's.
  const history = useScanningHistory(d.asset.id)
  const firstDue = a.scan_source === 'on' && !feeds.has('scan') && !!history.data && !history.data.items.some((r) => r.kind === 'device' && r.outcome !== 'stopped')
  const ip = a.ip && IPV4.test(a.ip) ? a.ip : ''
  const declared = a.origin === 'manual'
  // Whether the device has SNMP settings of its own (the same query as its SNMP card): true, false, or null when not known (loading,
  // or not an administrator: only administrators see SNMP settings, so others get no SNMP switch rather than a guess).
  const snmp = useSnmpSource(d, admin && snmpOn)
  const snmpSetUp = snmp.q.data ? snmp.q.data.state !== 'not_set_up' : null
  const silent = a.scan_source === 'off' && (a.snmp_source === 'off' || snmpSetUp === false)

  // An osquery agent that stopped calling is said where the person looks: the report knows it from the agent's own schedule.
  const agentReport = useAgentReport(a.id, agentsOn && feeds.has('agent')).data
  const agentQuiet = agentReport?.agent === 'osquery' && (agentReport.state === 'quiet' || agentReport.state === 'never_reported') ? agentReport : null
  const boxUrl = useAgents(admin && agentsOn && agentQuiet !== null).data?.server_url

  const ownState = snmpOn && admin && !!ip
  const family = actsAs(a.kind)
  const gear = GEAR_KINDS.has(family) && !COMPUTER_KINDS.has(family)
  const undecided = !gear && !COMPUTER_KINDS.has(family)
  const action = (f: Feed): React.ReactNode => {
    if (f === 'snmp') {
      if (!snmpOn) return <TurnOnModule id="sensor-active" reason={t('sources.snmp.off')} />
      if (!ip) return <span className="text-meta text-muted">{t('sources.noIp')}</span>
      if (!a.approved) {
        // SNMP reads only approved devices: approve it here, then add SNMP (#842 "do it where you are").
        return (
          <span className="flex flex-wrap items-center gap-2">
            <span className="text-meta text-muted">{t('sources.snmp.approveFirst')}</span>
            <Button size="sm" disabled={!canOp} busy={approve.isPending} busyLabel={t('common:busy.approving')} title={canOp ? undefined : t('common:needRole', { role: t('common:role.operator') })}
              onClick={() => approve.mutate(undefined, { onSuccess: () => toast.success(t('pending.approved', { name: nameOf(a, kindLabel(a.kind)) })), onError: (e) => toast.error(errMsg(e)) })}>{t('sources.snmp.approveHere')}</Button>
          </span>
        )
      }
      if (!admin) return <span className="text-meta text-muted">{t('sources.adminOnly')}</span>
      // Set up (or Edit, Check now, Remove) opens the SNMP settings right here, on this row.
      return <SnmpSourceActions d={d} src={snmp} />
    }
    if (f === 'agent') {
      if (!agentsOn) return <TurnOnModule id="agent-intake" reason={t('sources.agent.off')} />
      if (!admin) return <span className="text-meta text-muted">{t('sources.adminOnly')}</span>
      if (feeds.has('agent')) return <Link to="/devices/setup?tab=agents" className={cn(buttonVariants({ size: 'sm' }))}>{t('sources.agent.manage')}</Link>
      // Installing osquery opens the install steps for this device; managing tokens stays on the agents page.
      const install = <Button size="sm" variant={gear ? undefined : 'primary'} onClick={() => setEnrol(true)}>{t('sources.agent.add')}</Button>
      if (!gear && !undecided) return install
      // The same SNMP set-up the SNMP row opens, in place, once the device can be read (SNMP on, an IP, approved, not set up yet).
      const snmpHere = snmpOn && !!ip && a.approved && snmpSetUp === false
      const setUp = snmpHere ? <Button size="sm" variant="primary" onClick={() => snmp.setEditing(true)}>{t('sources.snmp.setUp')}</Button> : null
      return <span className="flex flex-wrap items-center gap-2">{setUp}{undecided ? install : null}</span>
    }
    // the first check is the window's; a person may ask for it now
    if (f === 'scan' && firstDue && admin) return <ScanNowButton targets={[a.id]} size="sm" variant="secondary" showProgress={false} />
    return null
  }
  // A person's entry is the manual source in use (INV-46): manual_at says so even for a hand-added device with no manual row left.
  if (d.manual_at && !feeds.has('manual')) feeds.set('manual', d.manual_at)
  const shown = FEEDS.filter((f) => f !== 'manual' || declared || feeds.has('manual'))
  return (
    <Section id="sources" title={t('sources.title')} description={t('sources.description')} stories={['S-INV-1', 'S-INV-4']}>
      <ul aria-label={t('sources.title')} className="grid gap-1.5">
        {shown.map((f) => {
          const on = feeds.has(f)
          const at = feeds.get(f) ?? null
          // Sources that only report (passive listening, what a person entered) are one line: a mark, the name, the last time. Only a
          // source the person can act on (network scan, SNMP, agent) keeps a control, and with it a frame.
          const act = f === 'scan' || f === 'snmp' || f === 'agent'
          const quiet = f === 'agent' && agentQuiet !== null
          const mark = <span aria-hidden className={cn('size-2 shrink-0 rounded-full', quiet ? 'bg-warn' : on ? 'bg-ok' : 'bg-off')} />
          const head = (
            <div className="flex min-w-0 flex-wrap items-center gap-x-2 gap-y-1">
              {mark}
              <span className="text-sm font-medium" title={act ? undefined : t(`sources.what.${f}`)}>{t(`sources.name.${f}`)}</span>
              {act ? <InfoTip topic={t(`sources.name.${f}`)}>{t(`sources.what.${f}`)}</InfoTip> : null}
              {/* the SNMP row says its own state below (working, waiting, not set up...): a second word here would contradict it */}
              {f === 'snmp' && ownState ? null
                : f === 'scan' && firstDue ? <FirstCheckText d={d} />
                : f === 'scan' && a.scan_source === 'on' ? <span className="text-meta text-muted">{on ? t('sources.feeds') : t('sources.scan.on')}</span>
                : <span className="text-meta text-muted">{on ? t('sources.feeds') : t('sources.notYet')}</span>}
              {f === 'scan' ? <ScanTimes id={a.id} seen={at} />
                : f === 'manual' ? <ManualTime d={d} />
                : at ? <When at={at} text={t('sources.lastSeen', { when: fmtRelative(at) })} /> : null}
            </div>
          )
          if (!act) return <li key={f} className="px-3 py-1">{head}</li>
          return (
            <li key={f} id={f === 'snmp' ? 'device-snmp' : undefined} className="grid min-w-0 gap-2 rounded-md border border-rule bg-surface px-3 py-2">
              <div className="flex flex-wrap items-center justify-between gap-2">
                {head}
                {action(f)}
              </div>
              {f === 'scan' || (f === 'snmp' && snmpOn && snmpSetUp) ? <SourceSwitch d={d} which={f} /> : null}
              {f === 'snmp' && ownState ? <SnmpSourceBody d={d} src={snmp} /> : null}
              {f === 'agent' && agentQuiet && (agentQuiet.state === 'quiet' || agentQuiet.state === 'never_reported') && agentQuiet.os
                ? <AgentQuietNote state={agentQuiet.state} since={agentQuiet.quiet_since} os={agentQuiet.os} box={boxUrl} /> : null}
              {f === 'agent' && agentsOn && !feeds.has('agent') && (gear || undecided) ? <p className="text-caption text-muted" data-testid="agent-kind-hint">{t(gear ? 'sources.agent.gearHint' : 'sources.agent.unknownHint')}</p> : null}
              {f === 'agent' && agentsOn ? <p className="text-caption text-muted">{t('sources.agent.how')}</p> : null}
            </li>
          )
        })}
      </ul>
      {/* the one place on the device page that says why a device added by hand is not scanned: next to the switch that turns it on */}
      {declared && a.scan_source === 'off' ? <p className="mt-3 max-w-3xl text-meta text-muted">{t(silent ? 'sources.declared' : 'sources.declaredScanOff')}</p> : null}
      <p className="mt-3 max-w-3xl text-meta text-muted">{t('sources.both')}</p>
      {enrol ? <InstallOnDeviceDialog d={d} onClose={() => setEnrol(false)} /> : null}
    </Section>
  )
}
