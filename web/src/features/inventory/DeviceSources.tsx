import { useState } from 'react'
import { Link } from 'react-router'
import { useTranslation } from 'react-i18next'
import { Section } from '@/components/common/PageHeader'
import { Chip } from '@/components/common/StatusChip'
import { Button, buttonVariants } from '@/components/ui/button'
import { Switch } from '@/components/ui/switch'
import { fmtDateTime, fmtRelative } from '@/lib/format'
import { useModuleEnabled } from '@/lib/modules'
import { useCan, useMe } from '@/lib/session'
import { cn } from '@/lib/utils'
import { AddDialog } from './AddDialog'
import { TurnOnModule } from './Inline'
import { useDeviceAction, useDeviceSnmp, useDeviceSources, useSettings } from './api'
import { useScanningHistory } from '@/features/scanning/api'
import { inRanges } from './AddToScopeDialog'
import { hasSnmpCard, nameOf } from './nameOf'
import { kindLabel } from '@/lib/deviceTypes'
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

/** SNMP without settings of the device's own: no read goes to it whatever its stored switch says (reads come only from a device's
 *  SNMP settings), so there is no switch to show, only what to do. Saving the settings turns SNMP on for the device. */
function SnmpNotSetUp({ card }: { card: boolean }) {
  const { t } = useTranslation('inventory')
  return (
    <p className="text-meta text-muted" data-testid="snmp-not-set-up">
      {t('sources.meaning.snmp.notSetUp')}
      {card ? <> <Link to="#device-snmp" className="text-accent underline-offset-4 hover:underline">{t('sources.meaning.snmp.setUpLink')}</Link></> : null}
    </p>
  )
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
  const ip = a.ip && IPV4.test(a.ip) ? a.ip : ''
  const declared = a.origin === 'manual'
  // Whether the device has SNMP settings of its own (the same query as its SNMP card): true, false, or null when not known (loading,
  // or not an administrator: only administrators see SNMP settings, so others get no SNMP switch rather than a guess).
  const snmpQ = useDeviceSnmp(a.id, admin && snmpOn)
  const snmpSetUp = snmpQ.data ? snmpQ.data.state !== 'not_set_up' : null
  const silent = a.scan_source === 'off' && (a.snmp_source === 'off' || snmpSetUp === false)

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
      // SNMP is set up on the device's own SNMP card (version, community or v3 user, Read from, Check now).
      return null
    }
    if (f === 'agent') {
      if (!agentsOn) return <TurnOnModule id="agent-intake" reason={t('sources.agent.off')} />
      if (!admin) return <span className="text-meta text-muted">{t('sources.adminOnly')}</span>
      // #849: installing osquery opens the Add a device dialog's osquery method here; managing tokens stays on the agents page.
      return feeds.has('agent')
        ? <Link to="/devices/setup?tab=agents" className={cn(buttonVariants({ size: 'sm' }))}>{t('sources.agent.manage')}</Link>
        : <Button size="sm" onClick={() => setEnrol(true)}>{t('sources.agent.add')}</Button>
    }
    return null
  }
  // A person's entry is the manual source in use (INV-46): manual_at says so even for a hand-added device with no manual row left.
  if (d.manual_at && !feeds.has('manual')) feeds.set('manual', d.manual_at)
  const shown = FEEDS.filter((f) => f !== 'manual' || declared || feeds.has('manual'))
  return (
    <Section id="sources" title={t('sources.title')} description={t('sources.description')} stories={['S-INV-1', 'S-INV-4']}>
      <ul aria-label={t('sources.title')} className="grid gap-2">
        {shown.map((f) => {
          const on = feeds.has(f)
          const at = feeds.get(f) ?? null
          return (
            <li key={f} className="grid min-w-0 gap-2 rounded-md border border-rule bg-surface p-3">
              <div className="flex flex-wrap items-center justify-between gap-2">
                <div className="flex min-w-0 flex-wrap items-center gap-2">
                  <span className="text-sm font-medium">{t(`sources.name.${f}`)}</span>
                  {on ? <Chip tone="ok">{t('sources.feeds')}</Chip> : <Chip tone="off">{t('sources.notYet')}</Chip>}
                  {f === 'scan' ? <ScanTimes id={a.id} seen={at} />
                    : f === 'manual' ? <ManualTime d={d} />
                    : at ? <When at={at} text={t('sources.lastSeen', { when: fmtRelative(at) })} /> : null}
                </div>
                {action(f)}
              </div>
              <p className="text-meta text-muted">{t(`sources.what.${f}`)}</p>
              {f === 'scan' || (f === 'snmp' && snmpOn && snmpSetUp) ? <SourceSwitch d={d} which={f} /> : null}
              {f === 'snmp' && snmpOn && snmpSetUp === false ? <SnmpNotSetUp card={hasSnmpCard(a, admin, snmpOn)} /> : null}
              {f === 'agent' && agentsOn ? <p className="text-caption text-muted">{t('sources.agent.how')}</p> : null}
            </li>
          )
        })}
      </ul>
      {/* the one place on the device page that says why a device added by hand is not scanned: next to the switch that turns it on */}
      {declared && a.scan_source === 'off' ? <p className="mt-3 max-w-3xl text-meta text-muted">{t(silent ? 'sources.declared' : 'sources.declaredScanOff')}</p> : null}
      <p className="mt-3 max-w-3xl text-meta text-muted">{t('sources.both')}</p>
      {enrol ? <AddDialog open method="osquery" onOpenChange={(o) => { if (!o) setEnrol(false) }} /> : null}
    </Section>
  )
}
