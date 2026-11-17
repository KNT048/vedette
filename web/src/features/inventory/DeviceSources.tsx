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
import { useDeviceAction, useDeviceSources, useSettings } from './api'
import { inRanges } from './AddToScopeDialog'
import { nameOf } from './nameOf'
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

/** The person's switch of one active source of the box for this device (network scan, SNMP), with what on and off mean in one
 *  line. Admin only; others see it locked with the reason. An agent has no switch: it is installed or uninstalled on the machine. */
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
                  {at ? <time className="text-caption text-muted" dateTime={at} title={fmtDateTime(at)}>{t('sources.lastSeen', { when: fmtRelative(at) })}</time> : null}
                </div>
                {action(f)}
              </div>
              <p className="text-meta text-muted">{t(`sources.what.${f}`)}</p>
              {f === 'scan' || (f === 'snmp' && snmpOn) ? <SourceSwitch d={d} which={f} /> : null}
              {f === 'agent' && agentsOn ? <p className="text-caption text-muted">{t('sources.agent.how')}</p> : null}
            </li>
          )
        })}
      </ul>
      {declared && a.scan_source === 'off' && a.snmp_source === 'off' ? <p className="mt-3 max-w-3xl text-meta text-muted">{t('sources.declared')}</p> : null}
      <p className="mt-3 max-w-3xl text-meta text-muted">{t('sources.both')}</p>
      {enrol ? <AddDialog open method="osquery" onOpenChange={(o) => { if (!o) setEnrol(false) }} /> : null}
    </Section>
  )
}
