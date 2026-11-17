import { useState, type FormEvent } from 'react'
import { Link } from 'react-router'
import { useTranslation } from 'react-i18next'
import { Notice, Section } from '@/components/common/PageHeader'
import { Chip } from '@/components/common/StatusChip'
import { BusyNote } from '@/components/common/BusyNote'
import { Button, buttonVariants } from '@/components/ui/button'
import { Switch } from '@/components/ui/switch'
import { Field } from '@/components/ui/input'
import { fmtDateTime, fmtRelative } from '@/lib/format'
import { useModuleEnabled } from '@/lib/modules'
import { useCan, useMe } from '@/lib/session'
import { cn } from '@/lib/utils'
import { AddDialog } from './AddDialog'
import { TurnOnModule } from './Inline'
import { CreatableSelect } from '@/components/common/CreatableSelect'
import { SnmpNext } from './SnmpNext'
import { CIDR_RE_UI, IPV4_RE_UI, SNMP_MAX } from './validate'
import { useDeviceAction, useDeviceSources, useSettings, useSnmp, useSnmpActions } from './api'
import { inRanges } from './AddToScopeDialog'
import { nameOf } from './nameOf'
import { kindLabel } from '@/lib/deviceTypes'
import { toast } from 'sonner'
import { credentialLabel, errMsg } from './kinds'
import { CredentialDialog, SnmpAnswer } from './SnmpSection'
import type { DeviceDetail, SnmpCredential, SnmpTestResult } from './types'

/** The five ways a device is fed (D-598, issue #829): scan, passive sensor, SNMP, agent (osquery or Wazuh), the person. */
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

/** Whether a credential's scope holds the address, as the box decides it (sensor-active snmpRow.covers: each IPv4 address or CIDR range
 *  of the scope; anything else holds nothing), so the read is not sent first with a credential the box refuses for this address. */
const credCovers = (scope: string[], ip: string) => scope.some((s) => (IPV4_RE_UI.test(s) || CIDR_RE_UI.test(s)) && inRanges(ip, [s]))

/** Read this device now with one saved SNMP credential (the same Test as Scope and sensors → SNMP, with this device's address); add a
 *  credential for this address, or add the address to a credential whose scope does not hold it, without leaving the page. */
function SnmpRead({ ip }: { ip: string }) {
  const { t } = useTranslation('inventory')
  const q = useSnmp(true)
  const { test } = useSnmpActions()
  const [cred, setCred] = useState('')
  const [result, setResult] = useState<SnmpTestResult | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [form, setForm] = useState<{ current: SnmpCredential | null; scope: string; widen: boolean } | null>(null)
  const creds = q.data?.credentials ?? []
  const read = (id: string) => { setResult(null); setError(null); test.mutate({ id, ip }, { onSuccess: setResult, onError: (er) => setError(errMsg(er)) }) }
  // #842 "do it where you are": a credential made or fixed here is selected and this device is read with it at once.
  const saved = (c: SnmpCredential) => { setCred(c.id); read(c.id) }
  if (q.isPending) return <p className="text-meta text-muted">{t('sources.snmp.loading')}</p>
  const dialog = form ? <CredentialDialog key={form.current?.id ?? 'new'} current={form.current} scope={form.scope} widen={form.widen} onClose={() => setForm(null)} onSaved={saved} /> : null
  const addNew = creds.length < SNMP_MAX ? () => setForm({ current: null, scope: ip, widen: false }) : undefined
  if (!creds.length) {
    return (
      <div className="flex flex-wrap items-center gap-2 text-meta text-muted">
        {t('sources.snmp.none')} <Button size="sm" variant="primary" onClick={addNew}>{t('sources.snmp.addFor', { ip })}</Button>{dialog}
      </div>
    )
  }
  // n82: the first credential (in the order they are tried) whose scope holds this address, never one the box refuses for it.
  const covering = creds.find((c) => credCovers(c.scope, ip))
  const chosen = cred || (covering?.id ?? '')
  const chosenCred = creds.find((c) => c.id === chosen)
  function submit(e: FormEvent) { e.preventDefault(); read(chosen) }
  return (
    <div className="grid min-w-0 gap-2">
      <form onSubmit={submit} noValidate className="flex flex-wrap items-end gap-2">
        <Field label={t('sources.snmp.credential')} htmlFor="device-snmp-cred">
          <CreatableSelect id="device-snmp-cred" className="w-auto" value={chosen} placeholder={covering ? undefined : t('sources.snmp.choose')} onChange={(id) => { setCred(id); setResult(null) }}
            options={creds.map((c) => ({ value: c.id, label: credentialLabel(c.name, c.version, t(`snmp.version.${c.version}`)) }))}
            newLabel={t('addDialog.snmp.newCredential')} canCreate={creds.length < SNMP_MAX} createDisabledReason={t('addDialog.snmp.capReason', { count: SNMP_MAX })}
            renderCreate={(p) => (p.open ? <CredentialDialog current={null} scope={ip} onClose={() => p.onOpenChange(false)}
              onSaved={(c) => { p.onCreated({ value: c.id, label: credentialLabel(c.name, c.version, t(`snmp.version.${c.version}`)) }); saved(c) }} /> : null)} />
        </Field>
        <Button type="submit" size="sm" variant="primary" disabled={!chosen} busy={test.isPending} busyLabel={t('snmp.run.running')}>{t('sources.snmp.read')}</Button>
        {chosenCred ? <Button size="sm" variant="link" onClick={() => setForm({ current: chosenCred, scope: chosenCred.scope.join('\n'), widen: false })}>{t('addDialog.snmp.editCredential', { name: chosenCred.name })}</Button> : null}
      </form>
      {covering ? null : <p className="text-meta text-muted">{t('sources.snmp.noneCovers', { ip })}</p>}
      {chosenCred && !result && !credCovers(chosenCred.scope, ip) && chosenCred.scope.length < 16 ? (
        <div><Button size="sm" onClick={() => setForm({ current: chosenCred, scope: [...chosenCred.scope, ip].join('\n'), widen: true })}>{t('sources.snmp.addToScope', { ip, name: chosenCred.name })}</Button></div>
      ) : null}
      {q.data && !q.data.ready ? <p className="text-meta text-warn">{q.data.message ?? t('snmp.notReady')}</p> : null}
      <BusyNote busy={test.isPending}>{t('snmp.run.pending', { ip })}</BusyNote>
      {error ? <Notice tone="danger" role="alert" className="mb-0" title={error} /> : null}
      {result && !test.isPending ? <SnmpAnswer r={result} ip={ip} /> : null}
      {result && !test.isPending && !result.ok ? (
        <SnmpNext r={result} ip={ip} cred={chosenCred} onRetry={() => read(chosen)}
          onWiden={() => chosenCred && setForm({ current: chosenCred, scope: [...chosenCred.scope, ip].join('\n'), widen: true })}
          onEdit={() => chosenCred && setForm({ current: chosenCred, scope: chosenCred.scope.join('\n'), widen: false })} />
      ) : null}
      {result?.reason === 'not_for_this_credential' ? <p className="text-caption text-muted">{t('sources.snmp.addToScopeHint')}</p> : null}
      <p className="text-caption text-muted">{t('sources.snmp.scopeHint')}</p>
      {dialog}
    </div>
  )
}

/** D-601: the person's switch of one active source of the box for this device (network scan, SNMP), with what on and off mean in one
 *  line. Admin only; others see it locked with the reason. An agent has no switch: it is installed or uninstalled on the machine. */
function SourceSwitch({ d, which }: { d: DeviceDetail; which: 'scan' | 'snmp' }) {
  const { t } = useTranslation('inventory')
  const admin = useCan('admin')
  const set = useDeviceSources(d.asset.id)
  const on = (which === 'scan' ? d.asset.scan_source : d.asset.snmp_source) === 'on'
  // review r2 M1: a discovered device outside the LAN ranges is read with SNMP only once a person turns it on here (the list is admin-only)
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

/** S-INV-1 (D-598, issue #829): which sources feed this device, and adding SNMP or osquery to it from here. Both can feed it at once.
 *  D-601: the network scan and SNMP are switched on or off per device here; a device added by hand starts with both off. */
export function DeviceSources({ d }: { d: DeviceDetail }) {
  const { t } = useTranslation('inventory')
  const me = useMe()
  const admin = me.data?.role === 'admin'
  const snmpOn = useModuleEnabled('sensor-active') === true
  const agentsOn = useModuleEnabled('agent-intake') === true
  const [reading, setReading] = useState(false)
  const [enrol, setEnrol] = useState(false)
  const canOp = useCan('operator')
  const approve = useDeviceAction(d.asset.id).approve
  const sources = useDeviceSources(d.asset.id)
  const a = d.asset
  // #829 C4: credentials this device answered before it moved out of their scope (the list is admin-only).
  const snmpList = useSnmp(snmpOn && admin)
  const movedOut = (snmpList.data?.credentials ?? []).flatMap((c) => c.moved_out.filter((m) => m.device_id === a.id).map((m) => ({ cred: c.name, ...m })))
  const feeds = feedsOf(d)
  const ip = a.ip && IPV4.test(a.ip) ? a.ip : ''
  const declared = a.origin === 'manual'

  const action = (f: Feed): React.ReactNode => {
    if (f === 'snmp') {
      if (!snmpOn) return <TurnOnModule id="sensor-active" reason={t('sources.snmp.off')} />
      if (!ip) return <span className="text-meta text-muted">{t('sources.noIp')}</span>
      if (!a.approved) {
        // SNMP reads only approved devices (D-512): approve it here, then add SNMP (#842 "do it where you are").
        return (
          <span className="flex flex-wrap items-center gap-2">
            <span className="text-meta text-muted">{t('sources.snmp.approveFirst')}</span>
            <Button size="sm" disabled={!canOp} busy={approve.isPending} busyLabel={t('common:busy.approving')} title={canOp ? undefined : t('common:needRole', { role: t('common:role.operator') })}
              onClick={() => approve.mutate(undefined, { onSuccess: () => toast.success(t('pending.approved', { name: nameOf(a, kindLabel(a.kind)) })), onError: (e) => toast.error(errMsg(e)) })}>{t('sources.snmp.approveHere')}</Button>
          </span>
        )
      }
      if (!admin) return <span className="text-meta text-muted">{t('sources.adminOnly')}</span>
      if (reading) return null
      // D-601: with SNMP off for this device, the button says it turns SNMP on (the person's consent, audited) and opens the read here.
      if (a.snmp_source === 'off') {
        return (
          <Button busy={sources.isPending} busyLabel={t('common:busy.saving')} size="sm" disabled={sources.isPending}
            onClick={() => sources.mutate({ snmp: 'on' }, { onSuccess: () => setReading(true), onError: (e) => toast.error(errMsg(e)) })}>{t('sources.snmp.turnOnAdd')}</Button>
        )
      }
      return <Button size="sm" onClick={() => setReading(true)}>{feeds.has('snmp') ? t('sources.snmp.readAgain') : t('sources.snmp.add')}</Button>
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
              {f === 'snmp' ? movedOut.map((m) => <p key={m.cred} role="status" className="text-meta text-warn">{t('sources.snmp.movedOut', { ip: m.ip, name: m.cred })}</p>) : null}
              {f === 'snmp' && reading && ip ? <SnmpRead ip={ip} /> : null}
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
