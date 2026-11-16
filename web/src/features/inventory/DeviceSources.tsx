import { useState, type FormEvent } from 'react'
import { Link } from 'react-router'
import { useTranslation } from 'react-i18next'
import { Notice, Section } from '@/components/common/PageHeader'
import { Chip } from '@/components/common/StatusChip'
import { Button, buttonVariants } from '@/components/ui/button'
import { Field } from '@/components/ui/input'
import { fmtDateTime, fmtRelative } from '@/lib/format'
import { useModuleEnabled } from '@/lib/modules'
import { useCan, useMe } from '@/lib/session'
import { cn } from '@/lib/utils'
import { AddDialog } from './AddDialog'
import { TurnOnModule } from './Inline'
import { CreatableSelect } from '@/components/common/CreatableSelect'
import { SnmpNext } from './SnmpNext'
import { SNMP_MAX } from './validate'
import { useDeviceAction, useSnmp, useSnmpActions } from './api'
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
  if (q.isPending) return <p className="text-[13px] text-muted">{t('sources.snmp.loading')}</p>
  const dialog = form ? <CredentialDialog key={form.current?.id ?? 'new'} current={form.current} scope={form.scope} widen={form.widen} onClose={() => setForm(null)} onSaved={saved} /> : null
  const addNew = creds.length < SNMP_MAX ? () => setForm({ current: null, scope: ip, widen: false }) : undefined
  if (!creds.length) {
    return (
      <div className="flex flex-wrap items-center gap-2 text-[13px] text-muted">
        {t('sources.snmp.none')} <Button size="sm" variant="primary" onClick={addNew}>{t('sources.snmp.addFor', { ip })}</Button>{dialog}
      </div>
    )
  }
  const chosen = cred || (creds[0]?.id ?? '')
  const chosenCred = creds.find((c) => c.id === chosen)
  function submit(e: FormEvent) { e.preventDefault(); read(chosen) }
  return (
    <div className="grid min-w-0 gap-2">
      <form onSubmit={submit} noValidate className="flex flex-wrap items-end gap-2">
        <Field label={t('sources.snmp.credential')} htmlFor="device-snmp-cred">
          <CreatableSelect id="device-snmp-cred" className="w-auto" value={chosen} onChange={(id) => { setCred(id); setResult(null) }}
            options={creds.map((c) => ({ value: c.id, label: credentialLabel(c.name, c.version, t(`snmp.version.${c.version}`)) }))}
            newLabel={t('addDialog.snmp.newCredential')} canCreate={creds.length < SNMP_MAX} createDisabledReason={t('addDialog.snmp.capReason', { count: SNMP_MAX })}
            renderCreate={(p) => (p.open ? <CredentialDialog current={null} scope={ip} onClose={() => p.onOpenChange(false)}
              onSaved={(c) => { p.onCreated({ value: c.id, label: credentialLabel(c.name, c.version, t(`snmp.version.${c.version}`)) }); saved(c) }} /> : null)} />
        </Field>
        <Button type="submit" size="sm" variant="primary" disabled={test.isPending}>{test.isPending ? t('snmp.run.running') : t('sources.snmp.read')}</Button>
        {chosenCred ? <Button size="sm" variant="link" onClick={() => setForm({ current: chosenCred, scope: chosenCred.scope.join('\n'), widen: false })}>{t('addDialog.snmp.editCredential', { name: chosenCred.name })}</Button> : null}
      </form>
      {q.data && !q.data.ready ? <p className="text-[13px] text-warn">{q.data.message ?? t('snmp.notReady')}</p> : null}
      {test.isPending ? <p role="status" aria-live="polite" className="text-[13px] text-muted">{t('snmp.run.pending', { ip })}</p> : null}
      {error ? <Notice tone="danger" role="alert" className="mb-0" title={error} /> : null}
      {result && !test.isPending ? <SnmpAnswer r={result} ip={ip} /> : null}
      {result && !test.isPending && !result.ok ? (
        <SnmpNext r={result} ip={ip} cred={chosenCred} onRetry={() => read(chosen)}
          onWiden={() => chosenCred && setForm({ current: chosenCred, scope: [...chosenCred.scope, ip].join('\n'), widen: true })}
          onEdit={() => chosenCred && setForm({ current: chosenCred, scope: chosenCred.scope.join('\n'), widen: false })} />
      ) : null}
      {result?.reason === 'not_for_this_credential' ? <p className="text-[12px] text-muted">{t('sources.snmp.addToScopeHint')}</p> : null}
      <p className="text-[12px] text-muted">{t('sources.snmp.scopeHint')}</p>
      {dialog}
    </div>
  )
}

/** S-INV-1 (D-598, issue #829): which sources feed this device, and adding SNMP or osquery to it from here. Both can feed it at once. */
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
  const a = d.asset
  const feeds = feedsOf(d)
  const ip = a.ip && IPV4.test(a.ip) ? a.ip : ''
  const declared = a.origin === 'manual'

  const action = (f: Feed): React.ReactNode => {
    if (f === 'snmp') {
      if (!snmpOn) return <TurnOnModule id="sensor-active" reason={t('sources.snmp.off')} />
      if (declared) return <span className="text-[13px] text-muted">{t('sources.snmp.declared')}</span>
      if (!ip) return <span className="text-[13px] text-muted">{t('sources.noIp')}</span>
      if (!a.approved) {
        // SNMP reads only approved devices (D-512): approve it here, then add SNMP (#842 "do it where you are").
        return (
          <span className="flex flex-wrap items-center gap-2">
            <span className="text-[13px] text-muted">{t('sources.snmp.approveFirst')}</span>
            <Button size="sm" disabled={!canOp || approve.isPending} title={canOp ? undefined : t('common:needRole', { role: t('common:role.operator') })}
              onClick={() => approve.mutate(undefined, { onSuccess: () => toast.success(t('pending.approved', { name: nameOf(a, kindLabel(a.kind)) })), onError: (e) => toast.error(errMsg(e)) })}>{t('sources.snmp.approveHere')}</Button>
          </span>
        )
      }
      if (!admin) return <span className="text-[13px] text-muted">{t('sources.adminOnly')}</span>
      return reading ? null : <Button size="sm" onClick={() => setReading(true)}>{feeds.has('snmp') ? t('sources.snmp.readAgain') : t('sources.snmp.add')}</Button>
    }
    if (f === 'agent') {
      if (!agentsOn) return <TurnOnModule id="agent-intake" reason={t('sources.agent.off')} />
      if (!admin) return <span className="text-[13px] text-muted">{t('sources.adminOnly')}</span>
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
                  {at ? <time className="text-[12px] text-muted" dateTime={at} title={fmtDateTime(at)}>{t('sources.lastSeen', { when: fmtRelative(at) })}</time> : null}
                </div>
                {action(f)}
              </div>
              <p className="text-[13px] text-muted">{t(`sources.what.${f}`)}</p>
              {f === 'snmp' && reading && ip ? <SnmpRead ip={ip} /> : null}
            </li>
          )
        })}
      </ul>
      <p className="mt-3 max-w-3xl text-[13px] text-muted">{t('sources.both')}</p>
      {enrol ? <AddDialog open method="osquery" onOpenChange={(o) => { if (!o) setEnrol(false) }} /> : null}
    </Section>
  )
}
