import { createElement, useId, useMemo, useRef, useState, type FormEvent } from 'react'
import { Link } from 'react-router'
import { useTranslation } from 'react-i18next'
import { Cable, FileSpreadsheet, PenLine, RadioTower, ServerCog, type LucideIcon } from 'lucide-react'
import { Notice } from '@/components/common/PageHeader'
import { InfoTip } from '@/components/common/InfoTip'
import { QueryState } from '@/components/common/States'
import { Button } from '@/components/ui/button'
import { RadioGroup, RadioItem } from '@/components/ui/checkbox'
import { Dialog, DialogContent } from '@/components/ui/dialog'
import { Field, Input, Select } from '@/components/ui/input'
import { useModuleEnabled } from '@/lib/modules'
import { useMe } from '@/lib/session'
import { cn } from '@/lib/utils'
import { AddForm } from './AddDeviceDialog'
import { OsqueryEnrol, WazuhForm } from './AgentsSection'
import { useAgents, useDevices, useSnmp, useSnmpActions } from './api'
import { ImportForm } from './ImportDialog'
import { errMsg } from './kinds'
import { CredentialDialog, CredentialForm, SnmpAnswer } from './SnmpSection'
import type { SnmpCredential, SnmpTestResult } from './types'
import { CIDR_RE_UI, cidrRange, IPV4_RE_UI } from './validate'

// "Add a device" (#849): ONE dialog with every way a device gets into the list. Manual is first and chosen on open, so the S-INV-2
// "three clicks" path stays three clicks; ?add=<method> opens it on a method (old ?tab=add, the device page's "Add SNMP / osquery").
export const METHODS = ['manual', 'snmp', 'osquery', 'wazuh', 'csv'] as const
export type Method = (typeof METHODS)[number]
const ICON: Record<Method, LucideIcon> = { manual: PenLine, snmp: RadioTower, osquery: ServerCog, wazuh: Cable, csv: FileSpreadsheet }

/** Why a method cannot be used here, or null. Manual and CSV need an operator (the button already does); the rest set up secrets: admin. */
function useBlocked(): Record<Method, string | null> {
  const { t } = useTranslation('inventory')
  const me = useMe()
  const admin = me.data ? me.data.role === 'admin' : true // unknown while loading: ?add=snmp must not fall back to Manual on the first paint
  const snmpOn = useModuleEnabled('sensor-active')
  const agentsOn = useModuleEnabled('agent-intake')
  const adminOnly = admin ? null : t('addDialog.adminOnly')
  return {
    manual: null,
    csv: null,
    snmp: snmpOn === false ? t('addDialog.snmpOff') : adminOnly,
    osquery: agentsOn === false ? t('addDialog.agentsOff') : adminOnly,
    wazuh: agentsOn === false ? t('addDialog.agentsOff') : adminOnly,
  }
}

const inScope = (target: string, scope: string[]) => {
  const r = cidrRange(IPV4_RE_UI.test(target) ? `${target}/32` : target)
  return scope.some((s) => { const q = cidrRange(IPV4_RE_UI.test(s) ? `${s}/32` : s); return r.base >= q.base && r.base + r.size <= q.base + q.size })
}

/** SNMP (D-512, the #829 device-page flow): a credential and an address or range. One address is read now with Test (it must be an approved
 *  device in the list: the Test reads devices, it does not create them); a range goes into the credential's scope and is read at every scan. */
function SnmpMethod() {
  const { t } = useTranslation('inventory')
  const uid = useId()
  const q = useSnmp(true)
  const devices = useDevices()
  const { test } = useSnmpActions()
  const [target, setTarget] = useState('')
  const [targetErr, setTargetErr] = useState<string | null>(null)
  const [cred, setCred] = useState('')
  const [adding, setAdding] = useState(false)
  const [widen, setWiden] = useState<SnmpCredential | null>(null)
  const [result, setResult] = useState<{ ip: string; r: SnmpTestResult } | null>(null)
  const [error, setError] = useState<string | null>(null)
  const known = useMemo(() => (devices.data?.items ?? []).filter((d) => d.approved && !d.is_box && IPV4_RE_UI.test(d.ip)).map((d) => d.ip), [devices.data])
  const creds = q.data?.credentials ?? []
  const chosen = creds.find((c) => c.id === cred) ?? creds[0]
  const v = target.trim()
  const isIp = IPV4_RE_UI.test(v)
  const isRange = CIDR_RE_UI.test(v)
  const covered = !!chosen && (isIp || isRange) && inScope(v, chosen.scope)

  if (q.isPending) return <p className="text-[13px] text-muted">{t('sources.snmp.loading')}</p>
  if (q.error) return <QueryState query={q}>{() => null}</QueryState>
  if (adding || !creds.length) {
    return (
      <div className="grid gap-3">
        <div className="flex items-center gap-1"><p className="text-sm font-medium">{t('snmp.form.addTitle')}</p><InfoTip topic={t('snmp.form.addTitle')}>{t('snmp.form.bodyInfo')}</InfoTip></div>
        <p className="text-[13px] text-muted">{creds.length ? t('snmp.form.body') : t('addDialog.snmp.first')}</p>
        <CredentialForm current={null} idPrefix="add-snmp" scope={isIp || isRange ? v : undefined}
          onCancel={() => setAdding(false)} onSaved={(c) => { setCred(c.id); setAdding(false) }} />
      </div>
    )
  }

  function submit(e: FormEvent) {
    e.preventDefault(); setResult(null); setError(null)
    if (!isIp && !isRange) { setTargetErr(t('addDialog.snmp.targetBad')); return }
    setTargetErr(null)
    if (isRange) { if (!covered && chosen) setWiden(chosen); return }
    if (chosen) test.mutate({ id: chosen.id, ip: v }, { onSuccess: (r) => setResult({ ip: v, r }), onError: (er) => setError(errMsg(er)) })
  }
  const targetId = `${uid}-target`
  return (
    <div className="grid min-w-0 gap-4">
      <form onSubmit={submit} noValidate className="grid gap-4">
        <div className="grid gap-4 md:grid-cols-2">
          <Field label={t('addDialog.snmp.target')} htmlFor={targetId} hint={t('addDialog.snmp.targetHint')} error={targetErr ?? undefined}>
            <Input id={targetId} list={`${uid}-known`} value={target} maxLength={18} inputMode="decimal" autoComplete="off" placeholder="192.168.10.3"
              onChange={(e) => { setTarget(e.target.value); setTargetErr(null); setResult(null) }} />
            <datalist id={`${uid}-known`}>{known.map((ip) => <option key={ip} value={ip} />)}</datalist>
          </Field>
          <Field label={t('sources.snmp.credential')} htmlFor={`${uid}-cred`}>
            <Select id={`${uid}-cred`} value={chosen?.id ?? ''} onChange={(e) => { if (e.target.value === '+') setAdding(true); else setCred(e.target.value); setResult(null) }}>
              {creds.map((c) => <option key={c.id} value={c.id}>{`${c.name} (${t(`snmp.version.${c.version}`)})`}</option>)}
              {creds.length < 8 ? <option value="+">{t('addDialog.snmp.newCredential')}</option> : null}
            </Select>
          </Field>
        </div>
        {q.data && !q.data.ready ? <p className="text-[13px] text-warn">{q.data.message ?? t('snmp.notReady')}</p> : null}
        {isRange && covered ? <Notice tone="accent" role="status" className="mb-0" title={t('addDialog.snmp.rangeCovered', { range: v, name: chosen?.name ?? '' })}>{t('addDialog.snmp.rangeWhen')}</Notice> : null}
        <div className="flex flex-wrap items-center gap-2">
          {isRange ? (
            covered ? null : <Button type="submit" variant="primary">{t('addDialog.snmp.addRange', { name: chosen?.name ?? '' })}</Button>
          ) : (
            <Button type="submit" variant="primary" disabled={test.isPending}>{test.isPending ? t('snmp.run.running') : t('addDialog.snmp.test')}</Button>
          )}
        </div>
      </form>
      {test.isPending ? <p role="status" aria-live="polite" className="text-[13px] text-muted">{t('snmp.run.pending', { ip: v })}</p> : null}
      {error ? <Notice tone="danger" role="alert" className="mb-0" title={error} /> : null}
      {result && !test.isPending ? <SnmpAnswer r={result.r} ip={result.ip} /> : null}
      {result?.r.reason === 'not_for_this_credential' && chosen && chosen.scope.length < 16 ? (
        <div><Button size="sm" onClick={() => setWiden(chosen)}>{t('sources.snmp.addToScope', { ip: result.ip, name: chosen.name })}</Button></div>
      ) : null}
      {result?.r.reason === 'not_approved' ? <p className="text-[13px]"><Link to="/devices?tab=review" className="text-accent underline-offset-4 hover:underline">{t('addDialog.snmp.openReview')}</Link></p> : null}
      {result?.r.reason === 'not_in_inventory' ? <p className="text-[13px] text-muted">{t('addDialog.snmp.notListed')}</p> : null}
      {widen ? <CredentialDialog current={widen} widen scope={[...widen.scope, v].join('\n')} onClose={() => setWiden(null)} /> : null}
    </div>
  )
}

/** osquery (S-INV-4): a token, then the one-line install for Linux or Windows servers. macOS has no installer (D-33). */
function OsqueryMethod({ onCreated }: { onCreated: (on: boolean) => void }) {
  const { t } = useTranslation('inventory')
  const q = useAgents(true)
  return (
    <div className="grid min-w-0 gap-3">
      <QueryState query={q}>{(d) => <OsqueryEnrol data={d} onCreated={() => onCreated(true)} />}</QueryState>
      <div className="flex items-center gap-1"><p className="text-[13px] text-muted">{t('addDialog.osquery.noMac')}</p><InfoTip topic={t('addDialog.osquery.noMacTopic')}>{t('addDialog.osquery.noMacInfo')}</InfoTip></div>
    </div>
  )
}

function WazuhMethod({ onDone }: { onDone: () => void }) {
  const { t } = useTranslation('inventory')
  const q = useAgents(true)
  return (
    <QueryState query={q}>
      {(d) => (
        <div className="grid min-w-0 gap-3">
          {d.wazuh ? <Notice tone="accent" role="status" className="mb-0" title={t('addDialog.wazuh.connected', { url: d.wazuh.url })}>{t('addDialog.wazuh.connectedBody')}</Notice> : null}
          <WazuhForm current={d.wazuh} onSaved={onDone} />
        </div>
      )}
    </QueryState>
  )
}

/** The method picker: radio cards, one row on a wide dialog, a list of compact rows on a phone. A method that cannot be used says why. */
function MethodPicker({ value, onChange, blocked }: { value: Method; onChange: (m: Method) => void; blocked: Record<Method, string | null> }) {
  const { t } = useTranslation('inventory')
  const uid = useId()
  return (
    <RadioGroup aria-label={t('addDialog.method')} value={value} onValueChange={(v) => onChange(v as Method)} className="grid grid-cols-1 gap-1.5 sm:grid-cols-5">
      {METHODS.map((m) => {
        const why = blocked[m]
        const id = `${uid}-${m}`
        return (
          <label key={m} htmlFor={id} className={cn('flex min-h-10 cursor-pointer items-center gap-2.5 rounded-md border px-3 py-2 sm:min-h-0 sm:flex-col sm:items-start sm:gap-1.5',
            value === m ? 'border-accent bg-accent-soft' : 'border-rule bg-surface hover:bg-sunken', why && 'cursor-not-allowed opacity-60 hover:bg-surface')}>
            <span className="flex items-center gap-2">
              <RadioItem id={id} value={m} disabled={!!why} aria-describedby={why ? `${id}-why` : undefined} />
              {createElement(ICON[m], { className: cn('size-4 shrink-0', value === m ? 'text-accent' : 'text-muted'), 'aria-hidden': true })}
              <span className="text-sm font-medium">{t(`addDialog.name.${m}`)}</span>
            </span>
            <span id={why ? `${id}-why` : undefined} className="text-[12px] leading-4 text-muted max-sm:ml-auto max-sm:text-right">{why ?? t(`addDialog.when.${m}`)}</span>
          </label>
        )
      })}
    </RadioGroup>
  )
}

export function AddDialog({ open, onOpenChange, method: initial = 'manual', onMethod }: { open: boolean; onOpenChange: (o: boolean) => void; method?: Method; onMethod?: (m: Method) => void }) {
  const { t } = useTranslation('inventory')
  const blocked = useBlocked()
  const listOpenRef = useRef(false)
  const [picked, setPicked] = useState<Method | null>(null)
  const [tokenShown, setTokenShown] = useState(false)
  const method = picked ?? (blocked[initial] ? 'manual' : initial)
  const close = (o: boolean) => { onOpenChange(o); if (!o) { setPicked(null); setTokenShown(false) } }
  const choose = (m: Method) => { setPicked(m); setTokenShown(false); onMethod?.(m) }
  const done = () => close(false)
  return (
    <Dialog open={open} onOpenChange={close}>
      <DialogContent wide title={t('add.title')} description={t('addDialog.body')} info={t('addDialog.bodyInfo')}
        onEscapeKeyDown={(e) => { if (listOpenRef.current) e.preventDefault() }}
        // Focus starts on the chosen method (APG radio group), not on the title's ⓘ.
        onOpenAutoFocus={(e) => { const r = (e.currentTarget as HTMLElement | null)?.querySelector<HTMLElement>('[role="radio"][data-state="checked"]'); if (r) { e.preventDefault(); r.focus() } }}>
        {/* Once the osquery token is shown the picker goes: switching away would lose the only copy of the secret on screen. */}
        {tokenShown ? null : <MethodPicker value={method} onChange={choose} blocked={blocked} />}
        <section aria-label={t(`addDialog.name.${method}`)} className="grid min-w-0 gap-3 border-t border-rule pt-4 [&>*]:min-w-0">
          <div className="flex items-center gap-1">
            <h3 className="text-sm font-semibold">{t(`addDialog.title.${method}`)}</h3>
            <InfoTip topic={t(`addDialog.name.${method}`)}>{t(`addDialog.info.${method}`)}</InfoTip>
          </div>
          {method === 'manual' ? <AddForm key="manual" mode="device" onDone={done} listOpenRef={listOpenRef} /> : null}
          {method === 'snmp' ? <SnmpMethod key="snmp" /> : null}
          {method === 'osquery' ? <OsqueryMethod key="osquery" onCreated={setTokenShown} /> : null}
          {method === 'wazuh' ? <WazuhMethod key="wazuh" onDone={done} /> : null}
          {method === 'csv' ? <ImportForm key="csv" onClose={done} /> : null}
        </section>
      </DialogContent>
    </Dialog>
  )
}
