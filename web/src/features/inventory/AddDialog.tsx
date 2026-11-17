import { createElement, useId, useMemo, useRef, useState, type FormEvent } from 'react'
import { useTranslation } from 'react-i18next'
import { Cable, FileSpreadsheet, PenLine, RadioTower, ServerCog, type LucideIcon } from 'lucide-react'
import { Notice } from '@/components/common/PageHeader'
import { InfoTip } from '@/components/common/InfoTip'
import { CreatableSelect } from '@/components/common/CreatableSelect'
import { DependencyLink } from '@/components/common/DependencyLink'
import { QueryState } from '@/components/common/States'
import { BusyNote } from '@/components/common/BusyNote'
import { Button } from '@/components/ui/button'
import { RadioGroup, RadioItem } from '@/components/ui/checkbox'
import { Dialog, DialogContent } from '@/components/ui/dialog'
import { Field, Input } from '@/components/ui/input'
import { useModuleEnabled, type ModuleId } from '@/lib/modules'
import { useMe } from '@/lib/session'
import { cn } from '@/lib/utils'
import { AddForm } from './AddDeviceDialog'
import { OsqueryEnrol, WazuhForm } from './AgentsSection'
import { inRanges } from './AddToScopeDialog'
import { useAgents, useDevices, useSettings, useSnmp, useSnmpActions } from './api'
import { TurnOnModule } from './Inline'
import { SnmpNext } from './SnmpNext'
import { ImportForm } from './ImportDialog'
import { credentialLabel, errMsg } from './kinds'
import { CredentialDialog, SnmpAnswer } from './SnmpSection'
import type { SnmpCredential, SnmpTestResult } from './types'
import { CIDR_RE_UI, IPV4_RE_UI, isPrivateCidr, LOCAL_RANGE_NAMES, normalizeRange, SNMP_MAX } from './validate'

// "Add a device" (#849): ONE dialog with every way a device gets into the list. Manual is first and chosen on open, so the S-INV-2
// "three clicks" path stays three clicks; ?add=<method> opens it on a method (old ?tab=add, the device page's "Add SNMP / osquery").
export const METHODS = ['manual', 'snmp', 'osquery', 'wazuh', 'csv'] as const
export type Method = (typeof METHODS)[number]
const ICON: Record<Method, LucideIcon> = { manual: PenLine, snmp: RadioTower, osquery: ServerCog, wazuh: Cable, csv: FileSpreadsheet }

/** What a method needs that this person or box lacks. `role`: only an admin sets up secrets (SNMP, agents), so the method is locked
 *  with that reason (a role cannot be created here). `module`: the module it runs in is off; the method stays open and its panel turns
 *  the module on right there (#842 "do it where you are"). */
type Need = { role: string | null; module: ModuleId | null }
function useNeeds(): Record<Method, Need> {
  const { t } = useTranslation('inventory')
  const me = useMe()
  const admin = me.data ? me.data.role === 'admin' : true // unknown while loading: ?add=snmp must not fall back to Manual on the first paint
  const snmpOn = useModuleEnabled('sensor-active')
  const agentsOn = useModuleEnabled('agent-intake')
  const role = admin ? null : t('addDialog.adminOnly')
  return {
    manual: { role: null, module: null },
    csv: { role: null, module: null },
    snmp: { role, module: snmpOn === false ? 'sensor-active' : null },
    osquery: { role, module: agentsOn === false ? 'agent-intake' : null },
    wazuh: { role, module: agentsOn === false ? 'agent-intake' : null },
  }
}

/** SNMP (D-512, the #829 device-page flow): a credential and an address or range. One address is read now with Test (it must be an approved
 *  device in the list: the Test reads devices, it does not create them); a range goes into the credential's scope and is read at every scan.
 *  Everything it needs is made here (kien 2026-11-16): "+ New credential" (a small dialog, selected on save, then read), Edit, the address
 *  added to a credential's scope or to the scan scope, the device approved; the full list stays in Devices › Scope, sensors and agents › SNMP. */
function SnmpMethod() {
  const { t } = useTranslation('inventory')
  const uid = useId()
  const q = useSnmp(true)
  const devices = useDevices()
  const settings = useSettings()
  const { test } = useSnmpActions()
  const [target, setTarget] = useState('')
  const [targetErr, setTargetErr] = useState<string | null>(null)
  const [cred, setCred] = useState('')
  const [form, setForm] = useState<{ current: SnmpCredential; scope?: string; widen?: boolean } | null>(null)
  const [result, setResult] = useState<{ ip: string; r: SnmpTestResult } | null>(null)
  const [error, setError] = useState<string | null>(null)
  const known = useMemo(() => (devices.data?.items ?? []).filter((d) => d.approved && !d.is_box && IPV4_RE_UI.test(d.ip)).map((d) => d.ip), [devices.data])
  const creds = q.data?.credentials ?? []
  const chosen = creds.find((c) => c.id === cred) ?? creds[0]
  const raw = target.trim()
  const isIp = IPV4_RE_UI.test(raw)
  // A range is taken as the Scope page takes it (normalizeRange): host bits cleared, "192.168.10.5/24" is 192.168.10.0/24 (#849 review M7).
  const v = CIDR_RE_UI.test(raw) ? normalizeRange(raw).value : raw
  const isRange = CIDR_RE_UI.test(v)
  const notLocal = isRange && !isPrivateCidr(v)
  const covered = !!chosen && (isIp || isRange) && inRanges(v, chosen.scope)
  // D-601: a range outside the LAN ranges goes into the credential's scope like any other; the LAN ranges are never widened for SNMP
  // (they govern discovery and network scans). A device there is read only once a person turns SNMP on for it on its page.
  const lan = settings.data?.lan_ranges
  const outsideLan = isRange && !notLocal && !!lan && !inRanges(v, lan)

  const read = (id: string, ip: string) => { setResult(null); setError(null); test.mutate({ id, ip }, { onSuccess: (r) => setResult({ ip, r }), onError: (er) => setError(errMsg(er)) }) }
  // The new credential is selected; it is read at once only when an address is typed (the customer asked for a read by making it here).
  const saved = (c: SnmpCredential) => { setCred(c.id); if (isIp) read(c.id, raw) }

  if (q.isPending) return <p className="text-meta text-muted">{t('sources.snmp.loading')}</p>
  if (q.error) return <QueryState query={q}>{() => null}</QueryState>

  function submit(e: FormEvent) {
    e.preventDefault(); setResult(null); setError(null)
    if (!isIp && !isRange) { setTargetErr(t('addDialog.snmp.targetBad')); return }
    if (notLocal) { setTargetErr(t('snmp.error.scopeNotLocal', { entry: v, ranges: LOCAL_RANGE_NAMES })); return }
    if (!chosen) { setTargetErr(t('addDialog.snmp.needCredential')); return } // Enter with no credential says what is missing (r2 L5)
    setTargetErr(null)
    if (isRange) { if (!covered) setForm({ current: chosen, widen: true, scope: [...chosen.scope, v].join('\n') }); return }
    read(chosen.id, raw)
  }
  const targetId = `${uid}-target`
  const credId = `${uid}-cred`
  const label = (c: SnmpCredential) => credentialLabel(c.name, c.version, t(`snmp.version.${c.version}`))
  return (
    <div className="grid min-w-0 gap-4">
      {creds.length ? null : <p className="text-meta text-muted">{t('addDialog.snmp.first')}</p>}
      <form onSubmit={submit} noValidate className="grid grid-cols-1 gap-4">
        <div className="grid grid-cols-1 gap-4 md:grid-cols-2">
          <Field label={t('addDialog.snmp.target')} htmlFor={targetId} hint={t('addDialog.snmp.targetHint')} error={targetErr ?? undefined}>
            <Input id={targetId} list={`${uid}-known`} value={target} maxLength={18} inputMode="decimal" autoComplete="off" placeholder="192.168.10.3"
              onChange={(e) => { setTarget(e.target.value); setTargetErr(null); setResult(null) }} />
            <datalist id={`${uid}-known`}>{known.map((ip) => <option key={ip} value={ip} />)}</datalist>
          </Field>
          <div className="grid content-start gap-1.5">
            <Field label={t('sources.snmp.credential')} htmlFor={credId}>
              <CreatableSelect id={credId} value={chosen?.id ?? ''} onChange={(id) => { setCred(id); setResult(null) }}
                options={creds.map((c) => ({ value: c.id, label: label(c) }))} placeholder={creds.length ? undefined : t('addDialog.snmp.noCredential')}
                newLabel={t('addDialog.snmp.newCredential')} canCreate={creds.length < SNMP_MAX} createDisabledReason={t('addDialog.snmp.capReason', { count: SNMP_MAX })}
                renderCreate={(p) => (p.open ? <CredentialDialog current={null} scope={isIp || (isRange && !notLocal) ? v : undefined} onClose={() => p.onOpenChange(false)}
                  onSaved={(c) => { p.onCreated({ value: c.id, label: label(c) }); saved(c) }} /> : null)} />
            </Field>
            {chosen ? <div><Button size="sm" variant="link" onClick={() => setForm({ current: chosen })}>{t('addDialog.snmp.editCredential', { name: chosen.name })}</Button></div> : null}
            {creds.length >= SNMP_MAX ? <DependencyLink reason={t('addDialog.snmp.capWhy', { count: SNMP_MAX })} to="/devices/setup?tab=snmp#snmp" label={t('addDialog.snmp.capLink')} /> : null}
          </div>
        </div>
        {q.data && !q.data.ready ? <p className="text-meta text-warn">{q.data.message ?? t('snmp.notReady')}</p> : null}
        {outsideLan ? <Notice tone="accent" role="status" className="mb-0" title={t('addDialog.snmp.outsideLan', { range: v })}>{t('addDialog.snmp.outsideLanWhy')}</Notice> : null}
        {isRange && covered ? <Notice tone="accent" role="status" className="mb-0" title={t('addDialog.snmp.rangeCovered', { range: v, name: chosen?.name ?? '' })}>{t('addDialog.snmp.rangeWhen')}</Notice> : null}
        {chosen ? (
          <div className="flex flex-wrap items-center gap-2">
            {/* busy-guard: for a range the form only opens a dialog (add to scope, or widen the credential), each with its own busy Save */}
            {isRange ? (
              covered ? null : /* busy-guard: opens the credential dialog */ <Button type="submit" variant="primary">{t('addDialog.snmp.addRange', { name: chosen.name })}</Button>
            ) : (
              <Button type="submit" variant="primary" busy={test.isPending} busyLabel={t('snmp.run.running')}>{t('addDialog.snmp.test')}</Button>
            )}
          </div>
        ) : null}
      </form>
      <BusyNote busy={test.isPending}>{t('snmp.run.pending', { ip: raw })}</BusyNote>
      {error ? <Notice tone="danger" role="alert" className="mb-0" title={error} /> : null}
      {result && !test.isPending ? <SnmpAnswer r={result.r} ip={result.ip} /> : null}
      {result && !test.isPending && !result.r.ok ? (
        <SnmpNext r={result.r} ip={result.ip} cred={chosen}
          onWiden={() => chosen && setForm({ current: chosen, widen: true, scope: [...chosen.scope, result.ip].join('\n') })}
          onEdit={() => chosen && setForm({ current: chosen })} onRetry={() => chosen && read(chosen.id, result.ip)} />
      ) : null}
      {form ? <CredentialDialog key={form.current.id} current={form.current} scope={form.scope} widen={form.widen} onClose={() => setForm(null)} onSaved={saved} /> : null}
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
      <div className="flex items-center gap-1"><p className="text-meta text-muted">{t('addDialog.osquery.noMac')}</p><InfoTip topic={t('addDialog.osquery.noMacTopic')}>{t('addDialog.osquery.noMacInfo')}</InfoTip></div>
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
function MethodPicker({ value, onChange, needs }: { value: Method; onChange: (m: Method) => void; needs: Record<Method, Need> }) {
  const { t } = useTranslation('inventory')
  const uid = useId()
  return (
    <RadioGroup aria-label={t('addDialog.method')} value={value} onValueChange={(v) => onChange(v as Method)} className="grid grid-cols-1 gap-1.5 sm:grid-cols-5">
      {METHODS.map((m) => {
        const why = needs[m].role
        const off = needs[m].module
        const id = `${uid}-${m}`
        return (
          <label key={m} htmlFor={id} className={cn('flex min-h-10 cursor-pointer items-center gap-2.5 rounded-md border px-3 py-2 sm:min-h-0 sm:flex-col sm:items-start sm:gap-1.5',
            value === m ? 'border-accent bg-accent-soft' : 'border-rule bg-surface hover:bg-sunken', why && 'cursor-not-allowed opacity-60 hover:bg-surface')}>
            <span className="flex items-center gap-2">
              <RadioItem id={id} value={m} disabled={!!why} aria-describedby={why ? `${id}-why` : undefined} />
              {createElement(ICON[m], { className: cn('size-4 shrink-0', value === m ? 'text-accent' : 'text-muted'), 'aria-hidden': true })}
              <span className="text-sm font-medium">{t(`addDialog.name.${m}`)}</span>
            </span>
            <span id={why ? `${id}-why` : undefined} className="text-caption text-muted max-sm:ml-auto max-sm:text-right">{why ?? (off ? t('addDialog.moduleOff') : t(`addDialog.when.${m}`))}</span>
          </label>
        )
      })}
    </RadioGroup>
  )
}

export function AddDialog({ open, onOpenChange, method: initial = 'manual', onMethod }: { open: boolean; onOpenChange: (o: boolean) => void; method?: Method; onMethod?: (m: Method) => void }) {
  const { t } = useTranslation('inventory')
  const needs = useNeeds()
  const listOpenRef = useRef(false)
  const [picked, setPicked] = useState<Method | null>(null)
  const [tokenShown, setTokenShown] = useState(false)
  const method = picked ?? (needs[initial].role ? 'manual' : initial)
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
        {tokenShown ? null : <MethodPicker value={method} onChange={choose} needs={needs} />}
        <section aria-label={t(`addDialog.name.${method}`)} className="grid min-w-0 grid-cols-1 gap-3 border-t border-rule pt-4 [&>*]:min-w-0">
          <div className="flex items-center gap-1">
            <h3 className="text-sm font-semibold">{t(`addDialog.title.${method}`)}</h3>
            <InfoTip topic={t(`addDialog.name.${method}`)}>{t(`addDialog.info.${method}`)}</InfoTip>
          </div>
          {method === 'manual' ? <AddForm key="manual" mode="device" onDone={done} listOpenRef={listOpenRef} /> : null}
          {needs[method].module ? <TurnOnModule id={needs[method].module!} reason={t(`addDialog.needs.${method}`)} /> : (
            <>
              {method === 'snmp' ? <SnmpMethod key="snmp" /> : null}
              {method === 'osquery' ? <OsqueryMethod key="osquery" onCreated={setTokenShown} /> : null}
              {method === 'wazuh' ? <WazuhMethod key="wazuh" onDone={done} /> : null}
            </>
          )}
          {method === 'csv' ? <ImportForm key="csv" onClose={done} /> : null}
        </section>
      </DialogContent>
    </Dialog>
  )
}
