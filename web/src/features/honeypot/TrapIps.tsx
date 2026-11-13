import { useState, type FormEvent } from 'react'
import { useTranslation } from 'react-i18next'
import { toast } from 'sonner'
import { FlaskConical, Pencil, Plus, Trash2 } from 'lucide-react'
import { Section, Panel } from '@/components/common/PageHeader'
import { QueryState } from '@/components/common/States'
import { Button } from '@/components/ui/button'
import { Checkbox } from '@/components/ui/checkbox'
import { Field, Input, Label, Select } from '@/components/ui/input'
import { Switch } from '@/components/ui/switch'
import { ApiError } from '@/lib/api'
import { fmtRelative } from '@/lib/format'
import { useCan } from '@/lib/session'
import { useAddTrapIp, useDeleteTrapIp, useEditTrapIp, useTestScan, useToggleTrapIp, useTrapIps } from './api'
import { PRESETS, presetDef, SERVICE_PORT, VENDORS } from './presets'
import { TrapStateChip } from './TrapStateChip'
import { HP_SERVICES, type Hit, type HpService, type TrapIP, type TrapIPsResponse, type TrapPreset, type TrapVendor } from './types'

const errMsg = (e: unknown) => (e instanceof Error ? e.message : String(e))

type FieldId = 'preset' | 'name' | 'ip' | 'vendor' | 'services' | 'form'
/** Which field a server error belongs to (D-466: each error under its own field; the rest above the buttons). */
const FIELD_OF: Record<string, FieldId> = {
  bad_preset: 'preset', bad_name: 'name', name_in_use: 'name', bad_vendor: 'vendor', bad_services: 'services',
  bad_ip: 'ip', no_lan: 'ip', ip_outside_lan: 'ip', ip_is_box: 'ip', ip_in_use: 'ip',
}
const INPUT_ID: Record<Exclude<FieldId, 'form'>, string> = { preset: 'tip-preset', name: 'tip-name', ip: 'tip-ip', vendor: 'tip-vendor', services: 'tip-svc-smb' }

/** D-466: one list of Trap IPs; each is a profile (name, address, vendor, its own services). S-HP-1, S-HP-2. */
export default function TrapIpsTab({ hits, lan, smbName }: { hits: Hit[]; lan: string; smbName: string | null }) {
  const { t } = useTranslation('honeypot')
  const q = useTrapIps()
  return (
    <Section id="trap-ips" title={t('trapIp.title')} description={t('trapIp.description', { lan })}>
      <QueryState query={q}>{(d) => <Inner data={d} hits={hits} smbName={smbName} />}</QueryState>
    </Section>
  )
}

type Editing = { mode: 'add'; preset: TrapPreset } | { mode: 'edit'; item: TrapIP } | null

function Inner({ data, hits, smbName }: { data: TrapIPsResponse; hits: Hit[]; smbName: string | null }) {
  const { t } = useTranslation('honeypot')
  const admin = useCan('admin')
  const operator = useCan('operator')
  const toggle = useToggleTrapIp()
  const del = useDeleteTrapIp()
  const scan = useTestScan()
  const [editing, setEditing] = useState<Editing>(null)
  const lastScan = hits.find((h) => h.kind === 'scan' && !h.is_test)
  const scanReason = !operator ? t('common:needRole', { role: t('common:role.operator') }) : data.items.filter((x) => x.enabled).length < 2 ? t('trapIp.scan.needDecoys') : undefined
  const needAdmin = admin ? undefined : t('common:needRole', { role: t('common:role.admin') })
  const firstSmb = smbName ? data.items.find((x) => x.enabled && x.name === smbName && x.services.includes('smb')) : undefined

  function open(e: Editing) {
    setEditing(e)
    requestAnimationFrame(() => document.getElementById('tip-preset')?.focus())
  }

  return (
    <div className="grid gap-4">
      {data.suggestions.length ? (
        <Panel className="p-4">
          <p className="text-sm font-medium">{t('trapIp.suggestTitle')}</p>
          <ul className="mt-2 grid gap-1.5 text-sm">
            {data.suggestions.map((s) => (
              <li key={s.preset} className="flex flex-wrap items-center justify-between gap-2">
                <span>{t('trapIp.suggestItem', { count: s.count, type: t(`trapIp.preset.${s.preset}`), names: s.examples.join(', ') })}</span>
                <Button size="sm" disabled={!admin} title={needAdmin} onClick={() => open({ mode: 'add', preset: s.preset })}>
                  {t('trapIp.useType', { type: t(`trapIp.preset.${s.preset}`) })}
                </Button>
              </li>
            ))}
          </ul>
        </Panel>
      ) : null}

      {editing ? (
        <TrapIpForm key={editing.mode === 'edit' ? editing.item.id : `add-${editing.preset}`} data={data} editing={editing} onDone={() => setEditing(null)} />
      ) : (
        <div>
          <Button variant="primary" disabled={!admin} title={needAdmin} onClick={() => open({ mode: 'add', preset: data.suggestions[0]?.preset ?? 'file_server' })}><Plus />{t('trapIp.add')}</Button>
        </div>
      )}

      {data.items.length ? (
        <ul className="grid divide-y divide-rule rounded-md border border-rule bg-surface" aria-label={t('trapIp.listLabel')}>
          {data.items.map((d) => (
            <li key={d.id} className="flex flex-wrap items-center justify-between gap-3 px-4 py-3 text-sm">
              <span className="grid min-w-0">
                <span className="font-medium">{d.name} <span className="text-[13px] font-normal text-muted tabular-nums">{d.ip}</span></span>
                <span className="text-[12px] text-muted">
                  {t(`trapIp.preset.${d.preset}`)}: {d.services.map((s) => `${t(`service.${s}`)} ${SERVICE_PORT[s]}`).join(', ')}
                  {d.vendor ? ` · ${t(`trapIp.vendor.${d.vendor}`)}` : null}
                  {d.mac ? <> · <span className="tabular-nums">{t('trapIp.mac', { mac: d.mac })}</span></> : null}
                </span>
                {firstSmb?.id === d.id ? <span className="text-[12px] text-muted">{t('trapIp.smbName')}</span> : null}
                {d.reason ? <span className={d.state === 'failed' || d.state === 'conflict' ? 'text-[12px] text-danger' : 'text-[12px] text-muted'}>{d.reason}</span> : null}
              </span>
              <span className="flex items-center gap-3">
                <TrapStateChip state={d.state} />
                <Switch checked={d.enabled} disabled={!admin || toggle.isPending} title={needAdmin} aria-label={t('trapIp.switchLabel', { name: d.name })}
                  onCheckedChange={(v) => toggle.mutate({ id: d.id, enabled: v }, { onError: (e) => toast.error(errMsg(e)) })} />
                <Button size="sm" variant="ghost" disabled={!admin} title={needAdmin} aria-label={t('trapIp.editLabel', { name: d.name })} onClick={() => open({ mode: 'edit', item: d })}><Pencil /></Button>
                <Button size="sm" variant="ghost" disabled={!admin || del.isPending} aria-label={t('trapIp.deleteLabel', { name: d.name })} title={needAdmin}
                  onClick={() => del.mutate(d.id, { onSuccess: () => { toast.success(t('trapIp.deleted', { name: d.name })); if (editing?.mode === 'edit' && editing.item.id === d.id) setEditing(null) }, onError: (e) => toast.error(errMsg(e)) })}><Trash2 /></Button>
              </span>
            </li>
          ))}
        </ul>
      ) : <p className="text-sm text-muted">{t('trapIp.none')}</p>}
      {!admin ? <p className="text-[13px] text-muted">{t('needAdmin')}</p> : null}

      <Panel className="p-4">
        <div className="flex flex-wrap items-start justify-between gap-3">
          <div className="grid max-w-3xl gap-1">
            <p className="text-sm font-medium">{t('trapIp.scan.title')}</p>
            <p className="text-[13px] text-muted">{t('trapIp.scan.body')}</p>
            <p className="text-[13px] text-muted">{lastScan ? t('trapIp.scan.last', { when: fmtRelative(lastScan.ts), src: lastScan.src_name ?? lastScan.src_ip }) : t('trapIp.scan.never')}</p>
          </div>
          <Button size="sm" disabled={!!scanReason || scan.isPending} title={scanReason} onClick={() => scan.mutate(undefined, { onSuccess: () => toast.success(t('trapIp.scan.testToast')), onError: (e) => toast.error(errMsg(e)) })}>
            <FlaskConical />{t('trapIp.scan.test')}
          </Button>
        </div>
      </Panel>
    </div>
  )
}

function TrapIpForm({ data, editing, onDone }: { data: TrapIPsResponse; editing: NonNullable<Editing>; onDone: () => void }) {
  const { t } = useTranslation('honeypot')
  const add = useAddTrapIp()
  const edit = useEditTrapIp()
  const cur = editing.mode === 'edit' ? editing.item : null
  const [preset, setPreset] = useState<TrapPreset>(cur?.preset ?? (editing.mode === 'add' ? editing.preset : 'file_server'))
  const [name, setName] = useState(cur?.name ?? '')
  const [ip, setIp] = useState(cur?.ip ?? '')
  const [vendor, setVendor] = useState<TrapVendor | null>(cur ? cur.vendor : presetDef(preset).vendor)
  const [services, setServices] = useState<HpService[]>(cur?.services ?? presetDef(preset).services)
  const [errors, setErrors] = useState<Partial<Record<FieldId, string>>>({})
  const def = presetDef(preset)
  const busy = add.isPending || edit.isPending
  const oui = VENDORS.find((v) => v.id === vendor)?.oui

  function pickPreset(p: TrapPreset) {
    setPreset(p)
    const d = presetDef(p)
    if (p !== 'custom') { setServices(d.services); setVendor(d.vendor) }
    setErrors((e) => ({ ...e, preset: undefined, services: undefined, vendor: undefined }))
  }
  function flip(s: HpService, on: boolean) {
    setServices((l) => (on ? HP_SERVICES.filter((x) => x === s || l.includes(x)) : l.filter((x) => x !== s)))
    setErrors((e) => ({ ...e, services: undefined }))
  }
  function focus(f: FieldId) { if (f !== 'form') document.getElementById(INPUT_ID[f])?.focus() }

  function submit(e: FormEvent) {
    e.preventDefault()
    // The empty fields are said at once, each under its own field; the rest the server checks (the same rules as the box).
    const local: Partial<Record<FieldId, string>> = {}
    if (!name.trim()) local.name = t('trapIp.form.nameRequired', { example: def.example })
    if (!ip.trim()) local.ip = t('trapIp.form.ipRequired')
    if (!services.length) local.services = t('trapIp.form.servicesRequired')
    setErrors(local)
    const first = (['name', 'ip', 'services'] as const).find((f) => local[f])
    if (first) { focus(first); return }
    const b = { name: name.trim(), ip: ip.trim(), preset, vendor, services }
    const onError = (er: unknown) => {
      const f = er instanceof ApiError ? FIELD_OF[er.code] ?? 'form' : 'form'
      setErrors({ [f]: errMsg(er) })
      focus(f)
    }
    if (cur) edit.mutate({ id: cur.id, ...b }, { onSuccess: (x) => { toast.success(t('trapIp.saved', { name: x.name })); onDone() }, onError })
    else add.mutate(b, { onSuccess: (x) => { toast.success(t('trapIp.added', { name: x.name })); onDone() }, onError })
  }

  const ipHint = data.spare_ips.length ? t(data.spare_checked ? 'trapIp.form.ipHint' : 'trapIp.form.ipHintUnchecked', { ips: data.spare_ips.join(', ') }) : t('trapIp.form.ipHintNone')
  const described = (f: Exclude<FieldId, 'form'>, id: string) => (errors[f] ? `${id}-error` : `${id}-hint`)
  return (
    <Panel className="p-4">
      <form onSubmit={submit} noValidate aria-labelledby="tip-form-title" className="grid gap-4">
        <p id="tip-form-title" className="text-sm font-medium">{cur ? t('trapIp.form.editTitle', { name: cur.name }) : t('trapIp.form.addTitle')}</p>
        <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
          <Field label={t('trapIp.form.preset')} htmlFor="tip-preset" hint={t('trapIp.form.presetHint')} error={errors.preset}>
            <Select id="tip-preset" value={preset} onChange={(e) => pickPreset(e.target.value as TrapPreset)} aria-invalid={errors.preset ? true : undefined} aria-describedby={described('preset', 'tip-preset')}>
              {PRESETS.map((p) => <option key={p.id} value={p.id}>{t(`trapIp.preset.${p.id}`)}</option>)}
            </Select>
          </Field>
          <Field label={t('trapIp.form.name')} htmlFor="tip-name" hint={t('trapIp.form.nameHint')} error={errors.name}>
            <Input id="tip-name" value={name} onChange={(e) => { setName(e.target.value); setErrors((x) => ({ ...x, name: undefined })) }} maxLength={15} autoComplete="off" spellCheck={false}
              placeholder={t('trapIp.form.namePlaceholder', { example: def.example })} aria-invalid={errors.name ? true : undefined} aria-describedby={described('name', 'tip-name')} />
          </Field>
          <Field label={t('trapIp.form.ip')} htmlFor="tip-ip" hint={ipHint} error={errors.ip}>
            <Input id="tip-ip" value={ip} onChange={(e) => { setIp(e.target.value); setErrors((x) => ({ ...x, ip: undefined })) }} inputMode="decimal" autoComplete="off"
              placeholder={data.spare_ips[0] ? t('trapIp.form.ipPlaceholder', { ip: data.spare_ips[0] }) : undefined} aria-invalid={errors.ip ? true : undefined} aria-describedby={described('ip', 'tip-ip')} />
          </Field>
          <Field label={t('trapIp.form.vendor')} htmlFor="tip-vendor" hint={vendor && oui ? t('trapIp.form.vendorHint', { oui, vendor: t(`trapIp.vendor.${vendor}`) }) : t('trapIp.form.vendorHintNone')} error={errors.vendor}>
            <Select id="tip-vendor" value={vendor ?? ''} onChange={(e) => { setVendor((e.target.value || null) as TrapVendor | null); setErrors((x) => ({ ...x, vendor: undefined })) }} aria-invalid={errors.vendor ? true : undefined} aria-describedby={described('vendor', 'tip-vendor')}>
              <option value="">{t('trapIp.vendor.none')}</option>
              {VENDORS.map((v) => <option key={v.id} value={v.id}>{t(`trapIp.vendor.${v.id}`)}</option>)}
            </Select>
          </Field>
        </div>
        <fieldset className="grid gap-2" aria-describedby={errors.services ? 'tip-services-error' : 'tip-services-hint'}>
          <legend className="mb-1 text-sm font-medium">{t('trapIp.form.services')}</legend>
          <div className="flex flex-wrap gap-x-5 gap-y-2">
            {HP_SERVICES.map((s) => (
              <div key={s} className="flex items-center gap-2">
                <Checkbox id={`tip-svc-${s}`} checked={services.includes(s)} onCheckedChange={(c) => flip(s, c === true)} />
                <Label htmlFor={`tip-svc-${s}`} className="font-normal">{t(`service.${s}`)} <span className="text-muted tabular-nums">{SERVICE_PORT[s]}</span></Label>
              </div>
            ))}
          </div>
          {errors.services ? <p id="tip-services-error" className="text-[13px] text-danger">{errors.services}</p> : <p id="tip-services-hint" className="text-[13px] text-muted">{t('trapIp.form.servicesHint')}</p>}
        </fieldset>
        {errors.form ? <p role="alert" className="rounded-md border border-danger/40 bg-danger-soft px-3 py-2 text-[13px] text-danger">{errors.form}</p> : null}
        <div className="flex flex-wrap gap-2">
          <Button type="submit" variant="primary" disabled={busy}>{cur ? t('trapIp.form.save') : t('trapIp.form.add')}</Button>
          <Button type="button" onClick={onDone}>{t('trapIp.form.cancel')}</Button>
        </div>
      </form>
    </Panel>
  )
}
