import { useEffect, useState, type FormEvent, type ReactNode } from 'react'
import { Link, useSearchParams } from 'react-router'
import { useTranslation } from 'react-i18next'
import { toast } from 'sonner'
import { FlaskConical, Pencil, Plus, Trash2 } from 'lucide-react'
import { InfoTip } from '@/components/common/InfoTip'
import { Notice, Section } from '@/components/common/PageHeader'
import { Card } from '@/components/common/Card'
import { DependencyLink } from '@/components/common/DependencyLink'
import { DataTable, type ColumnDef } from '@/components/common/DataTable'
import { QueryState } from '@/components/common/States'
import { Button } from '@/components/ui/button'
import { Dialog, DialogContent, DialogFooter } from '@/components/ui/dialog'
import { Checkbox } from '@/components/ui/checkbox'
import { Field, Input, Label, Select } from '@/components/ui/input'
import { Switch } from '@/components/ui/switch'
import { ListRow, RowList } from '@/components/common/ListParts'
import { ApiError } from '@/lib/api'
import { fmtDateTime, fmtRelative } from '@/lib/format'
import { useCan } from '@/lib/session'
import { useAddTrapIp, useDeleteTrapIp, useEditTrapIp, useTestScan, useToggleTrapIp, useTrapIps } from './api'
import { testAlertToast } from './testAlert'
import { PRESETS, presetDef, portLabel, VENDORS } from './presets'
import { TrapStateChip } from './TrapStateChip'
import { HP_SERVICES, type Hit, type HpService, type TrapIP, type TrapIPsResponse, type TrapPreset, type TrapVendor } from './types'

const errMsg = (e: unknown) => (e instanceof Error ? e.message : String(e))

type FieldId = 'preset' | 'name' | 'ip' | 'vendor' | 'services' | 'form'
/** Which field a server error belongs to (each error under its own field; the rest above the buttons). */
const FIELD_OF: Record<string, FieldId> = {
  bad_preset: 'preset', bad_name: 'name', name_in_use: 'name', bad_vendor: 'vendor', bad_services: 'services',
  bad_ip: 'ip', no_lan: 'ip', ip_outside_lan: 'ip', ip_is_box: 'ip', ip_is_gateway: 'ip', ip_in_use: 'ip',
}
const INPUT_ID: Record<Exclude<FieldId, 'form'>, string> = { preset: 'tip-preset', name: 'tip-name', ip: 'tip-ip', vendor: 'tip-vendor', services: 'tip-svc-smb' }

/** One list of Trap IPs; each is a profile (name, address, vendor, its own services). S-HP-1, S-HP-2. */
export default function TrapIpsTab({ hits, lan, lanKnown = true, smbName }: { hits: Hit[]; lan: string; lanKnown?: boolean; smbName: string | null }) {
  const { t } = useTranslation('honeypot')
  const q = useTrapIps()
  const admin = useCan('admin') // /devices/setup is the administrator's (#875 r1)
  return (
    <Section id="trap-ips" label={t('trapIp.title')} description={t('trapIp.description', { lan })} info={t('trapIp.descriptionInfo')}>
      {/* §0: a Trap IP goes on the LAN range; while the box does not know it, the way to the exact field */}
      {lanKnown ? null : admin ? <DependencyLink className="mb-4" reason={t('trapIp.noLan')} to="/settings/scanning?tab=safety#range-input" label={t('trapIp.noLanLink')} />
        : <p className="mb-4 text-meta text-muted">{t('trapIp.noLan')} {t('trapIp.noLanAskAdmin')}</p>}
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
  // ?add=<look> (or add=suggested) opens the Add dialog on that look: the action of a coverage gap on the Overview tab
  const [params, setParams] = useSearchParams()
  const asked = params.get('add')
  const [editing, setEditing] = useState<Editing>(() => {
    if (!admin || !asked) return null
    const preset = asked === 'suggested' ? data.suggestions[0]?.preset ?? 'file_server' : PRESETS.find((p) => p.id === asked)?.id
    return preset ? { mode: 'add', preset } : null
  })
  useEffect(() => {
    if (asked) setParams((p) => { p.delete('add'); return p }, { replace: true })
  }, [asked, setParams])
  const lastScan = hits.find((h) => h.kind === 'scan' && !h.is_test)
  const scanReason = !operator ? t('common:needRole', { role: t('common:role.operator') }) : data.items.filter((x) => x.enabled).length < 2 ? t('trapIp.scan.needDecoys') : undefined
  const needAdmin = admin ? undefined : t('common:needRole', { role: t('common:role.admin') })
  const firstSmb = smbName ? data.items.find((x) => x.enabled && x.name === smbName && x.services.includes('smb')) : undefined

  const open = (e: Editing) => setEditing(e)
  // what the list's search reads: the name, the address, the vendor and the services
  const searchCols: ColumnDef<TrapIP>[] = [{ id: 'text', accessorFn: (d) => [d.name, d.ip, d.vendor ?? '', d.services.join(' '), d.reason ?? ''].join(' ') }]

  const addButton = <Button id="trap-ip-add" variant="primary" disabled={!admin} title={needAdmin} onClick={() => open({ mode: 'add', preset: data.suggestions[0]?.preset ?? 'file_server' })}><Plus />{t('trapIp.add')}</Button>
  return (
    <div className="grid gap-4">
      {data.suggestions.length ? (
        <Card>
          <p className="text-sm font-medium">{t('trapIp.suggestTitle')}</p>
          <div className="mt-2">
            <RowList label={t('trapIp.suggestTitle')}>
              {data.suggestions.map((s) => (
                <ListRow key={s.preset} title={t(`trapIp.preset.${s.preset}`)}
                  meta={[t('trapIp.suggestItem', { count: s.count, type: t(`trapIp.preset.${s.preset}`), names: s.examples.join(', ') })]}
                  actions={<Button size="sm" disabled={!admin} title={needAdmin} onClick={() => open({ mode: 'add', preset: s.preset })}>
                    {t('trapIp.useType', { type: t(`trapIp.preset.${s.preset}`) })}
                  </Button>} />
              ))}
            </RowList>
          </div>
        </Card>
      ) : null}

      {/* the add action sits in the list's toolbar; with no Trap IP yet there is no list, so it stands alone */}
      {data.items.length ? null : <div>{addButton}</div>}
      {/* 17 services and four fields: a wide dialog over the list, which stays as it was underneath */}
      <Dialog open={!!editing} onOpenChange={(o) => { if (!o) setEditing(null) }}>
        {editing ? (
          <DialogContent wide title={editing.mode === 'edit' ? t('trapIp.form.editTitle', { name: editing.item.name }) : t('trapIp.form.addTitle')}>
            <TrapIpForm key={editing.mode === 'edit' ? editing.item.id : `add-${editing.preset}`} data={data} editing={editing} onDone={() => setEditing(null)} />
          </DialogContent>
        ) : null}
      </Dialog>

      {data.items.length ? (
        <DataTable urlKey="trap-ips" caption={t('trapIp.listLabel')} data={data.items} columns={searchCols} pageSize={25} actions={addButton}
          list={(d) => (
            <ListRow title={d.name} sub={<span className="tabular-nums">{d.ip}</span>} badges={<TrapStateChip state={d.state} />}
              meta={[
                firstSmb?.id === d.id ? t('trapIp.smbName') : null,
                d.reason ? <span key="reason" className={d.state === 'failed' || d.state === 'conflict' ? 'text-danger' : undefined}>{d.reason}</span> : null,
              ]}
              actions={<>
                  <Switch checked={d.enabled} disabled={!admin || toggle.isPending} title={needAdmin} aria-label={t('trapIp.switchLabel', { name: d.name })}
                    onCheckedChange={(v) => toggle.mutate({ id: d.id, enabled: v }, { onError: (e) => toast.error(errMsg(e)) })} />
                  <Button size="sm" variant="ghost" disabled={!admin} title={needAdmin} aria-label={t('trapIp.editLabel', { name: d.name })} onClick={() => open({ mode: 'edit', item: d })}><Pencil /></Button>
                  <Button size="sm" variant="ghost" disabled={!admin || del.isPending} busy={del.isPending && del.variables === d.id} aria-label={t('trapIp.deleteLabel', { name: d.name })} title={needAdmin}
                    onClick={() => del.mutate(d.id, { onSuccess: () => { toast.success(t('trapIp.deleted', { name: d.name })); if (editing?.mode === 'edit' && editing.item.id === d.id) setEditing(null) }, onError: (e) => toast.error(errMsg(e)) })}><Trash2 /></Button>
              </>}>
              <TrapIpDetails d={d} />
            </ListRow>
          )} />
      ) : <div className="flex items-center gap-1 text-sm text-muted"><p>{t('trapIp.none')}</p><InfoTip topic={t('trapIp.title')}>{t('trapIp.noneInfo')}</InfoTip></div>}
      {!admin ? <p className="text-meta text-muted">{t('needAdmin')}</p> : null}

      <Card>
        <div className="flex flex-wrap items-start justify-between gap-3">
          <div className="grid max-w-3xl gap-1">
            <div className="flex items-center gap-1">
              <p className="text-sm font-medium">{t('trapIp.scan.title')}</p>
              <InfoTip topic={t('trapIp.scan.title')}>{t('trapIp.scan.bodyInfo')}</InfoTip>
            </div>
            <p className="text-meta text-muted">{t('trapIp.scan.body')}</p>
            <p className="text-meta text-muted">{lastScan ? t('trapIp.scan.last', { when: fmtRelative(lastScan.ts), src: lastScan.src_name ?? lastScan.src_ip, trapIps: lastScan.trap_hostname || lastScan.trap_ip }) : t('trapIp.scan.never')}</p>
          </div>
          <Button size="sm" disabled={!!scanReason} busy={scan.isPending} busyLabel={t('common:busy.testing')} title={scanReason} onClick={() => scan.mutate(undefined, { onSuccess: (hit) => testAlertToast(t, t('trapIp.scan.testToast'), hit), onError: (e) => toast.error(errMsg(e)) })}>
            <FlaskConical />{t('trapIp.scan.test')}
          </Button>
        </div>
      </Card>
    </div>
  )
}

/** `example` when no Trap IP has it, else the example with the first free number: BUILD-SRV-02 → BUILD-SRV-03, FILESRV-OLD → FILESRV-OLD-2
 *  (at most 15 characters, the NetBIOS limit). */
function freeName(example: string, taken: string[]): string {
  if (!taken.includes(example.toUpperCase())) return example
  const m = /^(.*?)(\d+)$/.exec(example)
  for (let n = m ? Number(m[2]) + 1 : 2; n < 100; n++) {
    const tail = m ? String(n).padStart(m[2]!.length, '0') : `-${n}`
    const name = `${(m ? m[1]! : example).slice(0, 15 - tail.length)}${tail}`
    if (!taken.includes(name.toUpperCase())) return name
  }
  return ''
}

function TrapIpForm({ data, editing, onDone }: { data: TrapIPsResponse; editing: NonNullable<Editing>; onDone: () => void }) {
  const { t } = useTranslation('honeypot')
  const add = useAddTrapIp()
  const edit = useEditTrapIp()
  const cur = editing.mode === 'edit' ? editing.item : null
  const [preset, setPreset] = useState<TrapPreset>(cur?.preset ?? (editing.mode === 'add' ? editing.preset : 'file_server'))
  // A new Trap IP starts with a free name of its look (FILESRV-OLD, NAS-ARCHIVE …); while the person has not typed one, the name
  // follows the look they pick, so a trap that answers SSH is not left named like a file server.
  const taken = data.items.filter((x) => x.id !== cur?.id).map((x) => x.name.toUpperCase())
  const suggested = (p: TrapPreset) => freeName(presetDef(p).example, taken)
  const [name, setName] = useState(cur?.name ?? suggested(preset))
  const [named, setNamed] = useState(!!cur)
  const [ip, setIp] = useState(cur?.ip ?? '')
  const [vendor, setVendor] = useState<TrapVendor | null>(cur ? cur.vendor : presetDef(preset).vendor)
  const [services, setServices] = useState<HpService[]>(cur?.services ?? presetDef(preset).services)
  const [errors, setErrors] = useState<Partial<Record<FieldId, string>>>({})
  const def = presetDef(preset)
  const busy = add.isPending || edit.isPending
  const oui = VENDORS.find((v) => v.id === vendor)?.oui

  function pickPreset(p: TrapPreset) {
    setPreset(p)
    if (!named) setName(suggested(p))
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
  const ipInfo = t(data.spare_ips.length ? (data.spare_checked ? 'trapIp.form.ipHintInfo' : 'trapIp.form.ipHintUncheckedInfo') : 'trapIp.form.ipHintNoneInfo')
  const described = (f: Exclude<FieldId, 'form'>, id: string) => (errors[f] ? `${id}-error` : `${id}-hint`)
  return (
    <form onSubmit={submit} noValidate className="grid gap-4">
        <div className="grid gap-4 sm:grid-cols-2">
          <Field label={t('trapIp.form.preset')} htmlFor="tip-preset" hint={t('trapIp.form.presetHint')} error={errors.preset}>
            <Select id="tip-preset" value={preset} onChange={(e) => pickPreset(e.target.value as TrapPreset)} aria-invalid={errors.preset ? true : undefined} aria-describedby={described('preset', 'tip-preset')}>
              {PRESETS.map((p) => <option key={p.id} value={p.id}>{t(`trapIp.preset.${p.id}`)}</option>)}
            </Select>
          </Field>
          <Field label={t('trapIp.form.name')} htmlFor="tip-name" hint={t('trapIp.form.nameHint')} info={t('trapIp.form.nameHintInfo')} error={errors.name}>
            <Input id="tip-name" value={name} onChange={(e) => { setName(e.target.value); setNamed(true); setErrors((x) => ({ ...x, name: undefined })) }} maxLength={15} autoComplete="off" spellCheck={false}
              placeholder={t('trapIp.form.namePlaceholder', { example: def.example })} aria-invalid={errors.name ? true : undefined} aria-describedby={described('name', 'tip-name')} />
          </Field>
          <Field label={t('trapIp.form.ip')} htmlFor="tip-ip" hint={ipHint} info={ipInfo} error={errors.ip}>
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
          <legend className="mb-1 flex items-center gap-1 text-sm font-medium">{t('trapIp.form.services')}<InfoTip topic={t('trapIp.form.services')}>{t('trapIp.form.servicesHintInfo')}</InfoTip></legend>
          <div className="flex flex-wrap gap-x-5 gap-y-2">
            {HP_SERVICES.map((s) => (
              <div key={s} className="flex items-center gap-2">
                <Checkbox id={`tip-svc-${s}`} checked={services.includes(s)} onCheckedChange={(c) => flip(s, c === true)} />
                <Label htmlFor={`tip-svc-${s}`} className="font-normal">{t(`service.${s}`)} <span className="text-muted tabular-nums">{portLabel(s)}</span></Label>
              </div>
            ))}
          </div>
          {errors.services ? <p id="tip-services-error" className="text-meta text-danger">{errors.services}</p> : <p id="tip-services-hint" className="text-meta text-muted">{t('trapIp.form.servicesHint')}</p>}
        </fieldset>
        {errors.form ? <Notice tone="danger" role="alert" className="mb-0" title={errors.form} /> : null}
        <DialogFooter>
          <Button type="button" onClick={onDone}>{t('trapIp.form.cancel')}</Button>
          <Button type="submit" variant="primary" busy={busy} busyLabel={t(cur ? 'common:busy.saving' : 'common:busy.adding')}>{cur ? t('trapIp.form.save') : t('trapIp.form.add')}</Button>
        </DialogFooter>
    </form>
  )
}

/** Where a Trap IP lives and what it shows the network (B2): looks, MAC and the vendor a scanner reads from it, open services, link, last touch, device. */
function TrapIpDetails({ d }: { d: TrapIP }) {
  const { t } = useTranslation('honeypot')
  const svc = (l: HpService[]) => l.map((s) => `${t(`service.${s}`)} ${portLabel(s)}`).join(', ')
  const listening = d.state === 'listening'
  const allOpen = listening && d.open_services.some((s) => !d.services.includes(s))
  const mac = !d.mac ? <span className="text-muted">{t('trapIp.where.macNone')}</span>
    : <span className="tabular-nums">{d.mac_vendor ? t('trapIp.where.macVendor', { mac: d.mac, vendor: d.mac_vendor }) : t('trapIp.where.macLocal', { mac: d.mac })}</span>
  const where = !d.attachment ? <span className="text-muted">{t('trapIp.where.attachedNone')}</span>
    : <>{d.attachment.parent ? t('trapIp.where.attachedMacvlan', { link: d.attachment.link, parent: d.attachment.parent }) : t('trapIp.where.attachedMacvlanNoParent', { link: d.attachment.link })} <InfoTip topic={t('trapIp.where.attached')}>{t('trapIp.where.attachedMacvlanInfo')}</InfoTip></>
  const rows: { k: string; label: string; value: ReactNode }[] = [
    { k: 'looks', label: t('trapIp.where.looks'), value: `${t(`trapIp.preset.${d.preset}`)}${d.vendor ? ` · ${t(`trapIp.vendor.${d.vendor}`)}` : ''}` },
    { k: 'mac', label: t('trapIp.where.mac'), value: mac },
    { k: 'open', label: t('trapIp.where.open'), value: d.open_services.length ? <>{svc(d.open_services)}{allOpen ? <span className="flex items-center gap-1 text-muted">{t('trapIp.where.openAll')}<InfoTip topic={t('trapIp.where.open')}>{t('trapIp.where.openAllInfo')}</InfoTip></span> : null}</> : <span className="text-muted">{t('trapIp.where.openNone')}</span> },
    { k: 'attached', label: t('trapIp.where.attached'), value: where },
    { k: 'last', label: t('trapIp.where.lastHit'), value: d.last_hit_at ? <time dateTime={d.last_hit_at} title={fmtDateTime(d.last_hit_at)}>{fmtRelative(d.last_hit_at)}</time> : <span className="text-muted">{t('trapIp.where.lastHitNever')}</span> },
  ]
  if (d.device_id) rows.push({ k: 'device', label: t('trapIp.where.device'), value: <Link className="text-accent underline-offset-4 hover:underline" to={`/devices/${d.device_id}`}>{t('trapIp.where.deviceLink', { name: d.device_name ?? d.ip })}</Link> })
  return (
    <dl aria-label={t('trapIp.detailsLabel', { name: d.name })} className="grid gap-x-6 gap-y-1 text-meta sm:grid-cols-[max-content_1fr]">
      {rows.map((r) => (
        <div key={r.k} className="contents">
          <dt className="text-muted">{r.label}</dt>
          <dd className="min-w-0 break-words">{r.value}</dd>
        </div>
      ))}
    </dl>
  )
}
