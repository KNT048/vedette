import { useState } from 'react'
import { Link } from 'react-router'
import { useTranslation } from 'react-i18next'
import { toast } from 'sonner'
import { FileText, Printer, Sparkles } from 'lucide-react'
import { Notice, Panel, Section } from '@/components/common/PageHeader'
import { EmptyState, QueryState } from '@/components/common/States'
import { Button, buttonVariants } from '@/components/ui/button'
import { Checkbox } from '@/components/ui/checkbox'
import { Field, Input, Label, Select } from '@/components/ui/input'
import { fmtDateTime } from '@/lib/format'
import { useCan } from '@/lib/session'
import { useGeneratePdpl, usePdpl, usePdplAi, useSaveOrg } from './api'
import { PdplDocument } from './PdplDocument'
import { ActionError } from './parts'
import { ApiError } from '@/lib/api'
import type { DataVolume, OrgSize, PdplOrg, PdplState } from './types'

const VOLUMES: DataVolume[] = ['lt1k', '1k_10k', '10k_100k', 'gte100k']
const SIZES: OrgSize[] = ['household', 'micro', 'small', 'startup', 'other']
const SECTORS = ['retail', 'manufacturing', 'services', 'education', 'health', 'finance', 'it', 'other'] as const

export default function PdplTab() {
  const { t } = useTranslation('reports')
  const pdpl = usePdpl()
  return (
    <>
      <Notice tone="warn" role="note" className="mb-6" title={t('doc.pdpl.disclaimerTitle')}>{t('doc.pdpl.disclaimerBody')}</Notice>
      <QueryState query={pdpl}>{(s) => <><OrgSection s={s} /><ReportSection s={s} /></>}</QueryState>
    </>
  )
}

type Form = { name: string; tax_code: string; address: string; sector: string; employees: string; size: OrgSize | ''; data_volume: DataVolume; processing_service: boolean; contact_name: string; contact_email: string; contact_phone: string; sensitive: boolean; cross_border: boolean; processors: boolean; level: PdplOrg['level'] }
type Errs = Partial<Record<keyof Form, string>>
const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/
const SERVER_FIELD: Record<string, keyof Form> = { invalid_name: 'name', invalid_tax_code: 'tax_code', invalid_address: 'address', invalid_sector: 'sector', invalid_employees: 'employees', invalid_size: 'size', invalid_volume: 'data_volume', invalid_contact: 'contact_name', invalid_email: 'contact_email', invalid_phone: 'contact_phone', invalid_level: 'level' }

function OrgSection({ s }: { s: PdplState }) {
  const { t } = useTranslation('reports')
  const operator = useCan('operator')
  const save = useSaveOrg()
  const o = s.org
  const [f, setF] = useState<Form>({
    name: o?.name ?? s.defaults.name, tax_code: o?.tax_code ?? '', address: o?.address ?? '', sector: o?.sector ?? '', employees: o ? String(o.employees) : '', size: o?.size ?? '',
    data_volume: o?.data_volume ?? 'lt1k', processing_service: o?.processing_service ?? false, contact_name: o?.contact_name ?? '', contact_email: o?.contact_email ?? '', contact_phone: o?.contact_phone ?? '',
    sensitive: o?.sensitive ?? false, cross_border: o?.cross_border ?? false, processors: o?.processors ?? false, level: o?.level ?? '',
  })
  const [errs, setErrs] = useState<Errs>({})
  const set = <K extends keyof Form>(k: K, v: Form[K]) => { setF((p) => ({ ...p, [k]: v })); setErrs((e) => ({ ...e, [k]: undefined })) }
  const serverKey = save.error instanceof ApiError ? SERVER_FIELD[save.error.code] : undefined
  const err = (k: keyof Form) => errs[k] ?? (serverKey === k ? (save.error as Error).message : undefined)
  const reason = operator ? undefined : t('common:needRole', { role: t('common:role.operator') })

  /** Kiểm ở trình duyệt để lỗi hiện đúng ô; máy chủ kiểm lại cùng quy tắc. */
  function validate(): boolean {
    const n: Errs = {}
    const len = (v: string, a: number, b: number) => v.trim().length >= a && v.trim().length <= b
    if (!len(f.name, 2, 120)) n.name = t('pdpl.err.name')
    if (!/^\d{10}(-\d{3})?$/.test(f.tax_code.trim())) n.tax_code = t('pdpl.err.tax')
    if (!len(f.address, 5, 200)) n.address = t('pdpl.err.address')
    if (!f.sector) n.sector = t('pdpl.err.sector')
    if (f.employees.trim() === '' || !Number.isInteger(Number(f.employees)) || Number(f.employees) < 0) n.employees = t('pdpl.err.employees')
    if (!f.size) n.size = t('pdpl.err.size')
    if (!len(f.contact_name, 2, 80)) n.contact_name = t('pdpl.err.contactName')
    if (f.contact_email.trim() === '') n.contact_email = t('pdpl.err.contactEmailRequired')
    else if (!EMAIL_RE.test(f.contact_email.trim())) n.contact_email = t('pdpl.err.contactEmail')
    if (f.contact_phone.trim() === '') n.contact_phone = t('pdpl.err.contactPhoneRequired')
    else if (!/^(0|\+84)\d{9,10}$/.test(f.contact_phone.replace(/[\s.]/g, ''))) n.contact_phone = t('pdpl.err.contactPhone')
    setErrs(n)
    return Object.keys(n).length === 0
  }
  const text = (k: 'name' | 'tax_code' | 'address' | 'contact_name' | 'contact_email' | 'contact_phone', label: string, extra?: { hint?: string; type?: string; placeholder?: string; span?: boolean }) => (
    <Field label={label} htmlFor={`pd-${k}`} hint={extra?.hint} error={err(k)} className={extra?.span ? 'sm:col-span-2' : undefined}>
      <Input id={`pd-${k}`} type={extra?.type} value={f[k]} onChange={(e) => set(k, e.target.value)} disabled={!operator} placeholder={extra?.placeholder} autoComplete="off" aria-invalid={err(k) ? true : undefined} aria-describedby={err(k) ? `pd-${k}-error` : extra?.hint ? `pd-${k}-hint` : undefined} />
    </Field>
  )
  const flag = (k: 'sensitive' | 'cross_border' | 'processors' | 'processing_service', label: string, hint: string) => (
    <div className="flex items-start gap-3">
      <Checkbox id={`pd-${k}`} checked={f[k]} onCheckedChange={(v) => set(k, v === true)} disabled={!operator} className="mt-0.5" />
      <div className="grid gap-0.5"><Label htmlFor={`pd-${k}`} className="font-normal">{label}</Label><p className="text-[13px] text-muted">{hint}</p></div>
    </div>
  )
  const sel = (k: 'sector' | 'size' | 'data_volume' | 'level', label: string, options: [string, string][], hint?: string, span?: boolean) => (
    <Field label={label} htmlFor={`pd-${k}`} hint={hint} error={err(k)} className={span ? 'sm:col-span-2' : undefined}>
      <Select id={`pd-${k}`} value={f[k]} onChange={(e) => set(k, e.target.value as never)} disabled={!operator} aria-invalid={err(k) ? true : undefined} aria-describedby={err(k) ? `pd-${k}-error` : hint ? `pd-${k}-hint` : undefined}>
        {options.map(([v, l]) => <option key={v} value={v}>{l}</option>)}
      </Select>
    </Field>
  )
  return (
    <Section title={t('pdpl.org.title')} description={t('pdpl.org.description')} stories={['S-REP-2']}>
      <form noValidate className="grid max-w-3xl gap-4" onSubmit={(e) => { e.preventDefault(); if (!validate()) return; save.mutate({ ...f, employees: Number(f.employees) } as PdplOrg, { onSuccess: () => toast.success(t('pdpl.org.saved')) }) }}>
        <div className="grid gap-4 sm:grid-cols-2">
          {text('name', t('pdpl.org.name'))}
          {text('tax_code', t('pdpl.org.tax'), { hint: t('pdpl.org.taxHint'), placeholder: '0312345678' })}
          {text('address', t('pdpl.org.address'), { span: true })}
          {sel('sector', t('pdpl.org.sector'), [['', t('pdpl.org.sectorPick')], ...SECTORS.map((k): [string, string] => [k, t(`pdpl.sector.${k}`)])])}
          <Field label={t('pdpl.org.employees')} htmlFor="pd-employees" error={err('employees')}>
            <Input id="pd-employees" type="number" min={0} max={1000000} value={f.employees} onChange={(e) => set('employees', e.target.value)} disabled={!operator} aria-invalid={err('employees') ? true : undefined} aria-describedby={err('employees') ? 'pd-employees-error' : undefined} />
          </Field>
          {sel('size', t('pdpl.org.size'), [['', t('pdpl.org.sizePick')], ...SIZES.map((k): [string, string] => [k, t(`pdpl.size.${k}`)])], t('pdpl.org.sizeHint'), true)}
          {sel('data_volume', t('pdpl.org.volume'), VOLUMES.map((v): [string, string] => [v, t(`pdpl.volume.${v}`)]), t('pdpl.org.volumeHint'), true)}
          {text('contact_name', t('pdpl.org.contactName'), { hint: t('pdpl.org.contactHint') })}
          {text('contact_email', t('pdpl.org.contactEmail'), { type: 'email' })}
          {text('contact_phone', t('pdpl.org.contactPhone'), { type: 'tel', placeholder: '0901234567' })}
          {sel('level', t('pdpl.org.level'), [['', t('pdpl.org.levelNone')], ...(['1', '2', '3', '4', '5'] as const).map((l): [string, string] => [l, t('pdpl.org.levelOption', { level: l })])], t('pdpl.org.levelHint'), true)}
        </div>
        <div className="grid gap-3">
          {flag('processing_service', t('pdpl.processingService'), t('pdpl.processingServiceHint'))}
          {flag('sensitive', t('pdpl.sensitive'), t('pdpl.sensitiveHint'))}
          {flag('cross_border', t('pdpl.crossBorder'), t('pdpl.crossBorderHint'))}
          {flag('processors', t('pdpl.processors'), t('pdpl.processorsHint'))}
        </div>
        {save.error && !serverKey ? <ActionError error={save.error} /> : null}
        <div><Button type="submit" variant="primary" disabled={!operator || save.isPending} title={reason}>{save.isPending ? t('pdpl.org.saving') : t('pdpl.org.save')}</Button></div>
      </form>
    </Section>
  )
}

function ReportSection({ s }: { s: PdplState }) {
  const { t } = useTranslation('reports')
  const operator = useCan('operator')
  const gen = useGeneratePdpl()
  const ai = usePdplAi()
  const r = s.report
  const needOrg = !s.org
  const reason = !operator ? t('common:needRole', { role: t('common:role.operator') }) : needOrg ? t('pdpl.report.needOrg') : undefined
  return (
    <Section title={t('pdpl.report.title')} description={t('pdpl.report.description')} stories={['S-REP-2']}
      actions={
        <>
          <Button variant={r ? 'secondary' : 'primary'} onClick={() => gen.mutate(undefined, { onSuccess: () => toast.success(t('pdpl.report.generated')) })} disabled={!operator || needOrg || gen.isPending} title={reason}><FileText aria-hidden />{gen.isPending ? t('pdpl.report.generating') : r ? t('pdpl.report.regenerate') : t('pdpl.report.generate')}</Button>
          {r ? (
            <>
              <Button onClick={() => ai.mutate(undefined, { onSuccess: () => toast.success(t('weekly.ai.done')) })} disabled={!operator || !s.ai_available || ai.isPending} title={!operator ? reason : s.ai_available ? undefined : t('weekly.ai.unavailable')}><Sparkles aria-hidden />{ai.isPending ? t('weekly.ai.working') : t('weekly.ai.button')}</Button>
              <Link to="/reports/print/pdpl" className={buttonVariants({ variant: 'primary' })}><Printer aria-hidden />{t('print.button')}</Link>
            </>
          ) : null}
        </>
      }>
      <div className="grid grid-cols-[minmax(0,1fr)] gap-3">
        <ActionError error={gen.error} />
        <ActionError error={ai.error} />
        {r ? (
          <>
            <p className="text-[13px] text-muted">{t('pdpl.report.at', { time: fmtDateTime(r.generated_at) })}</p>
            <Panel className="p-6"><PdplDocument report={r} /></Panel>
          </>
        ) : <EmptyState title={t('pdpl.report.empty')}>{needOrg ? t('pdpl.report.emptyNeedOrg') : t('pdpl.report.emptyReady')}</EmptyState>}
      </div>
    </Section>
  )
}
