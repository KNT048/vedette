import { useState } from 'react'
import { useTranslation } from 'react-i18next'
import { X } from 'lucide-react'
import { toast } from 'sonner'
import { KeyValue, Section } from '@/components/common/PageHeader'
import { Chip, type Tone } from '@/components/common/StatusChip'
import { Button } from '@/components/ui/button'
import { Field, Input, Label, Select } from '@/components/ui/input'
import { Switch } from '@/components/ui/switch'
import { fmtRelative } from '@/lib/format'
import { useNetworkActions, useSpanStatus } from './api'
import { errMsg, useGate } from './parts'
import { FILTER_TYPES, filterProblem, normaliseFilter, type FilterType } from './networkRules'
import type { NetworkState, SpanConfig, SpanStatus } from './types'

const TONE: Record<SpanStatus['verdict'], Tone> = { off: 'off', ok: 'ok', own_only: 'warn', no_traffic: 'warn', no_link: 'warn', sensor_unreachable: 'warn' }
const EXTRACT = ['dns', 'tls_sni', 'http_host', 'flows'] as const

/** Live health of the mirrored traffic with plain advice. Refreshes every 5 seconds. */
function Status({ iface }: { iface: string | null }) {
  const { t } = useTranslation('core')
  const q = useSpanStatus()
  const s = q.data
  if (!s) return null
  return (
    <div className="grid gap-3 rounded-md border border-rule bg-surface px-4 py-3" aria-label={t('network.span.statusTitle')} role="group">
      <div className="flex flex-wrap items-center gap-2">
        <h3 className="text-sm font-semibold">{t('network.span.statusTitle')}</h3>
        <Chip tone={TONE[s.verdict]}>{t(`network.span.verdict.${s.verdict}.title`)}</Chip>
      </div>
      <p className="max-w-2xl text-sm">{t(`network.span.verdict.${s.verdict}.advice`, { iface: iface ?? '' })}</p>
      {s.verdict !== 'off' ? (
        <KeyValue items={[
          { label: t('network.span.pps'), value: s.packets_per_s },
          { label: t('network.span.macs'), value: s.other_macs },
          { label: t('network.span.last'), value: s.last_packet_at ? fmtRelative(s.last_packet_at) : t('network.span.never') },
        ]} />
      ) : null}
    </div>
  )
}

/** readOnly (D-403, SPAN hidden for v1): what this box already has, every control locked and no Save; the way out is the role Unused. */
export function SpanCard({ d, readOnly = false }: { d: NetworkState; readOnly?: boolean }) {
  const { t } = useTranslation('core')
  const gate = useGate('admin')
  const locked = gate.disabled || readOnly
  const { span } = useNetworkActions()
  const [v, setV] = useState<SpanConfig>(d.span)
  const [ftype, setFtype] = useState<FilterType>('cidr')
  const [fvalue, setFvalue] = useState('')
  const [ferror, setFerror] = useState<string | null>(null)
  const [error, setError] = useState<string | null>(null)
  const dirty = JSON.stringify(v) !== JSON.stringify(d.span)
  const chosen = EXTRACT.filter((k) => v.extract[k])
  function addFilter() {
    const p = filterProblem(ftype, fvalue)
    if (p) { setFerror(p); return }
    const value = normaliseFilter(ftype, fvalue)
    if (v.filters.some((f) => f.type === ftype && f.value === value)) { setFerror(t('network.span.filterDup', { value })); return }
    setV({ ...v, filters: [...v.filters, { type: ftype, value }] }); setFvalue(''); setFerror(null)
  }
  return (
    <Section id="span" title={t('network.span.title')} description={t('network.span.desc')} stories={['S-CORE-8', 'S-INV-1', 'S-LOG-4']}>
      <div className="grid max-w-3xl gap-5">
        <Status iface={d.span.interface} />
        <p className="-mt-3 text-[13px] text-muted">{t('network.span.statusNote')}</p>
        {readOnly ? <p role="note" className="rounded-md border border-rule bg-sunken px-3 py-2 text-[13px]">{t('network.span.kept', { iface: d.span.interface ?? d.interfaces.find((i) => i.role === 'span')?.name ?? '' })}</p> : null}
        <form className="grid gap-5" noValidate onSubmit={(e) => {
          e.preventDefault(); setError(null)
          span.mutate(v, { onSuccess: () => toast.success(t('network.span.saved')), onError: (er) => setError(errMsg(er, t)) })
        }}>
          <div className="flex items-center gap-3">
            <Switch id="span-enabled" checked={v.enabled} disabled={locked} title={gate.title} onCheckedChange={(on) => setV({ ...v, enabled: on })} />
            <Label htmlFor="span-enabled">{t('network.span.enabled')}</Label>
          </div>
          <Field label={t('network.span.port')} htmlFor="span-iface" hint={t('network.span.portHint')} className="max-w-sm">
            <Select id="span-iface" value={v.interface ?? ''} disabled={locked} onChange={(e) => setV({ ...v, interface: e.target.value || null })}>
              <option value="">{t('network.span.choose')}</option>
              {d.interfaces.map((i) => (
                <option key={i.name} value={i.name} disabled={i.role === 'management'}>{i.name}{i.role === 'management' ? ` ${t('network.span.isManagement')}` : i.link ? '' : ` ${t('network.span.noLink')}`}</option>
              ))}
            </Select>
          </Field>

          <fieldset className="grid gap-2">
            <legend className="mb-1 text-sm font-medium">{t('network.span.extractTitle')}</legend>
            {EXTRACT.map((k) => (
              <div key={k} className="flex items-start gap-3">
                <Switch id={`span-x-${k}`} checked={v.extract[k]} disabled={locked} className="mt-0.5" onCheckedChange={(on) => setV({ ...v, extract: { ...v.extract, [k]: on } })} />
                <div className="grid gap-0.5"><Label htmlFor={`span-x-${k}`}>{t(`network.span.extract.${k}`)}</Label><span className="text-[13px] text-muted">{t(`network.span.extractHint.${k}`)}</span></div>
              </div>
            ))}
            <p className="text-[13px] font-medium">{t('network.span.neverStored')}</p>
            <p className="text-[13px] text-muted" data-testid="span-reading">{chosen.length ? t('network.span.reading', { list: chosen.map((k) => t(`network.span.extract.${k}`)).join(', ') }) : t('network.span.readingNone')}</p>
          </fieldset>

          <fieldset className="grid gap-3">
            <legend className="mb-1 text-sm font-medium">{t('network.span.filtersTitle')}</legend>
            <p className="max-w-xl text-[13px] text-muted">{t('network.span.filtersDesc')}</p>
            {v.filters.length ? (
              <ul aria-label={t('network.span.filtersTitle')} className="flex flex-wrap gap-2">
                {v.filters.map((f) => (
                  <li key={`${f.type}:${f.value}`} className="flex items-center gap-1.5 rounded-md border border-rule bg-surface py-1 pl-2.5 pr-1 text-[13px]">
                    <span className="text-muted">{t(`network.span.ftype.${f.type}.short`)}</span><span className="font-mono text-[12.5px]">{f.value}</span>
                    <Button size="sm" variant="ghost" disabled={locked} aria-label={t('network.span.filterRemove', { value: f.value })} onClick={() => setV({ ...v, filters: v.filters.filter((x) => x !== f) })}><X /></Button>
                  </li>
                ))}
              </ul>
            ) : <p className="text-[13px] text-muted">{t('network.span.filtersNone')}</p>}
            <div className="grid items-start gap-3 sm:grid-cols-[170px_minmax(0,1fr)_auto]">
              <Field label={t('network.span.ftypeLabel')} htmlFor="span-ftype">
                <Select id="span-ftype" value={ftype} disabled={locked} onChange={(e) => { setFtype(e.target.value as FilterType); setFvalue(''); setFerror(null) }}>
                  {FILTER_TYPES.map((x) => <option key={x} value={x}>{t(`network.span.ftype.${x}.option`)}</option>)}
                </Select>
              </Field>
              <Field label={t(`network.span.ftype.${ftype}.label`)} htmlFor="span-fvalue" hint={t(`network.span.ftype.${ftype}.hint`)} error={ferror ?? undefined}>
                <Input id="span-fvalue" autoComplete="off" value={fvalue} disabled={locked} aria-invalid={!!ferror} placeholder={t(`network.span.ftype.${ftype}.example`)} inputMode={ftype === 'port' ? 'numeric' : undefined}
                  onChange={(e) => { setFvalue(e.target.value); setFerror(null) }} onKeyDown={(e) => { if (e.key === 'Enter') { e.preventDefault(); addFilter() } }} />
              </Field>
              <div className="sm:pt-[26px]"><Button type="button" disabled={locked} onClick={addFilter}>{t('network.span.filterAdd')}</Button></div>
            </div>
          </fieldset>

          <fieldset className="grid gap-3">
            <legend className="mb-1 text-sm font-medium">{t('network.span.limitsTitle')}</legend>
            <div className="grid gap-3 sm:grid-cols-2">
              <Field label={t('network.span.cpu')} htmlFor="span-cpu" hint={t('network.span.cpuHint')}><Input id="span-cpu" type="number" min={5} max={50} value={v.cpu_percent} disabled={locked} onChange={(e) => setV({ ...v, cpu_percent: Number(e.target.value) })} /></Field>
              <Field label={t('network.span.mem')} htmlFor="span-mem" hint={t('network.span.memHint')}><Input id="span-mem" type="number" min={128} max={2048} step={64} value={v.memory_mb} disabled={locked} onChange={(e) => setV({ ...v, memory_mb: Number(e.target.value) })} /></Field>
            </div>
          </fieldset>

          {error ? <p role="alert" className="rounded-md border border-danger/40 bg-danger-soft px-3 py-2 text-sm text-danger">{error}</p> : null}
          {readOnly ? null : <div className="flex flex-wrap items-center gap-3">
            <Button type="submit" variant="primary" disabled={gate.disabled || !dirty || span.isPending} title={gate.title}>{t('network.span.save')}</Button>
            {dirty ? <span className="text-[13px] text-muted">{t('network.span.unsaved')}</span> : null}
          </div>}
        </form>
      </div>
    </Section>
  )
}
