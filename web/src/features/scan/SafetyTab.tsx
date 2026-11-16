import { useState } from 'react'
import { Link } from 'react-router'
import { useTranslation } from 'react-i18next'
import { toast } from 'sonner'
import { ShieldCheck } from 'lucide-react'
import { Notice, Section } from '@/components/common/PageHeader'
import { Card } from '@/components/common/Card'
import { EmptyState, QueryState } from '@/components/common/States'
import { Button } from '@/components/ui/button'
import { Checkbox } from '@/components/ui/checkbox'
import { Field, Input, Label, Select, Textarea } from '@/components/ui/input'
import { Switch } from '@/components/ui/switch'
import { fmtDate } from '@/lib/format'
import { useCan } from '@/lib/session'
import { useSaveConfig, useScanConfig, useTargets } from './api'
import { errMsg } from './errors'
import { DAY_ORDER } from './links'
import type { ScanConfigResponse, ScanTarget } from './types'

const RATES = [1, 2, 5, 10, 20]
const AFTER = [2, 3, 5, 10]

function Form({ data }: { data: ScanConfigResponse }) {
  const { t } = useTranslation('scan')
  const can = useCan('admin')
  const save = useSaveConfig()
  const c0 = data.config
  const [days, setDays] = useState<number[]>(c0.window.days)
  const [from, setFrom] = useState(c0.window.from)
  const [to, setTo] = useState(c0.window.to)
  const [rate, setRate] = useState(c0.rate)
  const [excl, setExcl] = useState(c0.exclusions.join('\n'))
  const [stopOn, setStopOn] = useState(c0.stop_on_unresponsive)
  const [after, setAfter] = useState(c0.unresponsive_after)
  const [error, setError] = useState<string | undefined>()
  const dis = !can

  function submit(e: React.FormEvent) {
    e.preventDefault()
    setError(undefined)
    save.mutate({
      window: { days, from, to }, rate, exclusions: excl.split('\n').map((l) => l.trim()).filter(Boolean),
      stop_on_unresponsive: stopOn, unresponsive_after: after,
    }, { onSuccess: () => toast.success(t('safety.saved')), onError: (err) => setError(errMsg(err)) })
  }

  return (
    <form onSubmit={submit} className="grid max-w-3xl gap-8" noValidate>
      {dis ? <Notice tone="off" className="mb-0" title={t('safety.adminOnly')} /> : null}
      <p className="max-w-3xl text-sm">{t('safety.appliesTo')}</p>

      <Section id="scope" title={t('safety.scopeTitle')} description={t('safety.scopeDescription')} info={t('safety.scopeInfo')} stories={['S-SCAN-1']}>
        <Card className="grid gap-1 text-sm">
          <p>{data.scope.networks.length ? t('start.scope', { networks: data.scope.networks.join(', ') }) : t('start.noNetworks')}</p>
          <p className={data.scope.commitment ? 'text-muted' : 'text-danger'}>
            {data.scope.commitment ? t('start.commitment', { date: fmtDate(data.scope.commitment.confirmed_at), by: data.scope.commitment.by }) : t('start.noCommitment')}
          </p>
          <Link to="/devices/setup" className="w-fit text-[13px] text-accent underline-offset-4 hover:underline">{t('safety.scopeChange')}</Link>
        </Card>
      </Section>

      <Section id="window" title={t('safety.windowTitle')} description={t('safety.windowDescription')} info={t('safety.windowDescriptionInfo')} stories={['S-SCAN-4']}>
        <div className="grid gap-4">
          <fieldset className="grid gap-2" disabled={dis}>
            <legend className="mb-1 text-sm font-medium">{t('safety.days')}</legend>
            <div className="flex flex-wrap gap-x-4 gap-y-2">
              {DAY_ORDER.map((d) => (
                <span key={d} className="inline-flex items-center gap-2 text-sm">
                  <Checkbox id={`day-${d}`} checked={days.includes(d)} onCheckedChange={(v) => setDays((l) => (v === true ? [...l, d] : l.filter((x) => x !== d)))} />
                  <label htmlFor={`day-${d}`}>{t(`days.${d}`)}</label>
                </span>
              ))}
            </div>
          </fieldset>
          <div className="grid gap-4 sm:grid-cols-3">
            <Field htmlFor="win-from" label={t('safety.from')}><Input id="win-from" type="time" value={from} onChange={(e) => setFrom(e.target.value)} disabled={dis} /></Field>
            <Field htmlFor="win-to" label={t('safety.to')}><Input id="win-to" type="time" value={to} onChange={(e) => setTo(e.target.value)} disabled={dis} /></Field>
            <Field htmlFor="rate" label={t('safety.rate')} hint={t('safety.rateHint')}>
              <Select id="rate" value={rate} onChange={(e) => setRate(Number(e.target.value))} disabled={dis}>
                {(RATES.includes(rate) ? RATES : [...RATES, rate].sort((a, b) => a - b)).map((r) => <option key={r} value={r}>{t('safety.rateOption', { count: r })}</option>)}
              </Select>
            </Field>
          </div>
        </div>
      </Section>

      <Section id="exclusions" title={t('safety.exclTitle')} description={t('safety.exclDescription')} stories={['S-SCAN-4']}>
        <Field htmlFor="excl" label={t('safety.exclLabel')} hint={t('safety.exclHint')} info={t('safety.exclHintInfo')}>
          <Textarea id="excl" value={excl} onChange={(e) => setExcl(e.target.value)} disabled={dis} spellCheck={false} rows={4} />
        </Field>
      </Section>

      <Section id="fragile" title={t('safety.fragileTitle')} description={t('safety.fragileDescription')} info={t('start.safeNote')} stories={['S-SCAN-1']}>
        <Fragile />
      </Section>

      <Section id="autostop" title={t('safety.stopTitle')} description={t('safety.stopDescription')} stories={['S-SCAN-4']}>
        <div className="grid gap-3">
          <div className="flex items-center gap-3">
            <Switch id="stop-on" checked={stopOn} onCheckedChange={setStopOn} disabled={dis} />
            <Label htmlFor="stop-on">{t('safety.stopSwitch')}</Label>
          </div>
          <Field htmlFor="after" label={t('safety.stopAfter')} className="max-w-xs">
            <Select id="after" value={after} onChange={(e) => setAfter(Number(e.target.value))} disabled={dis || !stopOn}>
              {(AFTER.includes(after) ? AFTER : [...AFTER, after].sort((a, b) => a - b)).map((n) => <option key={n} value={n}>{t('safety.stopAfterOption', { count: n })}</option>)}
            </Select>
          </Field>
        </div>
      </Section>

      <Section id="never" title={t('safety.neverTitle')} description={t('safety.neverDescription')}
        info={(['exploit', 'write', 'tags'] as const).map((k) => <p key={k}>{t(`safety.never.${k}Info`)}</p>)}>
        <Card className="grid gap-2">
          <p className="flex items-center gap-2 text-sm font-medium"><ShieldCheck className="size-4 text-ok" aria-hidden />{t('safety.neverHeadline')}</p>
          <ul className="grid list-disc gap-1 pl-9 text-sm">
            {(['exploit', 'dos', 'brute', 'write', 'tags'] as const).map((k) => <li key={k}>{t(`safety.never.${k}`)}</li>)}
          </ul>
          <p className="text-[13px] text-muted">{t('safety.neverLocked')}</p>
        </Card>
      </Section>


      {error ? <Notice tone="danger" role="alert" className="mb-0" title={error} /> : null}
      <div><Button type="submit" variant="primary" disabled={dis || save.isPending}>{t('safety.save')}</Button></div>
    </form>
  )
}

/** D-126: fragile and unclassified devices are scanned only when a person picks them, at a quarter of the speed. Set per device. */
function Fragile() {
  const { t } = useTranslation('scan')
  const q = useTargets()
  return (
    <QueryState query={q}>
      {(d) => {
        const list: ScanTarget[] = d.items.filter((x) => x.kind === 'internal' && x.fragile && !x.box)
        return (
          <div className="grid gap-2">
            {list.length ? (
              <ul aria-label={t('safety.fragileTitle')} className="divide-y divide-rule rounded-md border border-rule bg-surface">
                {list.map((x) => (
                  <li key={x.id} className="flex flex-wrap items-center gap-x-3 gap-y-1 px-3 py-2 text-sm">
                    <Link to={`/devices/${x.id}`} className="font-medium text-accent underline-offset-4 hover:underline">{x.label}</Link>
                    <span className="text-[13px] text-muted">{x.ip}</span>
                    <span className="text-[13px] text-muted">{x.device_kind === 'unknown' || !x.device_kind ? t('safety.fragileUnknown') : t('safety.fragileKind')}</span>
                  </li>
                ))}
              </ul>
            ) : <EmptyState title={t('safety.fragileNone')} />}
            <Link to="/devices/setup" className="w-fit text-[13px] text-accent underline-offset-4 hover:underline">{t('safety.fragileTypes')}</Link>
          </div>
        )
      }}
    </QueryState>
  )
}

export function SafetyTab() {
  const q = useScanConfig()
  return <QueryState query={q}>{(d) => <Form data={d} />}</QueryState>
}
