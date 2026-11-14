import { useState } from 'react'
import { useTranslation } from 'react-i18next'
import { toast } from 'sonner'
import { ShieldCheck } from 'lucide-react'
import { Notice, Section, Panel } from '@/components/common/PageHeader'
import { QueryState } from '@/components/common/States'
import { Button } from '@/components/ui/button'
import { Checkbox } from '@/components/ui/checkbox'
import { Field, Input, Label, Select, Textarea } from '@/components/ui/input'
import { Switch } from '@/components/ui/switch'
import { fmtDateTime } from '@/lib/format'
import { useCan } from '@/lib/session'
import { useSaveConfig, useScanConfig } from './api'
import { errMsg } from './errors'
import type { ScanConfig, ScanConfigResponse } from './types'

const DAY_ORDER = [1, 2, 3, 4, 5, 6, 7]
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
  const [sch, setSch] = useState<ScanConfig['schedule']>(c0.schedule)
  const [error, setError] = useState<string | undefined>()
  const dis = !can

  function submit(e: React.FormEvent) {
    e.preventDefault()
    setError(undefined)
    save.mutate({
      window: { days, from, to }, rate, exclusions: excl.split('\n').map((l) => l.trim()).filter(Boolean),
      stop_on_unresponsive: stopOn, unresponsive_after: after, schedule: sch,
    }, { onSuccess: () => toast.success(t('safety.saved')), onError: (err) => setError(errMsg(err)) })
  }

  return (
    <form onSubmit={submit} className="grid max-w-3xl gap-8" noValidate>
      {dis ? <Notice tone="off" className="mb-0" title={t('safety.adminOnly')} /> : null}

      <Section id="window" title={t('safety.windowTitle')} description={t('safety.windowDescription')} stories={['S-SCAN-4']}>
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
        <Field htmlFor="excl" label={t('safety.exclLabel')} hint={t('safety.exclHint')}>
          <Textarea id="excl" value={excl} onChange={(e) => setExcl(e.target.value)} disabled={dis} spellCheck={false} rows={4} />
        </Field>
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

      <Section id="never" title={t('safety.neverTitle')} description={t('safety.neverDescription')}>
        <Panel className="grid gap-2 p-4">
          <p className="flex items-center gap-2 text-sm font-medium"><ShieldCheck className="size-4 text-ok" aria-hidden />{t('safety.neverHeadline')}</p>
          <ul className="grid list-disc gap-1 pl-9 text-sm">
            {(['exploit', 'dos', 'brute', 'write', 'tags'] as const).map((k) => <li key={k}>{t(`safety.never.${k}`)}</li>)}
          </ul>
          <p className="text-[13px] text-muted">{t('safety.neverLocked')}</p>
        </Panel>
      </Section>

      <Section id="schedule" title={t('safety.schedTitle')} description={t('safety.schedDescription')} stories={['S-SCAN-4']}>
        <div className="grid gap-4">
          <div className="flex items-center gap-3">
            <Switch id="sch-on" checked={sch.enabled} onCheckedChange={(v) => setSch((s) => ({ ...s, enabled: v }))} disabled={dis} />
            <Label htmlFor="sch-on">{t('safety.schedSwitch')}</Label>
          </div>
          <div className="grid gap-4 sm:grid-cols-3">
            <Field htmlFor="sch-freq" label={t('safety.freq')}>
              <Select id="sch-freq" value={sch.frequency} onChange={(e) => setSch((s) => ({ ...s, frequency: e.target.value as 'daily' | 'weekly' }))} disabled={dis || !sch.enabled}>
                <option value="daily">{t('safety.daily')}</option>
                <option value="weekly">{t('safety.weekly')}</option>
              </Select>
            </Field>
            <Field htmlFor="sch-day" label={t('safety.weekday')}>
              <Select id="sch-day" value={sch.weekday} onChange={(e) => setSch((s) => ({ ...s, weekday: Number(e.target.value) }))} disabled={dis || !sch.enabled || sch.frequency !== 'weekly'}>
                {DAY_ORDER.map((d) => <option key={d} value={d}>{t(`daysLong.${d}`)}</option>)}
              </Select>
            </Field>
            <Field htmlFor="sch-at" label={t('safety.at')}><Input id="sch-at" type="time" value={sch.at} onChange={(e) => setSch((s) => ({ ...s, at: e.target.value }))} disabled={dis || !sch.enabled} /></Field>
          </div>
          <p className="text-[13px] text-muted">{data.schedule_blocked_reason ? data.schedule_blocked_reason : !data.can_scan && sch.enabled ? t(data.scope.commitment ? 'safety.nextScannerDown' : 'safety.nextBlocked') : data.next_run ? t('safety.next', { time: fmtDateTime(data.next_run) }) : t('safety.nextNone')}</p>
        </div>
      </Section>

      {error ? <Notice tone="danger" role="alert" className="mb-0" title={error} /> : null}
      <div><Button type="submit" variant="primary" disabled={dis || save.isPending}>{t('safety.save')}</Button></div>
    </form>
  )
}

export function SafetyTab() {
  const q = useScanConfig()
  return <QueryState query={q}>{(d) => <Form data={d} />}</QueryState>
}
