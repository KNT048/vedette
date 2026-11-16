import { useState } from 'react'
import { useTranslation } from 'react-i18next'
import { toast } from 'sonner'
import { Notice } from '@/components/common/PageHeader'
import { QueryState } from '@/components/common/States'
import { Button } from '@/components/ui/button'
import { Field, Input, Label, Select } from '@/components/ui/input'
import { Switch } from '@/components/ui/switch'
import { fmtDateTime } from '@/lib/format'
import { useCan } from '@/lib/session'
import { useSaveConfig, useScanConfig } from './api'
import { errMsg } from './errors'
import { DAY_ORDER } from './links'
import type { ScanConfig, ScanConfigResponse } from './types'

/** S-SCAN-2, S-SCAN-4: Nuclei's own settings on its engine card (#850): the regular scan and the rescan when a new KEV entry has a
 *  template. The time window, speed and exclusions it follows are the shared safety block. */
function Form({ data }: { data: ScanConfigResponse }) {
  const { t } = useTranslation('scan')
  const can = useCan('admin')
  const save = useSaveConfig()
  const [sch, setSch] = useState<ScanConfig['schedule']>(data.config.schedule)
  const [error, setError] = useState<string | undefined>()
  const dis = !can
  const w = data.config.window
  function submit(e: React.FormEvent) {
    e.preventDefault()
    setError(undefined)
    // weekday only means something for a weekly schedule (QA 2026-11-12: Daily still sent it)
    const schedule = sch.frequency === 'daily' ? { enabled: sch.enabled, frequency: sch.frequency, at: sch.at } : sch
    save.mutate({ schedule: schedule as ScanConfig['schedule'] }, { onSuccess: () => toast.success(t('safety.saved')), onError: (err) => setError(errMsg(err)) })
  }
  return (
    <div className="grid gap-5">
      <form onSubmit={submit} className="grid max-w-xl gap-4" noValidate aria-labelledby="nuclei-sched-title">
        <h3 id="nuclei-sched-title" className="text-sm font-semibold">{t('safety.schedTitle')}</h3>
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
            {/* only the days of the shared window can be picked (QA 2026-11-12: the server refused the others) */}
            <Select id="sch-day" value={sch.weekday} onChange={(e) => setSch((s) => ({ ...s, weekday: Number(e.target.value) }))} disabled={dis || !sch.enabled || sch.frequency !== 'weekly'}>
              {DAY_ORDER.map((d) => <option key={d} value={d} disabled={!w.days.includes(d)}>{t(`daysLong.${d}`)}</option>)}
            </Select>
          </Field>
          <Field htmlFor="sch-at" label={t('safety.at')} hint={t('nuclei.inWindow', { from: w.from, to: w.to })}>
            <Input id="sch-at" type="time" value={sch.at} onChange={(e) => setSch((s) => ({ ...s, at: e.target.value }))} disabled={dis || !sch.enabled} />
          </Field>
        </div>
        <p className="text-[13px] text-muted">{data.schedule_blocked_reason ? data.schedule_blocked_reason : !data.can_scan && sch.enabled ? t(data.scope.commitment ? 'safety.nextScannerDown' : 'safety.nextBlocked') : data.next_run ? t('safety.next', { time: fmtDateTime(data.next_run) }) : t('safety.nextNone')}</p>
        {error ? <Notice tone="danger" role="alert" className="mb-0" title={error} /> : null}
        <div><Button type="submit" disabled={dis || save.isPending}>{t('nuclei.saveSchedule')}</Button></div>
      </form>
      <AutoStop data={data} disabled={dis} />
      <div className="grid gap-2">
        <div className="flex flex-wrap items-center gap-3">
          <Switch id="auto-on" checked={data.config.auto_rescan} disabled={dis || save.isPending}
            onCheckedChange={(v) => save.mutate({ auto_rescan: v }, { onSuccess: () => toast.success(v ? t('auto.onToast') : t('auto.offToast')), onError: (e) => toast.error(errMsg(e)) })} />
          <Label htmlFor="auto-on">{t('auto.switch')}</Label>
        </div>
        {!data.config.auto_rescan ? <Notice tone="warn" className="mb-0 max-w-xl" title={t('auto.offNote')} info={t('auto.offNoteInfo')} /> : null}
      </div>
      {dis ? <p className="text-[13px] text-muted">{t('common:needRole', { role: t('common:role.admin') })}</p> : null}
    </div>
  )
}

const AFTER = [2, 3, 5, 10]

/** S-SCAN-4: auto-stop is the vulnerability checks' own (scan config), so it sits on their card (D-627 keeps it out of the shared block). */
function AutoStop({ data, disabled }: { data: ScanConfigResponse; disabled: boolean }) {
  const { t } = useTranslation('scan')
  const save = useSaveConfig()
  const c = data.config
  const put = (v: Partial<ScanConfig>) => save.mutate(v, { onSuccess: () => toast.success(t('safety.saved')), onError: (e) => toast.error(errMsg(e)) })
  return (
    <div className="grid max-w-xl gap-3" role="group" aria-labelledby="autostop-title">
      <h3 id="autostop-title" className="text-sm font-semibold">{t('safety.stopTitle')}</h3>
      <div className="flex items-center gap-3">
        <Switch id="stop-on" checked={c.stop_on_unresponsive} onCheckedChange={(v) => put({ stop_on_unresponsive: v })} disabled={disabled || save.isPending} />
        <Label htmlFor="stop-on">{t('safety.stopSwitch')}</Label>
      </div>
      <Field htmlFor="after" label={t('safety.stopAfter')} className="max-w-xs">
        <Select id="after" value={c.unresponsive_after} onChange={(e) => put({ unresponsive_after: Number(e.target.value) })} disabled={disabled || !c.stop_on_unresponsive || save.isPending}>
          {(AFTER.includes(c.unresponsive_after) ? AFTER : [...AFTER, c.unresponsive_after].sort((a, b) => a - b)).map((n) => <option key={n} value={n}>{t('safety.stopAfterOption', { count: n })}</option>)}
        </Select>
      </Field>
    </div>
  )
}

export function NucleiSettings() {
  const q = useScanConfig()
  return <QueryState query={q}>{(d) => <Form data={d} />}</QueryState>
}
