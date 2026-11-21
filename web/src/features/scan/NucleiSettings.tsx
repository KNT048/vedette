import { useTranslation } from 'react-i18next'
import { toast } from 'sonner'
import { Notice } from '@/components/common/PageHeader'
import { QueryState } from '@/components/common/States'
import { Field, Label, Select } from '@/components/ui/input'
import { Switch } from '@/components/ui/switch'
import { ScheduleEditor } from '@/components/schedule/ScheduleEditor'
import { useSchedule } from '@/components/schedule/api'
import { useCan } from '@/lib/session'
import { useSaveConfig, useScanConfig } from './api'
import { errMsg } from './errors'
import type { ScanConfig, ScanConfigResponse } from './types'

/** S-SCAN-2, S-SCAN-4: Nuclei's own settings on its engine card (#850): the regular scan (the shared schedule editor) and the
 *  rescan when a new KEV entry has a template. The time window, speed and exclusions it follows are the shared safety block. */
function Form({ data }: { data: ScanConfigResponse }) {
  const { t } = useTranslation('scan')
  const can = useCan('admin')
  const save = useSaveConfig()
  const sched = useSchedule('scan.vuln')
  const dis = !can
  // what holds every start while the schedule is on, said before a due time is skipped
  const blocked = !sched.data?.enabled ? null : data.can_scan ? null : t(data.scope.commitment ? 'safety.nextScannerDown' : 'safety.nextBlocked')
  return (
    <div className="grid gap-5">
      {/* the card already has its own button to run the checks now, with their progress */}
      <div className="grid max-w-xl gap-2" role="group" aria-labelledby="nuclei-sched-title">
        <h3 id="nuclei-sched-title" className="text-sm font-semibold">{t('safety.schedTitle')}</h3>
        <ScheduleEditor ownerKey="scan.vuln" name={t('nuclei.scheduleName')} runNow={false} />
        {blocked ? <p className="text-meta text-warn">{blocked}</p> : null}
      </div>
      <AutoStop data={data} disabled={dis} />
      <div className="grid gap-2">
        <div className="flex flex-wrap items-center gap-3">
          <Switch id="auto-on" checked={data.config.auto_rescan} disabled={dis || save.isPending}
            onCheckedChange={(v) => save.mutate({ auto_rescan: v }, { onSuccess: () => toast.success(v ? t('auto.onToast') : t('auto.offToast')), onError: (e) => toast.error(errMsg(e)) })} />
          <Label htmlFor="auto-on">{t('auto.switch')}</Label>
        </div>
        {!data.config.auto_rescan ? <Notice tone="warn" className="mb-0 max-w-xl" title={t('auto.offNote')} info={t('auto.offNoteInfo')} /> : null}
      </div>
      {dis ? <p className="text-meta text-muted">{t('common:needRole', { role: t('common:role.admin') })}</p> : null}
    </div>
  )
}

const AFTER = [2, 3, 5, 10]

/** S-SCAN-4: auto-stop is the vulnerability checks' own (scan config), so it sits on their card (it is kept out of the shared block). */
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
