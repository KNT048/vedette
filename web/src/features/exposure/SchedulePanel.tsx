import { useTranslation } from 'react-i18next'
import { toast } from 'sonner'
import { InfoTip } from '@/components/common/InfoTip'
import { Label, Select } from '@/components/ui/input'
import { fmtDateTime } from '@/lib/format'
import { useCan } from '@/lib/session'
import { useSetSchedule } from './api'
import type { ScheduleEvery, Target } from './types'

const EVERY: ScheduleEvery[] = ['off', 'daily', 'weekly', 'monthly']

/** INV-36: how often the box scans this target by itself, next to the scan button: the choice (admin), when the next scheduled scan
 *  starts, or why it does not. */
export function SchedulePanel({ target }: { target: Target }) {
  const { t } = useTranslation('exposure')
  const admin = useCan('admin')
  const save = useSetSchedule(target.id)
  const s = target.schedule
  const locked = admin ? undefined : t('common:needRole', { role: t('common:role.admin') })
  const change = (every: ScheduleEvery) => save.mutate(every, {
    onSuccess: () => toast.success(t('schedule.saved', { value: target.value, every: t(`schedule.every.${every}`) })),
    onError: (e) => toast.error(e instanceof Error ? e.message : String(e)),
  })
  return (
    <div className="-mt-3 mb-6 grid max-w-3xl gap-1">
      <div className="flex flex-wrap items-center gap-x-3 gap-y-1">
        <span className="flex items-center gap-1"><Label htmlFor="scan-every">{t('schedule.label')}</Label><InfoTip topic={t('schedule.label')}>{t('schedule.info')}</InfoTip></span>
        <Select id="scan-every" className="w-36" value={s.every} disabled={!admin || save.isPending} title={locked} onChange={(e) => change(e.target.value as ScheduleEvery)}>
          {EVERY.map((e) => <option key={e} value={e}>{t(`schedule.every.${e}`)}</option>)}
        </Select>
        <span className="text-meta text-muted">{s.every === 'off' ? t('schedule.off') : s.next_at ? t('schedule.next', { time: fmtDateTime(s.next_at) }) : null}</span>
      </div>
      {s.note ? <p className="text-meta text-warn">{s.note}</p> : null}
    </div>
  )
}
