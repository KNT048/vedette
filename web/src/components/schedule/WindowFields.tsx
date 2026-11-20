import { useTranslation } from 'react-i18next'
import { Checkbox } from '@/components/ui/checkbox'
import { Input, Label } from '@/components/ui/input'
import { DAYS } from './rule'

export interface WindowValue { days: number[]; from: string; to: string }

/** The days and hours of a window, one set of fields wherever a window is chosen: a schedule's own window and the operating system's
 *  maintenance window. `idPrefix` makes the ids (`<prefix>-day-1`, `<prefix>-from`, `<prefix>-to`) unique on the page. */
export function WindowFields({ idPrefix, value, onChange, disabled }: { idPrefix: string; value: WindowValue; onChange: (v: WindowValue) => void; disabled?: boolean }) {
  const { t } = useTranslation('schedule')
  const toggle = (d: number, on: boolean) => onChange({ ...value, days: on ? [...value.days, d].sort() : value.days.filter((x) => x !== d) })
  return (
    <div className="grid gap-3">
      <div role="group" aria-label={t('window.days')} className="flex flex-wrap gap-x-4 gap-y-2">
        {DAYS.map((d) => (
          <span key={d} className="inline-flex items-center gap-2 text-sm">
            <Checkbox id={`${idPrefix}-day-${d}`} checked={value.days.includes(d)} disabled={disabled} onCheckedChange={(v) => toggle(d, v === true)} />
            <Label htmlFor={`${idPrefix}-day-${d}`} className="font-normal">{t(`days.long.${d}`)}</Label>
          </span>
        ))}
      </div>
      <div className="flex flex-wrap items-center gap-3 text-sm">
        <Label htmlFor={`${idPrefix}-from`} className="font-normal">{t('window.from')}</Label>
        <Input id={`${idPrefix}-from`} type="time" className="w-32" value={value.from} disabled={disabled} onChange={(e) => onChange({ ...value, from: e.target.value })} />
        <Label htmlFor={`${idPrefix}-to`} className="font-normal">{t('window.until')}</Label>
        <Input id={`${idPrefix}-to`} type="time" className="w-32" value={value.to} disabled={disabled} onChange={(e) => onChange({ ...value, to: e.target.value })} />
      </div>
    </div>
  )
}
