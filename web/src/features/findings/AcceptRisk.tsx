// "Accept risk until…" (S-MIT-1): a risk is accepted until a day, never for good; the finding reopens by itself after it.
import { useState } from 'react'
import { useTranslation } from 'react-i18next'
import { Field, Input } from '@/components/ui/input'
import { Segmented } from '@/components/ui/segmented'
import { fmtDate } from '@/lib/format'
import { dayAfter, untilBounds } from './accept'

const PRESETS = ['30', '90', '180'] as const

/** 30 / 90 / 180 days, or a day in the date field. */
export function AcceptUntil({ id, value, onChange, error }: { id: string; value: string; onChange: (v: string) => void; error?: string }) {
  const { t } = useTranslation('findings')
  const [today] = useState(() => new Date())
  const { min, max } = untilBounds(today)
  const preset = PRESETS.find((d) => dayAfter(today, Number(d)) === value) ?? ''
  return (
    <div className="grid gap-2">
      <Segmented<string> label={t('accept.presets')} value={preset} onChange={(v) => onChange(dayAfter(today, Number(v)))}
        options={PRESETS.map((d) => ({ value: d, label: t('accept.days', { count: Number(d) }) }))} />
      <Field htmlFor={id} label={t('accept.until')} hint={value ? t('accept.reopensAfter', { date: fmtDate(value) }) : t('accept.untilHint')} error={error}>
        <Input id={id} type="date" className="w-fit" min={min} max={max} value={value} onChange={(e) => onChange(e.target.value)}
          aria-invalid={!!error} aria-describedby={error ? `${id}-error` : `${id}-hint`} />
      </Field>
    </div>
  )
}
