// "Accept risk until…" (D-498, S-MIT-1): a risk is accepted until a day, never for good; the finding reopens by itself after it.
import { useState } from 'react'
import { useTranslation } from 'react-i18next'
import { Chip, StatusChip } from '@/components/common/StatusChip'
import { Field, Input } from '@/components/ui/input'
import { Segmented } from '@/components/ui/segmented'
import { fmtDate } from '@/lib/format'
import { dayAfter, untilBounds } from './accept'
import type { FindingRow } from './types'
import { InfoTip } from '@/components/common/InfoTip'

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

/**
 * The status chip of a finding; "Risk accepted" is the findings module's own closed status (D-498). An open finding whose version the
 * device's own agent reports is "Detected by the agent" (D-548, like Tenable's and Qualys's agents and Defender Vulnerability Management),
 * not "Suspected"; "Confirmed" stays what a safe scan template saw.
 */
export function FindingStatusChip({ f }: { f: { status: FindingRow['status']; accepted_until?: string | null; evidence?: { agent?: boolean } | null; agent?: boolean } }) {
  const { t } = useTranslation('findings')
  // D-548: a finding carries it in its evidence, a report row (weekly, PDPL) as agent.
  // #824: the explanation is behind an ⓘ, not a hover-only title; the click stays off a clickable row; no ⓘ on paper (weekly, PDPL print).
  if (f.status === 'suspected' && (f.evidence?.agent || f.agent)) return <span className="inline-flex items-center gap-1" onClick={(e) => e.stopPropagation()}><Chip tone="warn">{t('agentChip')}</Chip><InfoTip topic={t('agentChip')} className="print:hidden">{t('agentChipHint')}</InfoTip></span>
  if (f.status !== 'risk_accepted') return <StatusChip status={f.status} />
  return <Chip tone="off" title={f.accepted_until ? t('accept.chipUntil', { date: fmtDate(f.accepted_until) }) : undefined}>{t('accept.chip')}</Chip>
}
