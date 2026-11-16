import { useTranslation } from 'react-i18next'
import { cn } from '@/lib/utils'
import type { FindingStatus, Severity } from '@/lib/types'

export type { FindingStatus, Severity }

/**
 * Bốn màu trạng thái có nghĩa cố định, luôn kèm chữ (FRONTEND §3), and a shape with one meaning each (docs/UI.md §7):
 * `soft` (the default for every tone), `solid` only for Confirmed, Critical (interim, UI.md question 3) and counters, `dashed` only for
 * Suspected. "Xác nhận" và "nghi" khác HÌNH, không chỉ khác màu.
 */
export type Tone = 'danger' | 'warn' | 'ok' | 'off' | 'accent'
export type Shape = 'soft' | 'solid' | 'dashed'

const soft: Record<Tone, string> = {
  danger: 'border border-danger/40 bg-danger-soft text-danger',
  warn: 'border border-warn/50 bg-warn-soft text-warn',
  ok: 'border border-ok/40 bg-ok-soft text-ok',
  off: 'border border-rule bg-off-soft text-off',
  accent: 'border border-accent/40 bg-accent-soft text-accent',
}
const solid: Record<Tone, string> = {
  danger: 'border border-danger bg-danger text-white dark:text-paper',
  warn: 'border border-warn bg-warn text-white dark:text-paper',
  ok: 'border border-ok bg-ok text-white dark:text-paper',
  off: 'border border-off bg-off text-white dark:text-paper',
  accent: 'border border-accent bg-accent text-accent-ink',
}
const dashed: Record<Tone, string> = {
  danger: 'border border-dashed border-danger bg-danger-soft/60 text-danger',
  warn: 'border border-dashed border-warn bg-warn-soft/60 text-warn',
  ok: 'border border-dashed border-ok bg-ok-soft/60 text-ok',
  off: 'border border-dashed border-off bg-off-soft/60 text-off',
  accent: 'border border-dashed border-accent bg-accent-soft/60 text-accent',
}
const SHAPES: Record<Shape, Record<Tone, string>> = { soft, solid, dashed }

export function Chip({ tone, shape = 'soft', children, className, title }: { tone: Tone; shape?: Shape; children: React.ReactNode; className?: string; title?: string }) {
  return (
    <span title={title} className={cn('inline-flex h-6 w-fit items-center gap-1.5 whitespace-nowrap rounded-sm px-2 text-caption font-medium leading-none', SHAPES[shape][tone], className)}>
      {shape === 'solid' ? <span aria-hidden className="size-1.5 bg-current" /> : null}
      {children}
    </span>
  )
}

const findingTone: Record<FindingStatus, Tone> = { confirmed: 'danger', suspected: 'warn', mitigated: 'ok', patched: 'ok', false_positive: 'off', not_relevant: 'off' }

export function StatusChip({ status }: { status: FindingStatus }) {
  const { t } = useTranslation()
  return <Chip tone={findingTone[status]} shape={status === 'confirmed' ? 'solid' : status === 'suspected' ? 'dashed' : 'soft'}>{t(`status.${status}`)}</Chip>
}

const sevTone: Record<Severity, Tone> = { critical: 'danger', high: 'danger', medium: 'warn', low: 'off', info: 'off' }
export function SeverityChip({ severity }: { severity: Severity }) {
  const { t } = useTranslation()
  // Interim (docs/UI.md question 3, option a): Critical solid, the rest soft.
  return <Chip tone={sevTone[severity]} shape={severity === 'critical' ? 'solid' : 'soft'}>{t(`severity.${severity}`)}</Chip>
}
