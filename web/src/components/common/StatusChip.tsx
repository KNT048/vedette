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

const soft: Record<Tone, string> = {
  danger: 'border border-danger/40 bg-danger-soft text-danger',
  warn: 'border border-warn/50 bg-warn-soft text-warn',
  ok: 'border border-ok/40 bg-ok-soft text-ok',
  off: 'border border-rule bg-off-soft text-off',
  accent: 'border border-accent/40 bg-accent-soft text-accent',
}
// docs/UI.md §7: solid only for danger (Confirmed, Critical), dashed only for warn (Suspected); the types allow nothing else.
const SOLID_DANGER = 'border border-danger bg-danger text-white dark:text-paper'
const DASHED_WARN = 'border border-dashed border-warn bg-warn-soft/60 text-warn'

type ChipBase = { children: React.ReactNode; className?: string; title?: string }
export type ChipProps = ChipBase & ({ tone: 'danger'; shape?: 'soft' | 'solid' } | { tone: 'warn'; shape?: 'soft' | 'dashed' } | { tone: 'ok' | 'off' | 'accent'; shape?: 'soft' })

export function Chip({ tone, shape = 'soft', children, className, title }: ChipProps) {
  const look = shape === 'solid' ? SOLID_DANGER : shape === 'dashed' ? DASHED_WARN : soft[tone]
  return (
    <span title={title} className={cn('inline-flex h-6 w-fit items-center gap-1.5 whitespace-nowrap rounded-sm px-2 text-caption font-medium leading-none', look, className)}>
      {shape === 'solid' ? <span aria-hidden className="size-1.5 bg-current" /> : null}
      {children}
    </span>
  )
}

const findingTone: Record<FindingStatus, Tone> = { confirmed: 'danger', suspected: 'warn', mitigated: 'ok', patched: 'ok', false_positive: 'off', not_relevant: 'off' }

export function StatusChip({ status }: { status: FindingStatus }) {
  const { t } = useTranslation()
  const text = t(`status.${status}`)
  if (status === 'confirmed') return <Chip tone="danger" shape="solid">{text}</Chip>
  if (status === 'suspected') return <Chip tone="warn" shape="dashed">{text}</Chip>
  return <Chip tone={findingTone[status]}>{text}</Chip>
}

const sevTone: Record<Severity, Tone> = { critical: 'danger', high: 'danger', medium: 'warn', low: 'off', info: 'off' }
export function SeverityChip({ severity }: { severity: Severity }) {
  const { t } = useTranslation()
  // Interim (docs/UI.md question 3, option a): Critical solid, the rest soft.
  if (severity === 'critical') return <Chip tone="danger" shape="solid">{t('severity.critical')}</Chip>
  return <Chip tone={sevTone[severity]}>{t(`severity.${severity}`)}</Chip>
}
