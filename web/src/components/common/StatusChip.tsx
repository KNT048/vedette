import { useTranslation } from 'react-i18next'
import { cn } from '@/lib/utils'
import type { FindingStatus, Severity } from '@/lib/types'

export type { FindingStatus, Severity }

/**
 * Bốn màu trạng thái có nghĩa cố định, luôn kèm chữ (FRONTEND §3), and a shape with one meaning each (docs/UI.md §7):
 * `soft` (the default for every tone), `solid` only for Confirmed and counters, `dashed` only for Suspected; severities carry a
 * level meter (SeverityMeter). "Xác nhận" và "nghi" khác HÌNH, không chỉ khác màu.
 */
export type Tone = 'danger' | 'warn' | 'ok' | 'off' | 'accent'

const soft: Record<Tone, string> = {
  danger: 'border border-danger/40 bg-danger-soft text-danger',
  warn: 'border border-warn/50 bg-warn-soft text-warn',
  ok: 'border border-ok/40 bg-ok-soft text-ok',
  off: 'border border-rule bg-off-soft text-off',
  accent: 'border border-accent/40 bg-accent-soft text-accent',
}
// docs/UI.md §7: solid only for danger (Confirmed), dashed only for warn (Suspected); the types allow nothing else.
const SOLID_DANGER = 'border border-danger bg-danger text-paper'
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
const sevLevel: Record<Severity, number> = { critical: 4, high: 3, medium: 2, low: 1, info: 0 }

/** The level as a small meter of four bars (docs/UI.md §7, decision (c), as Tenable gives each severity its own icon): filled bars
 *  in the chip's colour, the rest faint. Critical and High share a colour but not a meter; solid stays for "Confirmed" only.
 *  Decorative: the word carries the meaning. */
export function SeverityMeter({ level, className }: { level: number; className?: string }) {
  return (
    <svg aria-hidden viewBox="0 0 14 10" className={cn('h-2.5 w-3.5 shrink-0', className)} data-level={level}>
      {[0, 1, 2, 3].map((i) => <rect key={i} x={i * 3.5} y={7 - i * 2} width="2.5" height={3 + i * 2} rx="0.5" fill="currentColor" opacity={i < level ? 1 : 0.25} />)}
    </svg>
  )
}

export function SeverityChip({ severity }: { severity: Severity }) {
  const { t } = useTranslation()
  return <Chip tone={sevTone[severity]}><SeverityMeter level={sevLevel[severity]} />{t(`severity.${severity}`)}</Chip>
}
