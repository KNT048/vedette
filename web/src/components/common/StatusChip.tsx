import { cn } from '@/lib/utils'

/**
 * The generic chip: four tones with a fixed meaning, always with words (docs/UI.md §7). A status, a severity, how a match is
 * verified and how a finding was handled are not chips of their own: they come from components/common/status.
 */
export type Tone = 'danger' | 'warn' | 'ok' | 'off' | 'accent'

const soft: Record<Tone, string> = {
  danger: 'border border-danger/40 bg-danger-soft text-danger',
  warn: 'border border-warn/50 bg-warn-soft text-warn',
  ok: 'border border-ok/40 bg-ok-soft text-ok',
  off: 'border border-rule bg-off-soft text-off',
  accent: 'border border-accent/40 bg-accent-soft text-accent',
}
// docs/UI.md §7: the shapes the types allow; the status badges draw their own.
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
