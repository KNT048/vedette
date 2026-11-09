import { useTranslation } from 'react-i18next'
import { cn } from '@/lib/utils'
import type { FindingStatus, Severity } from '@/lib/types'

export type { FindingStatus, Severity }

/**
 * Bốn màu trạng thái có nghĩa cố định, luôn kèm chữ (FRONTEND §3):
 * danger = xác nhận/khẩn (khối đặc), warn = nghi/cần xem (viền đứt), ok = ổn/đã xử lý, off = tắt/không biết.
 * "Xác nhận" và "nghi" khác HÌNH, không chỉ khác màu.
 */
export type Tone = 'danger' | 'warn' | 'ok' | 'off' | 'accent'

const tones: Record<Tone, string> = {
  danger: 'bg-danger text-white dark:text-paper border border-danger',
  warn: 'border border-dashed border-warn text-warn bg-warn-soft/60',
  ok: 'border border-ok/40 bg-ok-soft text-ok',
  off: 'border border-rule bg-off-soft text-off',
  accent: 'border border-accent/40 bg-accent-soft text-accent',
}

export function Chip({ tone, children, className, title }: { tone: Tone; children: React.ReactNode; className?: string; title?: string }) {
  return (
    <span title={title} className={cn('inline-flex h-6 w-fit items-center gap-1.5 whitespace-nowrap rounded-[4px] px-2 text-[12px] font-medium leading-none', tones[tone], className)}>
      {tone === 'danger' ? <span aria-hidden className="size-1.5 bg-current" /> : null}
      {children}
    </span>
  )
}

const findingTone: Record<FindingStatus, Tone> = { confirmed: 'danger', suspected: 'warn', mitigated: 'ok', patched: 'ok', false_positive: 'off', not_relevant: 'off' }

export function StatusChip({ status }: { status: FindingStatus }) {
  const { t } = useTranslation()
  return <Chip tone={findingTone[status]}>{t(`status.${status}`)}</Chip>
}

const sevTone: Record<Severity, Tone> = { critical: 'danger', high: 'danger', medium: 'warn', low: 'off', info: 'off' }
export function SeverityChip({ severity }: { severity: Severity }) {
  const { t } = useTranslation()
  return <Chip tone={sevTone[severity]}>{t(`severity.${severity}`)}</Chip>
}
