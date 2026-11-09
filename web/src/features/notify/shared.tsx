import { useTranslation } from 'react-i18next'
import { Chip } from '@/components/common/StatusChip'
import type { IncidentStatus, Preview, SendRecord } from './types'

const TONE = { new: 'warn', acknowledged: 'accent', resolved: 'ok' } as const

export function IncidentStatusChip({ status }: { status: IncidentStatus }) {
  const { t } = useTranslation('notify')
  return <Chip tone={TONE[status]}>{t(`incidents.status.${status}`)}</Chip>
}

export const fmtClock = (iso: string) => new Intl.DateTimeFormat('en-GB', { hour: '2-digit', minute: '2-digit' }).format(new Date(iso))

/** Last result per channel: "Slack 09:12", or "Email failed" with the reason on hover. `variant="finding"` lists the failure reason inline. */
export function DeliveryBadges({ sends }: { sends: SendRecord[] }) {
  const { t } = useTranslation('notify')
  const last = new Map<string, SendRecord>()
  for (const s of [...sends].sort((a, b) => a.at.localeCompare(b.at))) last.set(s.channel, s)
  if (last.size === 0) return <span className="text-muted">{t('incidents.notSent')}</span>
  return (
    <span className="flex flex-wrap gap-1">
      {[...last.values()].map((s) => (s.ok
        ? <Chip key={s.channel} tone="off">{t('incidents.sentAt', { channel: t(`ch.${s.channel}`), time: fmtClock(s.at) })}</Chip>
        : <Chip key={s.channel} tone="warn" title={s.error}>{t('incidents.sentFailed', { channel: t(`ch.${s.channel}`) })}</Chip>))}
    </span>
  )
}

/** Xem trước đúng nội dung đã gửi: chữ thường trong khung, không mô phỏng giao diện của hãng khác (rule legal.md). */
export function MessagePreview({ preview, label }: { preview: Pick<Preview, 'text' | 'subject'>; label: string }) {
  const { t } = useTranslation('notify')
  return (
    <figure className="max-w-xl rounded-md border border-rule bg-sunken p-4" aria-label={label}>
      {preview.subject ? <p className="mb-2 text-sm font-medium">{t('detail.subject', { subject: preview.subject })}</p> : null}
      <pre className="whitespace-pre-wrap break-words font-sans text-sm leading-relaxed">{preview.text}</pre>
    </figure>
  )
}
