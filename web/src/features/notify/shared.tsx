import { Link } from 'react-router'
import { useTranslation } from 'react-i18next'
import { Chip } from '@/components/common/StatusChip'
import type { Incident, IncidentStatus, NotSent, NotSentReason, Preview, SendRecord } from './types'

const TONE = { new: 'warn', acknowledged: 'accent', resolved: 'ok' } as const

export function IncidentStatusChip({ status }: { status: IncidentStatus }) {
  const { t } = useTranslation('notify')
  return <Chip tone={TONE[status]}>{t(`incidents.status.${status}`)}</Chip>
}

/** The locale key of an incident's kind: a blocked connection to a known-bad address is an attempt (D-227). */
export const kindKey = (i: Pick<Incident, 'kind' | 'attempt'>) => `incidents.kind.${i.attempt ? 'bad_address_attempt' : i.kind}` as const

export const fmtClock = (iso: string) => new Intl.DateTimeFormat('en-GB', { hour: '2-digit', minute: '2-digit' }).format(new Date(iso))

/** Lý do có chỗ sửa (D-551): liên kết tới Settings, Alert channels; chỉ admin mở được trang đó. */
const FIXABLE: NotSentReason[] = ['no_channel', 'channels_off', 'channel_off', 'channel_removed', 'below_min_severity', 'quiet_hours', 'failed']

/** The fix link of a not-sent reason, for an admin; nothing for the others or a reason with nothing to fix. */
export function NotSentFix({ notSent, admin }: { notSent: NotSent | null; admin: boolean }) {
  const { t } = useTranslation('notify')
  if (!admin || !notSent || !FIXABLE.includes(notSent.reason)) return null
  return <Link to="/settings/channels" onClick={(e) => e.stopPropagation()} className="text-[13px] text-accent underline-offset-4 hover:underline">{t(`incidents.fix.${notSent.reason}`)}</Link>
}

/**
 * Last result per channel: "Slack 09:12", or "Email failed" with the reason on hover. With no message on any channel, the box's sentence
 * of why (INV-24, D-551) and, for an admin, the link to fix it.
 */
export function DeliveryBadges({ sends, notSent = null, admin = false }: { sends: SendRecord[]; notSent?: NotSent | null; admin?: boolean }) {
  const { t } = useTranslation('notify')
  const last = new Map<string, SendRecord>()
  for (const s of [...sends].sort((a, b) => a.at.localeCompare(b.at))) last.set(s.channel, s)
  if (last.size === 0) {
    return notSent
      ? <span className="grid max-w-[36ch] gap-0.5 text-[13px]"><span className={notSent.reason === 'queued' || notSent.reason === 'quiet_hours' ? 'text-muted' : undefined}>{notSent.text}</span><NotSentFix notSent={notSent} admin={admin} /></span>
      : <span className="text-muted">{t('incidents.notSent')}</span>
  }
  return (
    <span className="flex flex-wrap items-center gap-1">
      {[...last.values()].map((s) => (s.ok
        ? <Chip key={s.channel} tone="off">{t('incidents.sentAt', { channel: t(`ch.${s.channel}`), time: fmtClock(s.at) })}</Chip>
        : s.delayed ? <Chip key={s.channel} tone="accent" title={s.error}>{t('incidents.sentDelayed', { channel: t(`ch.${s.channel}`) })}</Chip>
        : <Chip key={s.channel} tone="warn" title={s.error}>{t('incidents.sentFailed', { channel: t(`ch.${s.channel}`) })}</Chip>))}
      <NotSentFix notSent={notSent} admin={admin} />
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
