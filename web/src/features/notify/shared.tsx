import { Link } from 'react-router'
import { useTranslation } from 'react-i18next'
import { Chip } from '@/components/common/StatusChip'
import { knownKind, type Incident, type IncidentStatus, type NotSent, type NotSentReason, type Preview, type SendRecord } from './types'
import { fmtTime } from '@/lib/format'

const TONE = { new: 'warn', acknowledged: 'accent', resolved: 'ok' } as const

export function IncidentStatusChip({ status }: { status: IncidentStatus }) {
  const { t } = useTranslation('notify')
  return <Chip tone={TONE[status]}>{t(`incidents.status.${status}`)}</Chip>
}

/** The locale key of an incident's kind: a blocked connection to a known-bad address is an attempt. */
export const kindKey = (i: Pick<Incident, 'kind' | 'attempt'>) => `incidents.kind.${i.attempt ? 'bad_address_attempt' : knownKind(i.kind)}` as const


/** The reason there is somewhere to edit: a link to Settings, Alert channels; only an admin can open that page. */
const FIXABLE: NotSentReason[] = ['no_channel', 'channels_off', 'channel_off', 'channel_removed', 'below_min_severity', 'quiet_hours', 'grouped', 'failed', 'trigger_off']

/** A reason that still goes out by itself: queued, held for quiet hours, waiting for its grouping window. */
export const waitingReason = (n: NotSent | null) => !!n && (n.reason === 'queued' || n.reason === 'quiet_hours' || n.reason === 'grouped')

/** Open incidents no channel has and that will not go out by themselves (queued / quiet hours do): the KPI "not sent" and `?sent=no`. */
export const needsFix = (n: NotSent | null) => !!n && ['no_channel', 'channels_off', 'channel_off', 'channel_removed', 'below_min_severity', 'failed'].includes(n.reason)

/** Need → place (docs/UI.md §0): the exact spot of Settings › Alert channels that fixes a reason: the channel named (its Set up or
 *  Edit button), the quiet hours, grouping or alert triggers (on its Settings tab), else the list of channels. The ids are in ChannelsSettings. */
export function fixAt(n: NotSent): string {
  if (n.reason === 'quiet_hours') return '/settings/channels?tab=settings#quiet-hours'
  if (n.reason === 'grouped') return '/settings/channels?tab=settings#grouping'
  if (n.reason === 'trigger_off') return '/settings/channels?tab=settings#triggers'
  if (n.channel && ['channel_off', 'channel_removed', 'below_min_severity', 'failed'].includes(n.reason)) return `/settings/channels#channel-${n.channel}`
  return '/settings/channels#channels'
}

/** The fix link of a not-sent reason, for an admin; nothing for the others or a reason with nothing to fix. */
export function NotSentFix({ notSent, admin }: { notSent: NotSent | null; admin: boolean }) {
  const { t } = useTranslation('notify')
  if (!admin || !notSent || !FIXABLE.includes(notSent.reason)) return null
  return <Link to={fixAt(notSent)} onClick={(e) => e.stopPropagation()} className="text-meta text-accent underline-offset-4 hover:underline">{t(`incidents.fix.${notSent.reason}`)}</Link>
}

/**
 * Last result per channel: "Slack 09:12", or "Email failed" with the reason on hover. With no message on any channel, the box's sentence
 * of why (INV-24) and, for an admin, the link to fix it. `noChannelShown`: the page carries the one "no channel" notice, so those rows say only "Not sent".
 */
export function DeliveryBadges({ sends, notSent = null, admin = false, noChannelShown = false }: { sends: SendRecord[]; notSent?: NotSent | null; admin?: boolean; noChannelShown?: boolean }) {
  const { t } = useTranslation('notify')
  const last = new Map<string, SendRecord>()
  for (const s of [...sends].sort((a, b) => a.at.localeCompare(b.at))) last.set(s.channel, s)
  if (last.size === 0) {
    // the page already said once that no channel is set up: the row does not repeat it
    if (noChannelShown && notSent?.reason === 'no_channel') return <span className="text-muted">{t('incidents.notSent')}</span>
    return notSent
      ? <span className="grid max-w-[36ch] gap-0.5 text-meta"><span className={notSent.reason === 'queued' || notSent.reason === 'quiet_hours' ? 'text-muted' : undefined}>{notSent.text}</span><NotSentFix notSent={notSent} admin={admin} /></span>
      : <span className="text-muted">{t('incidents.notSent')}</span>
  }
  return (
    <span className="flex flex-wrap items-center gap-1">
      {[...last.values()].map((s) => (s.ok
        ? <Chip key={s.channel} tone="off">{t('incidents.sentAt', { channel: t(`ch.${s.channel}`), time: fmtTime(s.at) })}</Chip>
        : s.delayed ? <Chip key={s.channel} tone="accent" title={s.error}>{t('incidents.sentDelayed', { channel: t(`ch.${s.channel}`) })}</Chip>
        : <Chip key={s.channel} tone="warn" title={s.error}>{t('incidents.sentFailed', { channel: t(`ch.${s.channel}`) })}</Chip>))}
      <NotSentFix notSent={notSent} admin={admin} />
    </span>
  )
}

/** A preview of exactly the content sent: plain text in a frame, it does not imitate another vendor's UI (legal rule). */
export function MessagePreview({ preview, label }: { preview: Pick<Preview, 'text' | 'subject'>; label: string }) {
  const { t } = useTranslation('notify')
  return (
    <figure className="max-w-xl rounded-md border border-rule bg-sunken p-4" aria-label={label}>
      {preview.subject ? <p className="mb-2 text-sm font-medium">{t('detail.subject', { subject: preview.subject })}</p> : null}
      <pre className="whitespace-pre-wrap break-words font-sans text-sm leading-relaxed">{preview.text}</pre>
    </figure>
  )
}
