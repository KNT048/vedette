import { Link } from 'react-router'
import { useTranslation } from 'react-i18next'
import { Section } from '@/components/common/PageHeader'
import { useModuleEnabled } from '@/lib/modules'
import { useCan } from '@/lib/session'
import { useFindingNotices } from './api'
import { fmtTime } from '@/lib/format'

/** Slot `finding.panels` (S-ALERT-1): which channels were told about this finding, and whether it arrived. */
export default function FindingNotices({ findingId }: Record<string, unknown>) {
  const { t } = useTranslation('notify')
  const admin = useCan('admin')
  const on = useModuleEnabled('notify')
  const q = useFindingNotices(String(findingId ?? ''))
  const sends = q.data?.sends ?? []
  if (!on || sends.length === 0) return null
  // "Notified" only for a message that arrived and named this finding; a failed attempt is said apart, never as notified.
  const ok = sends.filter((s) => s.ok).map((s) => t('finding.entry', { channel: t(`ch.${s.channel}`), time: fmtTime(s.at) })).join(', ')
  const failed = sends.filter((s) => !s.ok).map((s) => t('finding.entryFailed', { channel: t(`ch.${s.channel}`), reason: s.error ?? t('history.failed') })).join(', ')
  return (
    <Section id="notified" title={t('finding.title')} description={t('finding.description')} stories={['S-ALERT-1']}
      // Settings › Alert channels is an administrator's page; no link others cannot open
      actions={admin ? <Link to="/settings/channels/history" className="text-meta text-accent underline-offset-4 hover:underline">{t('finding.history')}</Link> : null}>
      {ok ? <p className="text-sm">{t('finding.notified', { list: ok })}</p> : null}
      {failed ? <p className="text-sm">{t('finding.notDelivered', { list: failed })}</p> : null}
    </Section>
  )
}
