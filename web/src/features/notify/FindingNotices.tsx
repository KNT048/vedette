import { Link } from 'react-router'
import { useTranslation } from 'react-i18next'
import { Section } from '@/components/common/PageHeader'
import { useModuleEnabled } from '@/lib/modules'
import { useFindingNotices } from './api'
import { fmtClock } from './shared'

/** Slot `finding.panels` (S-ALERT-1, D-52): which channels were told about this finding, and whether it arrived. */
export default function FindingNotices({ findingId }: Record<string, unknown>) {
  const { t } = useTranslation('notify')
  const on = useModuleEnabled('notify')
  const q = useFindingNotices(String(findingId ?? ''))
  const sends = q.data?.sends ?? []
  if (!on || sends.length === 0) return null
  const list = sends.map((s) => (s.ok ? t('finding.entry', { channel: t(`ch.${s.channel}`), time: fmtClock(s.at) }) : t('finding.entryFailed', { channel: t(`ch.${s.channel}`), reason: s.error ?? t('history.failed') }))).join(', ')
  return (
    <Section id="notified" title={t('finding.title')} description={t('finding.description')} stories={['S-ALERT-1']}
      actions={<Link to="/settings/channels" className="text-[13px] text-accent underline-offset-4 hover:underline">{t('finding.history')}</Link>}>
      <p className="text-sm">{t('finding.notified', { list })}</p>
    </Section>
  )
}
