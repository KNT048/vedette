import { Link } from 'react-router'
import { useTranslation } from 'react-i18next'
import { Section } from '@/components/common/PageHeader'
import { useModuleEnabled } from '@/lib/modules'
import { usePlans } from './api'
import { PlanView } from './parts'

/** Slot `finding.panels` (S-RESP-1): the AI response plan for this finding, when it is an open critical one. */
export default function FindingPanel({ findingId }: Record<string, unknown>) {
  const { t } = useTranslation('response')
  const on = useModuleEnabled('response')
  const id = String(findingId ?? '')
  const q = usePlans(id)
  const plan = q.data?.items[0]
  if (!on || !plan) return null
  return (
    <Section id="response" title={t('panel.title')} description={t('panel.description')} stories={['S-RESP-1']}
      actions={<Link to="/response" className="text-[13px] text-accent underline-offset-4 hover:underline">{t('panel.open')}</Link>}>
      <PlanView plan={plan} />
    </Section>
  )
}
