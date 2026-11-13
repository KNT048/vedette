import { useState } from 'react'
import { Link } from 'react-router'
import { useTranslation } from 'react-i18next'
import { Section } from '@/components/common/PageHeader'
import { EmptyState, ErrorState, Loading } from '@/components/common/States'
import { Segmented } from '@/components/ui/segmented'
import { useActions, usePlans } from './api'
import { PlanView } from './parts'
import { RequestCard } from './RequestCard'
import { AiSetup, InboxWhy, useSetupDone } from './AiSetup'
import type { ActionRequest } from './types'

function Plans() {
  const { t } = useTranslation('response')
  const plans = usePlans()
  if (plans.isPending) return <Loading />
  if (plans.error) return <ErrorState error={plans.error} onRetry={() => void plans.refetch()} />
  const { items, ai_available } = plans.data
  return (
    <Section title={t('plans.title')} description={t('plans.description')} stories={['S-RESP-1']}>
      {items.length ? (
        <div className="grid gap-6">{items.map((p) => <PlanView key={p.id} plan={p} heading />)}</div>
      ) : (
        <EmptyState title={ai_available ? t('plans.empty') : t('plans.noAi')}>{ai_available ? t('plans.emptyBody') : <>{t('plans.noAiBody')} <Link className="text-accent underline underline-offset-4" to="/settings/ai">{t('plans.toAi')}</Link></>}</EmptyState>
      )}
    </Section>
  )
}

type Risk = ActionRequest['risk']

/** The inbox (item 20, D-513): requests from the AI, rules and people, waiting first. With nothing waiting it shows the guided "Let the AI
 * propose actions" setup and why the AI proposed nothing; with requests waiting the setup folds into one line until its required steps are done. */
export function RequestsTab() {
  const { t } = useTranslation('response')
  const actions = useActions()
  const setupDone = useSetupDone()
  const [view, setView] = useState<'pending' | 'history'>('pending')
  const [src, setSrc] = useState<'all' | 'ai' | 'rule' | 'person'>('all')
  const [risk, setRisk] = useState<'all' | Risk>('all')
  if (actions.isPending) return <Loading />
  if (actions.error) return <ErrorState error={actions.error} onRetry={() => void actions.refetch()} />
  const items = actions.data.items.filter((a) => (src === 'all' || a.source === src) && (risk === 'all' || a.risk === risk) && (view === 'pending') === (a.status === 'pending'))
  const pending = actions.data.items.filter((a) => a.status === 'pending').length
  const filtered = src !== 'all' || risk !== 'all'
  return (
    <div className="grid gap-2">
      {pending && setupDone === false ? <AiSetup compact /> : null}
      <Section id="requests" title={t('requests.title')} description={t('requests.description')} stories={['S-RESP-2', 'S-RESP-3']}
        actions={<div className="flex flex-wrap gap-2">
          <Segmented label={t('requests.view')} value={view} onChange={setView} options={[{ value: 'pending', label: t('requests.pending', { count: pending }) }, { value: 'history', label: t('requests.history') }]} />
          <Segmented label={t('requests.source')} value={src} onChange={setSrc} options={[{ value: 'all', label: t('requests.all') }, { value: 'ai', label: t('requests.ai') }, { value: 'rule', label: t('requests.rules') }, { value: 'person', label: t('requests.people') }]} />
          <Segmented label={t('requests.risk')} value={risk} onChange={setRisk} options={[{ value: 'all', label: t('requests.anyRisk') }, ...(['high', 'medium', 'low'] as const).map((r) => ({ value: r, label: t(`catalog.risks.${r}`) }))]} />
        </div>}>
        {items.length ? <div className="grid gap-4">{items.map((a) => <RequestCard key={a.id} a={a} />)}</div>
          : <EmptyState title={view === 'pending' ? t('requests.emptyPending') : t('requests.empty')}>{filtered ? t('requests.emptyFiltered') : t('requests.emptyBody')}</EmptyState>}
      </Section>
      {!pending ? <><AiSetup /><InboxWhy /></> : null}
      <Plans />
    </div>
  )
}
