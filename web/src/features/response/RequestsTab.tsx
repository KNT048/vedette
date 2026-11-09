import { useState } from 'react'
import { Link } from 'react-router'
import { useTranslation } from 'react-i18next'
import { Section } from '@/components/common/PageHeader'
import { EmptyState, ErrorState, Loading } from '@/components/common/States'
import { Segmented } from '@/components/ui/segmented'
import { useActions, usePlans } from './api'
import { PlanView } from './parts'
import { RequestCard } from './RequestCard'

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

/** Pending and history, rules and AI together. One bundled request per rule run. */
export function RequestsTab() {
  const { t } = useTranslation('response')
  const actions = useActions()
  const [view, setView] = useState<'pending' | 'history'>('pending')
  const [src, setSrc] = useState<'all' | 'rule' | 'ai'>('all')
  if (actions.isPending) return <Loading />
  if (actions.error) return <ErrorState error={actions.error} onRetry={() => void actions.refetch()} />
  const all = actions.data.items.filter((a) => src === 'all' || a.source === src)
  const items = all.filter((a) => (view === 'pending') === (a.status === 'pending'))
  const pending = actions.data.items.filter((a) => a.status === 'pending').length
  return (
    <div className="grid gap-2">
      <Section id="requests" title={t('requests.title')} description={t('requests.description')} stories={['S-RESP-2', 'S-RESP-3']}
        actions={<div className="flex flex-wrap gap-2">
          <Segmented label={t('requests.view')} value={view} onChange={setView} options={[{ value: 'pending', label: t('requests.pending', { count: pending }) }, { value: 'history', label: t('requests.history') }]} />
          <Segmented label={t('requests.source')} value={src} onChange={setSrc} options={[{ value: 'all', label: t('requests.all') }, { value: 'rule', label: t('requests.rules') }, { value: 'ai', label: t('requests.ai') }]} />
        </div>}>
        {items.length ? <div className="grid gap-4">{items.map((a) => <RequestCard key={a.id} a={a} />)}</div> : <EmptyState title={view === 'pending' ? t('requests.emptyPending') : t('requests.empty')}>{t('requests.emptyBody')}</EmptyState>}
      </Section>
      <Plans />
    </div>
  )
}
