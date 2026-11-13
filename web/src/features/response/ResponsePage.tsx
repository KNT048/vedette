import { Link, Navigate, useLocation } from 'react-router'
import { useTranslation } from 'react-i18next'
import { PageHeader } from '@/components/common/PageHeader'
import { PageTabs } from '@/components/common/PageFrame'
import { ErrorState, Loading, RequireModule, SampleDataNote } from '@/components/common/States'
import { useCan } from '@/lib/session'
import { useActions, usePlans, useSettings } from './api'
import { EmergencyStop } from './parts'
import { RulesTab } from './RulesTab'
import { RequestsTab } from './RequestsTab'
import { BlocklistTab } from './BlocklistTab'
import { LogTab } from './LogTab'
import { MetricsTab } from './MetricsTab'

const OLD_HASH = ['rules', 'requests', 'blocklist', 'log', 'metrics']

function Content() {
  const { t } = useTranslation('response')
  const admin = useCan('admin')
  const operator = useCan('operator')
  const { hash, search } = useLocation()
  const plans = usePlans()
  const actions = useActions()
  const settings = useSettings(admin)
  // Liên kết cũ /response#requests (trước D-464) → /response?tab=requests; #ai là tên cũ của Requests.
  // Hash khác (ví dụ #main của liên kết "Skip to content") để nguyên.
  const old = hash.slice(1) === 'ai' ? 'requests' : hash.slice(1)
  if (OLD_HASH.includes(old)) {
    const p = new URLSearchParams(search)
    p.set('tab', old)
    return <Navigate replace to={{ search: `?${p}`, hash: '' }} />
  }
  if (plans.isPending || actions.isPending) return <Loading />
  if (plans.error || actions.error) return <ErrorState error={plans.error ?? actions.error} onRetry={() => { void plans.refetch(); void actions.refetch() }} />
  const { execution } = plans.data
  const pending = actions.data.items.filter((a) => a.status === 'pending').length
  const s = settings.data
  return (
    <>
      <PageHeader title={t('page.title')} stories={['S-RESP-1', 'S-RESP-2', 'S-RESP-3', 'S-RESP-4']}
        meta={t('page.meta')}
        actions={<><SampleDataNote />{execution ? <EmergencyStop /> : null}</>} />
      {s?.breaker_tripped_at || s?.stopped_at ? (
        <div role="alert" className="mb-6 rounded-md border border-danger/50 bg-danger-soft px-4 py-3 text-sm">
          <p className="font-medium text-danger">{t('page.breakerTitle')}</p>
          <p>{s.stopped_at ? t('page.stoppedBody') : t('page.breakerBody', { max: s.breaker_max_per_hour })} <Link className="text-accent underline underline-offset-4" to="/settings/response">{t('blocked.toSettings')}</Link></p>
        </div>
      ) : null}
      {execution ? (
        <div role="status" className="mb-6 rounded-md border border-danger/50 bg-danger-soft px-4 py-3 text-sm">
          <p className="font-medium text-danger">{t('page.onTitle')}</p>
          <p>{t('page.onBody', { pending })}</p>
        </div>
      ) : (
        <p className="mb-6 rounded-md border border-dashed border-rule bg-surface px-4 py-3 text-sm text-muted">
          {t('blocked.execution_off')} {admin ? <Link className="text-accent underline underline-offset-4" to="/settings/response">{t('blocked.toSettings')}</Link> : null}
        </p>
      )}
      <PageTabs label={t('tabs.label')} tabs={[
        { id: 'rules', label: t('tabs.rules'), panel: <RulesTab /> },
        { id: 'requests', label: t('tabs.requests'), panel: <RequestsTab />, badge: { count: pending, label: t('tabs.pending') } },
        ...(admin ? [{ id: 'blocklist', label: t('tabs.blocklist'), panel: <BlocklistTab /> }] : []),
        ...(operator ? [{ id: 'log', label: t('tabs.log'), panel: <LogTab /> }] : []),
        { id: 'metrics', label: t('tabs.metrics'), panel: <MetricsTab /> },
      ]} />
    </>
  )
}

export default function ResponsePage() {
  return <RequireModule module="response"><Content /></RequireModule>
}
