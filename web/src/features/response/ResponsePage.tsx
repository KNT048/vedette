import { Link, useLocation, useNavigate } from 'react-router'
import { useTranslation } from 'react-i18next'
import { PageHeader } from '@/components/common/PageHeader'
import { ErrorState, Loading, RequireModule, SampleDataNote } from '@/components/common/States'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs'
import { useCan } from '@/lib/session'
import { useActions, usePlans, useSettings } from './api'
import { EmergencyStop } from './parts'
import { RulesTab } from './RulesTab'
import { RequestsTab } from './RequestsTab'
import { BlocklistTab } from './BlocklistTab'
import { LogTab } from './LogTab'
import { MetricsTab } from './MetricsTab'

const TABS = ['rules', 'requests', 'blocklist', 'log', 'metrics'] as const
type Tab = (typeof TABS)[number]

function Content() {
  const { t } = useTranslation('response')
  const admin = useCan('admin')
  const operator = useCan('operator')
  const nav = useNavigate()
  const { hash } = useLocation()
  const plans = usePlans()
  const actions = useActions()
  const settings = useSettings(admin)
  if (plans.isPending || actions.isPending) return <Loading />
  if (plans.error || actions.error) return <ErrorState error={plans.error ?? actions.error} onRetry={() => { void plans.refetch(); void actions.refetch() }} />
  const { execution } = plans.data
  const pending = actions.data.items.filter((a) => a.status === 'pending').length
  const raw = hash.replace('#', '')
  const wanted = (raw === 'ai' ? 'requests' : raw) as Tab
  const tab: Tab = TABS.includes(wanted) && (wanted !== 'blocklist' || admin) && (wanted !== 'log' || operator) ? wanted : 'rules'
  const s = settings.data
  return (
    <>
      <PageHeader title={t('page.title')} stories={['S-RESP-1', 'S-RESP-2', 'S-RESP-3', 'S-RESP-4']}
        meta={t('page.meta')}
        actions={<><SampleDataNote />{execution ? <EmergencyStop /> : null}</>} />
      {s?.breaker_tripped_at ? (
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
      <Tabs value={tab} onValueChange={(v) => void nav({ hash: v }, { replace: true })}>
        <TabsList className="flex-wrap">
          <TabsTrigger value="rules">{t('tabs.rules')}</TabsTrigger>
          <TabsTrigger value="requests">{t('tabs.requests')}{pending ? ` (${pending})` : ''}</TabsTrigger>
          {admin ? <TabsTrigger value="blocklist">{t('tabs.blocklist')}</TabsTrigger> : null}
          {operator ? <TabsTrigger value="log">{t('tabs.log')}</TabsTrigger> : null}
          <TabsTrigger value="metrics">{t('tabs.metrics')}</TabsTrigger>
        </TabsList>
        <TabsContent value="rules"><RulesTab /></TabsContent>
        <TabsContent value="requests"><RequestsTab /></TabsContent>
        <TabsContent value="blocklist"><BlocklistTab /></TabsContent>
        <TabsContent value="log"><LogTab /></TabsContent>
        <TabsContent value="metrics"><MetricsTab /></TabsContent>
      </Tabs>
    </>
  )
}

export default function ResponsePage() {
  return <RequireModule module="response"><Content /></RequireModule>
}
