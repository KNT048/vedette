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
import { CatalogEditor } from './CatalogEditor'
import { NeverTouch } from './NeverTouch'
import { LogTab } from './LogTab'
import { MetricsTab } from './MetricsTab'
import { IncidentRespond, IncidentRespondOff } from './IncidentRespond'
import ResponseSettings from './ResponseSettings'

/** What the AI and the rules may do (the action catalog), what they may never touch, and the block list firewalls pull (D-513). */
function ActionsTab() {
  return <div className="grid grid-cols-[minmax(0,1fr)] gap-8"><CatalogEditor /><NeverTouch /><BlocklistTab /></div>
}

// Tabs before D-513: Block list moved into Actions, Metrics into Log.
const OLD_HASH = ['rules', 'requests', 'blocklist', 'log', 'metrics']
const MOVED: Record<string, string> = { blocklist: 'actions', metrics: 'log' }

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
    p.set('tab', MOVED[old] ?? old)
    return <Navigate replace to={{ search: `?${p}`, hash: '' }} />
  }
  const tab = new URLSearchParams(search).get('tab') ?? ''
  if (MOVED[tab]) {
    const p = new URLSearchParams(search)
    p.set('tab', MOVED[tab]!)
    return <Navigate replace to={{ search: `?${p}`, hash }} />
  }
  if (plans.isPending || actions.isPending) return <Loading />
  if (plans.error || actions.error) return <ErrorState error={plans.error ?? actions.error} onRetry={() => { void plans.refetch(); void actions.refetch() }} />
  const { execution } = plans.data
  const pending = actions.data.items.filter((a) => a.status === 'pending').length
  const s = settings.data
  const incident = new URLSearchParams(search).get('incident') // Respond on an incident (D-509)
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
          <p>{t('page.onBody', { count: pending })}</p>
        </div>
      ) : (
        <p className="mb-6 rounded-md border border-dashed border-rule bg-surface px-4 py-3 text-sm text-muted">
          {t('blocked.execution_off')} {admin ? <Link className="text-accent underline underline-offset-4" to="/settings/response">{t('blocked.toSettings')}</Link> : null}
        </p>
      )}
      {incident ? <IncidentRespond id={incident} /> : null}
      {/* D-513: the inbox first, then how requests are made (Rules, Actions), what happened (Log), and the switch and limits (Settings). */}
      <PageTabs label={t('tabs.label')} tabs={[
        { id: 'requests', label: t('tabs.requests'), panel: <RequestsTab />, badge: { count: pending, label: t('tabs.pending') } },
        { id: 'rules', label: t('tabs.rules'), panel: <RulesTab /> },
        ...(admin ? [{ id: 'actions', label: t('tabs.actions'), panel: <ActionsTab /> }] : []),
        { id: 'log', label: t('tabs.log'), panel: <>{operator ? <LogTab /> : null}<MetricsTab /></> },
        ...(admin ? [{ id: 'settings', label: t('tabs.settings'), panel: <ResponseSettings embedded /> }] : []),
      ]} />
    </>
  )
}

export default function ResponsePage() {
  const incident = new URLSearchParams(useLocation().search).get('incident')
  // Respond on an incident while response is off (the default): the manual steps still help (W7-1, S-RESP-3)
  return <RequireModule module="response" fallback={incident ? <IncidentRespondOff id={incident} /> : undefined}><Content /></RequireModule>
}
