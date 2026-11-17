import { Link, Navigate, useLocation } from 'react-router'
import { useTranslation } from 'react-i18next'
import { Notice, PageHeader } from '@/components/common/PageHeader'
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
import { Frozen, TurnOffResponse } from './Leaving'
import { FrozenCtx, useLeaving } from './frozen'

/** What the AI and the rules may do (the action catalog), what they may never touch, and the block list firewalls pull. */
function ActionsTab() {
  return <div className="grid grid-cols-[minmax(0,1fr)] gap-8"><CatalogEditor /><NeverTouch /><BlocklistTab /></div>
}

// Old tabs: Block list moved into Actions, Metrics into Log.
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
  const leaving = useLeaving() // On here but not offered in v1 → no new action, every way back stays (frozen.ts)
  // Liên kết cũ /response#requests (trước khi có khung trang) → /response?tab=requests; #ai là tên cũ của Requests.
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
  const incident = new URLSearchParams(search).get('incident') // Respond on an incident
  return (
    <FrozenCtx.Provider value={leaving}>
      <PageHeader title={t('page.title')} stories={['S-RESP-1', 'S-RESP-2', 'S-RESP-3', 'S-RESP-4']}
        meta={t('page.meta')} info={t('page.metaInfo')}
        actions={<><SampleDataNote />{execution ? <EmergencyStop /> : null}{leaving ? <TurnOffResponse /> : null}</>} />
      {s?.breaker_tripped_at || s?.stopped_at ? (
        <Notice tone="danger" role="alert" title={t('page.breakerTitle')} info={s.stopped_at ? t('page.stoppedBodyInfo') : t('page.breakerBodyInfo')}>
          {s.stopped_at ? t('page.stoppedBody') : t('page.breakerBody', { max: s.breaker_max_per_hour })} <Link className="text-accent underline underline-offset-4" to="/settings/response#resp-exec">{t('blocked.toSettings')}</Link>
        </Notice>
      ) : null}
      {execution ? (
        <Notice tone="danger" role="status" title={t('page.onTitle')} info={t('page.onBodyInfo')}>{t('page.onBody', { count: pending })}</Notice>
      ) : leaving ? null : ( // L2: no invitation to turn on what this build does not offer
        <Notice tone="off" title={<>{t('blocked.execution_off')} {admin ? <Link className="text-accent underline underline-offset-4" to="/settings/response#resp-exec">{t('blocked.toSettings')}</Link> : null}</>} />
      )}
      {incident ? <Frozen on={leaving}><IncidentRespond id={incident} /></Frozen> : null}
      {/* The inbox first, then how requests are made (Rules, Actions), what happened (Log), and the switch and limits (Settings). */}
      <PageTabs label={t('tabs.label')} tabs={[
        { id: 'requests', label: t('tabs.requests'), panel: <RequestsTab />, badge: { count: pending, label: t('tabs.pending') } },
        { id: 'rules', label: t('tabs.rules'), panel: <RulesTab /> },
        ...(admin ? [{ id: 'actions', label: t('tabs.actions'), panel: <Frozen on={leaving}><ActionsTab /></Frozen> }] : []),
        { id: 'log', label: t('tabs.log'), panel: <>{operator ? <LogTab /> : null}<Frozen on={leaving}><MetricsTab /></Frozen></> },
        ...(admin ? [{ id: 'settings', label: t('tabs.settings'), panel: <ResponseSettings embedded /> }] : []),
      ]} />
    </FrozenCtx.Provider>
  )
}

export default function ResponsePage() {
  const incident = new URLSearchParams(useLocation().search).get('incident')
  // Respond on an incident while response is off (the default): the manual steps still help (S-RESP-3)
  return <RequireModule module="response" page fallback={incident ? <IncidentRespondOff id={incident} /> : undefined}><Content /></RequireModule>
}
