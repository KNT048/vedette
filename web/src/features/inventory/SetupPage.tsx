import { Breadcrumbs } from '@/components/common/Breadcrumbs'
import { useTranslation } from 'react-i18next'
import { PageHeader } from '@/components/common/PageHeader'
import { OldHashToTab, PageTabs } from '@/components/common/PageFrame'
import { EmptyState, Loading, ModuleOff, QueryState, RequireModule, SampleDataNote } from '@/components/common/States'
import { useMe } from '@/lib/session'
import { AgentsSection, WazuhSection } from './AgentsSection'
import { useSettings } from './api'
import { NetworkForm } from './NetworkForm'
import { SensorsSection } from './SensorsSection'
import { Navigate, useLocation } from 'react-router'

// "Add devices" links to #agents and SNMP to #snmp; those and the other section ids open their tab.
const OLD_HASH: Record<string, string> = { ranges: 'scope', active: 'scope', fragile: 'scope', scope: 'scope', sensors: 'sensor', agents: 'agents', wazuh: 'wazuh' }

/** #850: old SNMP links (?tab=snmp, #snmp) land on the SNMP card of Settings › Scanning (SNMP itself is set up per device). */
function snmpMoved(search: string, hash: string): string | null {
  const p = new URLSearchParams(search)
  if (p.get('tab') !== 'snmp' && hash !== '#snmp') return null
  return '/settings/scanning?tab=engines#snmp'
}

function Body() {
  const { t } = useTranslation('inventory')
  const me = useMe()
  const settings = useSettings()
  const { search, hash } = useLocation()
  const admin = me.data?.role === 'admin'
  const moved = snmpMoved(search, hash)
  // UI.md §3: breadcrumbs (parents only) above the title.
  const crumbs = [{ label: t('common:shell.devices'), to: '/devices' }]
  const back = <Breadcrumbs items={crumbs} />
  if (moved) return <Navigate to={moved} replace />
  if (me.isPending) return <>{back}<Loading /></>
  if (!admin) {
    return <>{back}<PageHeader title={t('setup.forbiddenTitle')} /><EmptyState title={t('setup.forbidden')}>{t('setup.forbiddenBody', { role: t('common:role.admin') })}</EmptyState></>
  }
  const ranges = settings.data?.lan_ranges.length
  const title = ranges === undefined ? t('setup.titleLoading') : ranges === 0 ? t('setup.titleNone') : t('setup.title', { count: ranges })
  return (
    <>
      {back}
      <PageHeader title={title} stories={['S-INV-1', 'S-INV-4']} meta={<span className="inline-flex flex-wrap items-center gap-2"><SampleDataNote />{t('setup.meta')}</span>} info={t('setup.metaInfo')} />
      <OldHashToTab map={OLD_HASH} />
      {/* Four areas that each save on their own (scope, the box's sensor, SNMP credentials, agents), as Lansweeper keeps
          scanning targets and scanning credentials on separate pages. */}
      <PageTabs label={t('setup.tabs.label')} tabs={[
        { id: 'scope', label: t('setup.tabs.scope'), panel: <QueryState query={settings}>{(s) => <NetworkForm key={JSON.stringify(s)} settings={s} />}</QueryState> },
        { id: 'sensor', label: t('setup.tabs.sensor'), panel: <SensorsSection /> },
        // SNMP reads run in the active scanner: with sensor-active off the area does not exist, so neither does its tab.
        { id: 'agents', label: t('setup.tabs.agents'), panel: <AgentsSection /> },
        { id: 'wazuh', label: t('setup.tabs.wazuh'), panel: <WazuhSection /> },
      ]} />
    </>
  )
}

export default function SetupPage() {
  const { t } = useTranslation('inventory')
  return (
    <RequireModule module="inventory" fallback={<><PageHeader title={t('off.title')} /><ModuleOff module="inventory">{t('off.body')}</ModuleOff></>}>
      <Body />
    </RequireModule>
  )
}
