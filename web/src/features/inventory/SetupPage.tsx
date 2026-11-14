import { Link } from 'react-router'
import { useTranslation } from 'react-i18next'
import { ArrowLeft } from 'lucide-react'
import { PageHeader } from '@/components/common/PageHeader'
import { OldHashToTab, PageTabs } from '@/components/common/PageFrame'
import { EmptyState, Loading, ModuleOff, QueryState, RequireModule, SampleDataNote } from '@/components/common/States'
import { buttonVariants } from '@/components/ui/button'
import { useModuleEnabled } from '@/lib/modules'
import { useMe } from '@/lib/session'
import { cn } from '@/lib/utils'
import { AgentsSection } from './AgentsSection'
import { useSettings } from './api'
import { NetworkForm } from './NetworkForm'
import { SensorsSection } from './SensorsSection'
import { SnmpSection } from './SnmpSection'

// "Add devices" links to #agents (D-471) and SNMP to #snmp (D-512); those and the other section ids open their tab (D-519).
const OLD_HASH: Record<string, string> = { ranges: 'scope', active: 'scope', fragile: 'scope', scope: 'scope', sensors: 'sensor', snmp: 'snmp', agents: 'agents' }

function Body() {
  const { t } = useTranslation('inventory')
  const me = useMe()
  const settings = useSettings()
  const admin = me.data?.role === 'admin'
  const snmpOn = useModuleEnabled('sensor-active') === true
  const back = <Link to="/devices" className={cn(buttonVariants({ variant: 'link', size: 'sm' }), 'mb-3 inline-flex')}><ArrowLeft />{t('detail.back')}</Link>
  if (me.isPending) return <>{back}<Loading /></>
  if (!admin) {
    return <>{back}<PageHeader title={t('setup.forbiddenTitle')} /><EmptyState title={t('setup.forbidden')}>{t('setup.forbiddenBody', { role: t('common:role.admin') })}</EmptyState></>
  }
  const ranges = settings.data?.lan_ranges.length
  const title = ranges === undefined ? t('setup.titleLoading') : ranges === 0 ? t('setup.titleNone') : t('setup.title', { count: ranges })
  return (
    <>
      {back}
      <PageHeader title={title} stories={['S-INV-1', 'S-INV-4']} meta={<span className="inline-flex flex-wrap items-center gap-2"><SampleDataNote />{t('setup.meta')}</span>} />
      <OldHashToTab map={OLD_HASH} />
      {/* D-519: four areas that each save on their own (scope, the box's sensor, SNMP credentials, agents), as Lansweeper keeps
          scanning targets and scanning credentials on separate pages. */}
      <PageTabs label={t('setup.tabs.label')} tabs={[
        { id: 'scope', label: t('setup.tabs.scope'), panel: <QueryState query={settings}>{(s) => <NetworkForm key={JSON.stringify(s)} settings={s} />}</QueryState> },
        { id: 'sensor', label: t('setup.tabs.sensor'), panel: <SensorsSection /> },
        // SNMP reads run in the active scanner: with sensor-active off the area does not exist (D-512), so neither does its tab.
        ...(snmpOn ? [{ id: 'snmp', label: t('setup.tabs.snmp'), panel: <SnmpSection /> }] : []),
        { id: 'agents', label: t('setup.tabs.agents'), panel: <AgentsSection /> },
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
