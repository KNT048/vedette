import { Link, Navigate, useLocation, useSearchParams } from 'react-router'
import { useTranslation } from 'react-i18next'
import { ArrowLeft } from 'lucide-react'
import { PageHeader } from '@/components/common/PageHeader'
import { OldHashToTab, PageTabs } from '@/components/common/PageFrame'
import { EmptyState, Loading, ModuleOff, QueryState, RequireModule, SampleDataNote } from '@/components/common/States'
import { buttonVariants } from '@/components/ui/button'
import { useMe } from '@/lib/session'
import { cn } from '@/lib/utils'
import { AgentsSection } from './AgentsSection'
import { useSettings } from './api'
import { NetworkForm } from './NetworkForm'
import { SensorsSection } from './SensorsSection'

// "Add devices" links to #agents (D-471); those and the other section ids open their tab (D-519).
const OLD_HASH: Record<string, string> = { ranges: 'scope', active: 'scope', fragile: 'scope', scope: 'scope', sensors: 'sensor', agents: 'agents' }
/** The SNMP credential list left Devices (#849) for Settings › Scanning (#850); its old links (?tab=snmp, #snmp, ?snmp_ip=) go there. */
const SNMP_SETTINGS = '/settings/scanning'

function SnmpMoved() {
  const [params] = useSearchParams()
  const { hash } = useLocation()
  if (params.get('tab') !== 'snmp' && hash !== '#snmp') return null
  const ip = params.get('snmp_ip')
  return <Navigate replace to={{ pathname: SNMP_SETTINGS, search: ip ? `?${new URLSearchParams({ snmp_ip: ip })}` : '', hash: 'snmp' }} />
}

function Body() {
  const { t } = useTranslation('inventory')
  const me = useMe()
  const settings = useSettings()
  const admin = me.data?.role === 'admin'
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
      <PageHeader title={title} stories={['S-INV-1', 'S-INV-4']} meta={<span className="inline-flex flex-wrap items-center gap-2"><SampleDataNote />{t('setup.meta')}</span>} info={t('setup.metaInfo')} />
      <SnmpMoved />
      <OldHashToTab map={OLD_HASH} />
      {/* D-519: areas that each save on their own (scope, the box's sensor, agents), as Lansweeper keeps scanning targets and
          scanning credentials on separate pages; the SNMP credentials moved to Settings › Scanning (#849, #850). */}
      <PageTabs label={t('setup.tabs.label')} tabs={[
        { id: 'scope', label: t('setup.tabs.scope'), panel: <QueryState query={settings}>{(s) => <NetworkForm key={JSON.stringify(s)} settings={s} />}</QueryState> },
        { id: 'sensor', label: t('setup.tabs.sensor'), panel: <SensorsSection /> },
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
