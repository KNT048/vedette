import { Breadcrumbs } from '@/components/common/Breadcrumbs'
import { useTranslation } from 'react-i18next'
import { PageHeader } from '@/components/common/PageHeader'
import { OldHashToTab, PageTabs } from '@/components/common/PageFrame'
import { EmptyState, Loading, ModuleOff, RequireModule } from '@/components/common/States'
import { useMe } from '@/lib/session'
import { AgentsSection, WazuhSection } from './AgentsSection'
import { SensorsSection } from './SensorsSection'
import { Link, Navigate, useLocation } from 'react-router'
import { SlidersHorizontal } from 'lucide-react'
import { buttonVariants } from '@/components/ui/button'

// "Add devices" links to #agents and SNMP to #snmp; those and the other section ids open their tab.
const OLD_HASH: Record<string, string> = { sensors: 'sensor', agents: 'agents', wazuh: 'wazuh' }

/** The scan scope has one editor, Settings › Scanning › Safety: an old link to the Scope tab here (?tab=scope, #ranges, #active,
 *  #fragile, #scope) lands on the same field there. */
const SCOPE_FIELD: Record<string, string> = {
  'range-input': '/settings/scanning?tab=safety#range-input', ranges: '/settings/scanning?tab=safety#scope', scope: '/settings/scanning?tab=safety#scope',
  'scope-confirm': '/settings/scanning?tab=safety#scope-confirm', 'active-from': '/settings/scanning?tab=safety#win-from', active: '/settings/scanning?tab=safety#window',
  'active-enabled': '/settings/scanning?tab=engines#engine-nmap-discovery', fragile: '/settings/scanning?tab=safety#fragile', 'excl-input': '/settings/scanning?tab=safety#excl',
}
function scopeMoved(search: string, hash: string): string | null {
  const field = hash.slice(1)
  if (new URLSearchParams(search).get('tab') !== 'scope' && !['ranges', 'active', 'fragile', 'scope'].includes(field)) return null
  return SCOPE_FIELD[field] ?? '/settings/scanning?tab=safety#scope'
}

/** #850: old SNMP links (?tab=snmp, #snmp) land on the SNMP card of Settings › Scanning (SNMP itself is set up per device). */
function snmpMoved(search: string, hash: string): string | null {
  const p = new URLSearchParams(search)
  if (p.get('tab') !== 'snmp' && hash !== '#snmp') return null
  return '/settings/scanning?tab=engines#snmp'
}

function Body() {
  const { t } = useTranslation('inventory')
  const me = useMe()
  const { search, hash } = useLocation()
  const admin = me.data?.role === 'admin'
  const moved = snmpMoved(search, hash) ?? scopeMoved(search, hash)
  // UI.md §3: breadcrumbs (parents only) above the title.
  const crumbs = [{ label: t('common:shell.devices'), to: '/devices' }]
  const back = <Breadcrumbs items={crumbs} />
  if (moved) return <Navigate to={moved} replace />
  if (me.isPending) return <>{back}<Loading /></>
  if (!admin) {
    return <>{back}<PageHeader title={t('setup.forbiddenTitle')} /><EmptyState title={t('setup.forbidden')}>{t('setup.forbiddenBody', { role: t('common:role.admin') })}</EmptyState></>
  }
  return (
    <>
      {back}
      <PageHeader title={t('setup.title')} stories={['S-INV-1', 'S-INV-4']}
        actions={<Link to="/settings/scanning?tab=safety#scope" className={buttonVariants({ variant: 'secondary' })}><SlidersHorizontal />{t('setup.scopeLink')}</Link>} meta={t('setup.meta')} info={t('setup.metaInfo')} />
      <OldHashToTab map={OLD_HASH} />
      {/* Areas that each save on their own (the box's sensor, agents, Wazuh). The scan scope is edited in one place only,
          Settings › Scanning › Safety, with the other scanning settings it depends on (window, speed, cost of a pass). */}
      <PageTabs label={t('setup.tabs.label')} tabs={[
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
