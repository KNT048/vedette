import { Link } from 'react-router'
import { useTranslation } from 'react-i18next'
import { ArrowLeft } from 'lucide-react'
import { PageHeader } from '@/components/common/PageHeader'
import { EmptyState, Loading, ModuleOff, QueryState, RequireModule, SampleDataNote } from '@/components/common/States'
import { buttonVariants } from '@/components/ui/button'
import { useMe } from '@/lib/session'
import { cn } from '@/lib/utils'
import { AgentsSection } from './AgentsSection'
import { useSettings } from './api'
import { NetworkForm } from './NetworkForm'
import { SensorsSection } from './SensorsSection'

function Body() {
  const { t } = useTranslation('inventory')
  const me = useMe()
  const settings = useSettings()
  const back = <Link to="/devices" className={cn(buttonVariants({ variant: 'link', size: 'sm' }), 'mb-3 inline-flex')}><ArrowLeft />{t('detail.back')}</Link>
  if (me.isPending) return <>{back}<Loading /></>
  if (me.data?.role !== 'admin') {
    return <>{back}<PageHeader title={t('setup.forbiddenTitle')} /><EmptyState title={t('setup.forbidden')}>{t('setup.forbiddenBody', { role: t('common:role.admin') })}</EmptyState></>
  }
  const ranges = settings.data?.lan_ranges.length
  const title = ranges === undefined ? t('setup.titleLoading') : ranges === 0 ? t('setup.titleNone') : t('setup.title', { count: ranges })
  return (
    <>
      {back}
      <PageHeader title={title} stories={['S-INV-1', 'S-INV-4']} meta={<span className="inline-flex flex-wrap items-center gap-2"><SampleDataNote />{t('setup.meta')}</span>} />
      <QueryState query={settings}>{(s) => <NetworkForm key={JSON.stringify(s)} settings={s} />}</QueryState>
      <SensorsSection />
      <AgentsSection />
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
