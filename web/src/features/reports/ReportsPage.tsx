import { lazy, Suspense } from 'react'
import { useSearchParams } from 'react-router'
import { useTranslation } from 'react-i18next'
import { PageHeader } from '@/components/common/PageHeader'
import { Loading, RequireModule, SampleDataNote } from '@/components/common/States'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs'
import { useWeekly } from './api'

const WeeklyTab = lazy(() => import('./WeeklyTab'))
const PdplTab = lazy(() => import('./PdplTab'))

export default function ReportsPage() {
  const { t } = useTranslation('reports')
  const [params, setParams] = useSearchParams()
  const tab = params.get('tab') === 'pdpl' ? 'pdpl' : 'weekly'
  const weekly = useWeekly()
  const c = weekly.data?.report.counts
  const empty = !!c && c.devices === 0 && c.open_confirmed + c.open_suspected === 0 && c.new_findings === 0 && c.resolved === 0
  const title = empty ? t('page.titleEmpty') : c ? (c.open_confirmed + c.open_suspected > 0 ? t('page.title', { open: c.open_confirmed + c.open_suspected, unapproved: c.devices_unapproved }) : t('page.titleClear', { unapproved: c.devices_unapproved })) : t('page.titleLoading')
  return (
    <>
      <PageHeader title={title} meta={<span className="flex flex-wrap items-center gap-2"><SampleDataNote />{t('page.meta')}</span>} stories={['S-REP-1', 'S-REP-2']} />
      <RequireModule module="reports">
        <Tabs value={tab} onValueChange={(v) => setParams(v === 'pdpl' ? { tab: 'pdpl' } : {}, { replace: true })}>
          <TabsList aria-label={t('page.tabs')}>
            <TabsTrigger value="weekly">{t('page.weekly')}</TabsTrigger>
            <TabsTrigger value="pdpl">{t('page.pdpl')}</TabsTrigger>
          </TabsList>
          <Suspense fallback={<Loading />}>
            <TabsContent value="weekly"><WeeklyTab /></TabsContent>
            <TabsContent value="pdpl"><PdplTab /></TabsContent>
          </Suspense>
        </Tabs>
      </RequireModule>
    </>
  )
}
