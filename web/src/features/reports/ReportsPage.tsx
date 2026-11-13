import { lazy, Suspense } from 'react'
import { useTranslation } from 'react-i18next'
import { PageHeader } from '@/components/common/PageHeader'
import { PageTabs } from '@/components/common/PageFrame'
import { Loading, RequireModule, SampleDataNote } from '@/components/common/States'
import { useWeekly } from './api'

const WeeklyTab = lazy(() => import('./WeeklyTab'))
const PdplTab = lazy(() => import('./PdplTab'))

export default function ReportsPage() {
  const { t } = useTranslation('reports')
  const weekly = useWeekly()
  const c = weekly.data?.report.counts
  const empty = !!c && c.devices === 0 && c.open_confirmed + c.open_suspected === 0 && c.new_findings === 0 && c.resolved === 0
  const title = empty ? t('page.titleEmpty') : c ? (c.open_confirmed + c.open_suspected > 0 ? t('page.title', { open: c.open_confirmed + c.open_suspected, unapproved: c.devices_unapproved }) : t('page.titleClear', { unapproved: c.devices_unapproved })) : t('page.titleLoading')
  return (
    <>
      <PageHeader title={title} meta={<span className="flex flex-wrap items-center gap-2"><SampleDataNote />{t('page.meta')}</span>} stories={['S-REP-1', 'S-REP-2']} />
      <RequireModule module="reports">
        <PageTabs label={t('page.tabs')} tabs={[
          { id: 'weekly', label: t('page.weekly'), panel: <Suspense fallback={<Loading />}><WeeklyTab /></Suspense> },
          { id: 'pdpl', label: t('page.pdpl'), panel: <Suspense fallback={<Loading />}><PdplTab /></Suspense> },
        ]} />
      </RequireModule>
    </>
  )
}
