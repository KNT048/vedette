import { lazy, Suspense } from 'react'
import { useTranslation } from 'react-i18next'
import { PageHeader } from '@/components/common/PageHeader'
import { PageTabs } from '@/components/common/PageFrame'
import { Loading, RequireModule } from '@/components/common/States'
import { useReportDocument } from './api'
import { emptyReport } from './ReportTab'

const ReportTab = lazy(() => import('./ReportTab'))
const HistoryTab = lazy(() => import('./HistoryTab'))
const SettingsTab = lazy(() => import('./SettingsTab'))
const PdplTab = lazy(() => import('./PdplTab'))

export default function ReportsPage() {
  const { t } = useTranslation('reports')
  const doc = useReportDocument()
  const d = doc.data
  // The title says where things stand, as the report's own first line does (open now, handled in its period).
  const s = d?.summary
  const handled = s?.handled ?? d?.handled?.totals.reduce((n, x) => n + x.n, 0) ?? 0
  const status = !d ? null : emptyReport(d) ? t('page.titleEmpty')
    : s && s.open_now === 0 ? t('page.titleClear', { handled }) : s ? t('page.title', { count: s.open_now, handled }) : null
  const tab = (panel: React.ReactNode) => <Suspense fallback={<Loading />}>{panel}</Suspense>
  return (
    <>
      <PageHeader title={t('common:shell.reports')} meta={status} stories={['S-REP-1', 'S-REP-2']} />
      <RequireModule module="reports">
        <PageTabs label={t('page.tabs')} tabs={[
          { id: 'report', label: t('page.report'), panel: tab(<ReportTab />) },
          { id: 'history', label: t('page.history'), panel: tab(<HistoryTab />) },
          { id: 'settings', label: t('page.settings'), panel: tab(<SettingsTab />) },
          { id: 'pdpl', label: t('page.pdpl'), panel: tab(<PdplTab />) },
        ]} />
      </RequireModule>
    </>
  )
}
