import { useTranslation } from 'react-i18next'
import { Printer } from 'lucide-react'
import { PageHeader } from '@/components/common/PageHeader'
import { EmptyState, QueryState } from '@/components/common/States'
import { Button } from '@/components/ui/button'
import { usePdpl } from './api'
import { PdplDocument } from './PdplDocument'
import { ReportFilterSwitches } from './filters'

// Only .print-doc is printed (the print rules are in index.css, @media print); the person picks "Save as PDF" in the print dialog.
// The switch is the assessment tab's (one choice per browser): the printed copy follows it and says which it used.
function Shell({ back, title, children }: { back: string; title: string; children: React.ReactNode }) {
  const { t } = useTranslation('reports')
  return (
    <>
      {/* docs/UI.md §3: the parent above the title; the one primary action on the right of the header */}
      <div className="no-print">
        <PageHeader breadcrumbs={[{ label: t('nav.reports'), to: back }]} title={title} meta={t('print.hint')}
          actions={<Button variant="primary" onClick={() => window.print()}><Printer aria-hidden />{t('print.button')}</Button>} />
        <div className="mx-auto mb-4 max-w-[210mm]"><ReportFilterSwitches idPrefix="print-include" notRelevant={false} /></div>
      </div>
      <div className="print-doc mx-auto max-w-[210mm] rounded-md border border-rule bg-surface p-8">{children}</div>
    </>
  )
}

function PdplPrint() {
  const { t } = useTranslation('reports')
  const p = usePdpl()
  return (
    <QueryState query={p}>
      {(s) => s.report ? <PdplDocument report={s.report} /> : <EmptyState title={t('print.noPdpl')}>{t('print.noPdplBody')}</EmptyState>}
    </QueryState>
  )
}

export function PdplPrintPage() {
  const { t } = useTranslation('reports')
  return <Shell back="/reports?tab=pdpl" title={t('print.pdplTitle')}><PdplPrint /></Shell>
}
