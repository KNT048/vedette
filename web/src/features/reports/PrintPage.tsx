import { useParams } from 'react-router'
import { useTranslation } from 'react-i18next'
import { Printer } from 'lucide-react'
import { PageHeader } from '@/components/common/PageHeader'
import { EmptyState, QueryState } from '@/components/common/States'
import { Button } from '@/components/ui/button'
import { useMe } from '@/lib/session'
import { useHistoryEntry, usePdpl, useWeekly } from './api'
import { PdplDocument } from './PdplDocument'
import { WeeklyDocument } from './WeeklyDocument'

// Only .print-doc is printed (the print rules are in index.css, @media print); the person picks "Save as PDF" in the print dialog.
function Shell({ back, title, children }: { back: string; title: string; children: React.ReactNode }) {
  const { t } = useTranslation('reports')
  return (
    <>
      {/* docs/UI.md §3: the parent above the title; the one primary action on the right of the header */}
      <div className="no-print">
        <PageHeader breadcrumbs={[{ label: t('nav.reports'), to: back }]} title={title} meta={t('print.hint')}
          actions={<Button variant="primary" onClick={() => window.print()}><Printer aria-hidden />{t('print.button')}</Button>} />
      </div>
      <div className="print-doc mx-auto max-w-[210mm] rounded-md border border-rule bg-surface p-8">{children}</div>
    </>
  )
}

function WeeklyPrint() {
  const { id = '' } = useParams()
  const { data: me } = useMe()
  const cur = useWeekly()
  const hist = useHistoryEntry(id)
  const org = me?.org ?? ''
  return id ? <QueryState query={hist}>{(h) => <WeeklyDocument report={h.report} org={org} />}</QueryState> : <QueryState query={cur}>{(c) => <WeeklyDocument report={c.report} org={org} />}</QueryState>
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

export function WeeklyPrintPage() {
  const { t } = useTranslation('reports')
  return <Shell back="/reports" title={t('print.weeklyTitle')}><WeeklyPrint /></Shell>
}

export function PdplPrintPage() {
  const { t } = useTranslation('reports')
  return <Shell back="/reports?tab=pdpl" title={t('print.pdplTitle')}><PdplPrint /></Shell>
}
