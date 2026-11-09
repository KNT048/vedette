import { Link, useParams } from 'react-router'
import { useTranslation } from 'react-i18next'
import { ArrowLeft, Printer } from 'lucide-react'
import { EmptyState, QueryState } from '@/components/common/States'
import { Button } from '@/components/ui/button'
import { useMe } from '@/lib/session'
import { useHistoryEntry, usePdpl, useWeekly } from './api'
import { PdplDocument } from './PdplDocument'
import { WeeklyDocument } from './WeeklyDocument'

// Chỉ vùng .print-doc được in; thanh bên, thanh công cụ, toast bị ẩn. Người dùng chọn "Lưu thành PDF" trong hộp thoại in của trình duyệt.
const PRINT_CSS = `
@media print {
  body * { visibility: hidden !important; }
  .print-doc, .print-doc * { visibility: visible !important; }
  .print-doc { position: absolute; left: 0; top: 0; width: 100%; background: #fff; color: #111; padding: 0 !important; border: 0 !important; }
  .print-doc * { color: #111 !important; border-color: #bbb !important; background-color: transparent !important; }
  .no-print { display: none !important; }
  @page { size: A4; margin: 16mm; }
}`

function Shell({ back, title, children }: { back: string; title: string; children: React.ReactNode }) {
  const { t } = useTranslation('reports')
  return (
    <>
      <style>{PRINT_CSS}</style>
      <h1 className="no-print mb-3 text-xl font-semibold">{title}</h1>
      <div className="no-print mb-4 flex flex-wrap items-center justify-between gap-3">
        <Link to={back} className="inline-flex items-center gap-1 text-[13px] text-muted hover:text-ink"><ArrowLeft className="size-3.5" aria-hidden />{t('print.back')}</Link>
        <div className="flex flex-wrap items-center gap-3">
          <p className="text-[13px] text-muted">{t('print.hint')}</p>
          <Button variant="primary" onClick={() => window.print()}><Printer aria-hidden />{t('print.button')}</Button>
        </div>
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
