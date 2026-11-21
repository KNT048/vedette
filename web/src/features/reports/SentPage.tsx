import { useParams } from 'react-router'
import { useTranslation } from 'react-i18next'
import { Printer } from 'lucide-react'
import { Notice, PageHeader } from '@/components/common/PageHeader'
import { QueryState } from '@/components/common/States'
import { Button } from '@/components/ui/button'
import { fmtDateTime } from '@/lib/format'
import { useMe } from '@/lib/session'
import { useSentReport } from './api'
import { Paper } from './ReportTab'
import { SecurityReport } from './SecurityReport'

/** One sent report, exactly as it went out (the stored document, not today's figures), with Print. */
export default function SentPage() {
  const { t } = useTranslation('reports')
  const { id = '' } = useParams()
  const q = useSentReport(id)
  const { data: me } = useMe()
  return (
    <QueryState query={q}>
      {(r) => (
        <>
          <div className="no-print">
            <PageHeader breadcrumbs={[{ label: t('nav.reports'), to: '/reports' }, { label: t('page.history'), to: '/reports?tab=history' }]}
              title={t('history.page.title', { title: r.title, time: fmtDateTime(r.sent_at) })}
              meta={t('history.page.meta', { to: r.recipients.join(', ') })}
              actions={<Button variant="primary" onClick={() => window.print()}><Printer aria-hidden />{t('print.button')}</Button>} />
            {r.status === 'failed' ? <Notice tone="warn" role="status" title={t('history.page.failed', { error: r.error ?? '' })} className="mx-auto max-w-[210mm]" /> : null}
          </div>
          <Paper><SecurityReport doc={r.document} org={me?.org ?? ''} /></Paper>
        </>
      )}
    </QueryState>
  )
}
