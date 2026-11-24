import { Link, useNavigate } from 'react-router'
import { useTranslation } from 'react-i18next'
import { DataTable } from '@/components/common/DataTable'
import { EmptyState, QueryState } from '@/components/common/States'
import { Chip } from '@/components/common/StatusChip'
import { fmtDate, fmtDateTime, fmtPeriodEnd } from '@/lib/format'
import { useCan } from '@/lib/session'
import { useSentList } from './api'
import type { SentReportItem } from './types'

export const sentPath = (id: string) => `/reports/sent/${encodeURIComponent(id)}`

/** The reports sent, newest first; each opens exactly as it was sent. */
export default function HistoryTab() {
  const { t } = useTranslation('reports')
  const list = useSentList()
  const navigate = useNavigate()
  const admin = useCan('admin') // the email channel is an administrator's page: no link for anyone else
  type Row = SentReportItem
  return (
    <QueryState query={list}>
      {(h) => h.items.length === 0 ? <EmptyState title={t('history.empty')}>{t('history.emptyBody')}</EmptyState> : (
        <DataTable<Row> urlKey="report-history" caption={t('history.caption')} data={h.items} initialSort={[{ id: 'sent', desc: true }]}
          onRowClick={(r) => void navigate(sentPath(r.id))}
          rowTone={(r) => (r.status === 'failed' ? 'warn' : undefined)}
          columns={[
            { id: 'sent', header: t('history.col.sent'), accessorKey: 'sent_at', cell: ({ row }: { row: { original: Row } }) => (
              <Link to={sentPath(row.original.id)} onClick={(e) => e.stopPropagation()} aria-label={t('history.openLabel', { time: fmtDateTime(row.original.sent_at) })}
                className="whitespace-nowrap font-medium text-accent underline-offset-4 hover:underline">{fmtDateTime(row.original.sent_at)}</Link>
            ) },
            { id: 'period', header: t('history.col.period'), accessorFn: (r: Row) => r.period.from, cell: ({ row }: { row: { original: Row } }) => <span className="whitespace-nowrap">{fmtDate(row.original.period.from)} – {fmtPeriodEnd(row.original.period.to)}</span> },
            { id: 'trigger', header: t('history.col.trigger'), accessorFn: (r: Row) => (r.trigger === 'schedule' ? t('history.trigger.schedule') : r.sent_by ? t('history.trigger.manual', { by: r.sent_by }) : t('history.trigger.manualUnnamed')) },
            { id: 'to', header: t('history.col.to'), accessorFn: (r: Row) => r.recipients.length, cell: ({ row }: { row: { original: Row } }) => <span title={row.original.recipients.join(', ')}>{t('history.people', { count: row.original.recipients.length })}</span> },
            { id: 'status', header: t('history.col.status'), accessorKey: 'status', cell: ({ row }: { row: { original: Row } }) => row.original.status === 'sent'
              ? <Chip tone="ok">{t('history.sent')}</Chip>
              : (
                <span className="grid gap-1">
                  <Chip tone="warn">{t('history.failed')}</Chip>
                  {row.original.error ? <span className="max-w-xs whitespace-normal text-caption text-muted">{row.original.error}</span> : null}
                  {admin ? <Link to="/settings/channels#channel-email" onClick={(e) => e.stopPropagation()} className="w-fit text-caption text-accent underline-offset-4 hover:underline">{t('history.openChannel')}</Link> : null}
                </span>
              ) },
          ]} />
      )}
    </QueryState>
  )
}
