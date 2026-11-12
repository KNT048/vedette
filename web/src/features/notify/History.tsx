import { Link } from 'react-router'
import { useTranslation } from 'react-i18next'
import { toast } from 'sonner'
import { Section } from '@/components/common/PageHeader'
import { DataTable, type ColumnDef } from '@/components/common/DataTable'
import { EmptyState, QueryState } from '@/components/common/States'
import { Chip } from '@/components/common/StatusChip'
import { Button } from '@/components/ui/button'
import { ApiError } from '@/lib/api'
import { fmtDateTime } from '@/lib/format'
import { useCan } from '@/lib/session'
import { useHistory, useResend } from './api'
import type { HistoryItem } from './types'

/** Settings, Alert channels, History (D-52): every message sent, all kinds. */
export default function History() {
  const { t } = useTranslation('notify')
  const q = useHistory()
  const can = useCan('operator')
  const resend = useResend()
  const columns: ColumnDef<HistoryItem>[] = [
    { id: 'time', header: t('history.col.time'), accessorFn: (r) => r.at, cell: ({ row }) => <span className="whitespace-nowrap">{fmtDateTime(row.original.at)}</span> },
    { id: 'channel', header: t('history.col.channel'), accessorFn: (r) => r.channel, cell: ({ row }) => t(`ch.${row.original.channel}`) },
    { id: 'to', header: t('history.col.to'), accessorFn: (r) => r.to },
    { id: 'what', header: t('history.col.what'), accessorFn: (r) => r.what, cell: ({ row: { original: r } }) => (
      <div className="grid"><Link to={r.link} className="text-accent underline-offset-4 hover:underline">{r.what}</Link><span className="text-[12px] text-muted">{t(`history.kind.${r.kind}`)}</span></div>
    ) },
    { id: 'result', header: t('history.col.result'), accessorFn: (r) => Number(r.ok), cell: ({ row: { original: r } }) => (
      <div className="grid gap-1">{r.ok ? <Chip tone="ok">{t('history.ok')}</Chip> : <Chip tone="warn">{t('history.failed')}</Chip>}{r.error ? <span className="max-w-[48ch] text-[13px]">{r.error}</span> : null}</div>
    ) },
    { id: 'actions', header: t('history.col.actions'), enableSorting: false, cell: ({ row: { original: r } }) => (
      <Button size="sm" disabled={!can || resend.isPending} title={can ? undefined : t('common:needRole', { role: t('common:role.operator') })} aria-label={t('history.resendFor', { channel: t(`ch.${r.channel}`) })}
        onClick={() => resend.mutate(r.id, { onSuccess: (res) => { if (res.ok) toast.success(t('history.resendOk', { channel: t(`ch.${r.channel}`) })); else toast.error(res.error ?? t('history.failed')) }, onError: (e) => toast.error(e instanceof ApiError ? e.message : String(e)) })}>
        {t('history.resend')}
      </Button>
    ) },
  ]
  return (
    <Section id="history" title={t('history.title')} description={`${t('history.description')} ${t('history.retention')}`}>
      <QueryState query={q}>
        {(d) => (
          <>
            <p className="mb-3 max-w-3xl text-[13px] text-muted">{d.suppressed.count > 0 ? t('history.meta', { count: d.suppressed.count, days: d.suppressed.days }) : t('history.metaNone', { days: d.suppressed.days })}</p>
            {d.items.length === 0 ? <EmptyState title={t('history.emptyTitle')}>{t('history.emptyBody')}</EmptyState>
              : <DataTable caption={t('history.caption')} data={d.items} columns={columns} initialSort={[{ id: 'time', desc: true }]} />}
          </>
        )}
      </QueryState>
    </Section>
  )
}
