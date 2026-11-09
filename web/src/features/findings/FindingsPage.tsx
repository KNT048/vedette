import { useMemo, useState } from 'react'
import { Link, useNavigate, useSearchParams } from 'react-router'
import { useTranslation } from 'react-i18next'
import { X } from 'lucide-react'
import { PageHeader } from '@/components/common/PageHeader'
import { DataTable, type ColumnDef } from '@/components/common/DataTable'
import { EmptyState, QueryState, RequireModule, SampleDataNote } from '@/components/common/States'
import { SeverityChip, StatusChip } from '@/components/common/StatusChip'
import { Button } from '@/components/ui/button'
import { Segmented } from '@/components/ui/segmented'
import { fmtDateTime, fmtRelative } from '@/lib/format'
import { useFindings } from './api'
import { basisKey, isOpen } from './basis'
import type { FindingRow } from './types'

type Filter = 'open' | 'confirmed' | 'suspected' | 'resolved' | 'all'
const match: Record<Filter, (f: FindingRow) => boolean> = {
  open: (f) => isOpen(f.status),
  confirmed: (f) => f.status === 'confirmed',
  suspected: (f) => f.status === 'suspected',
  resolved: (f) => !isOpen(f.status),
  all: () => true,
}

function List() {
  const { t } = useTranslation('findings')
  const navigate = useNavigate()
  const [params, setParams] = useSearchParams()
  const cve = params.get('cve')?.toUpperCase() ?? ''
  const [filter, setFilter] = useState<Filter>('open')
  const q = useFindings()
  const items = q.data?.items
  const open = items?.filter((f) => isOpen(f.status)).length ?? 0
  const confirmed = items?.filter((f) => f.status === 'confirmed').length ?? 0
  const rows = useMemo(() => (items ?? []).filter(match[filter]).filter((f) => !cve || f.cve === cve), [items, filter, cve])

  const columns: ColumnDef<FindingRow>[] = [
    { id: 'device', header: t('col.device'), accessorFn: (r) => r.asset?.hostname ?? r.asset_id, cell: ({ row: { original: r } }) => (
      <div className="grid">
        {r.asset ? <Link to={`/devices/${r.asset.id}`} className="w-fit font-medium text-accent underline-offset-4 hover:underline">{r.asset.hostname ?? r.asset.ip}</Link> : <span className="font-medium">{r.asset_id}</span>}
        <span className="text-[12px] text-muted">{r.asset?.ip}</span>
      </div>
    ) },
    { id: 'cve', header: t('col.cve'), accessorFn: (r) => r.cve, cell: ({ row: { original: r } }) => <Link to={`/findings/${r.id}`} className="whitespace-nowrap font-medium text-accent underline-offset-4 hover:underline">{r.cve}</Link> },
    { id: 'product', header: t('col.product'), accessorFn: (r) => r.kev?.display ?? '', cell: ({ row: { original: r } }) => <span>{r.kev?.display ?? '–'}</span> },
    { id: 'status', header: t('col.status'), accessorFn: (r) => r.status, cell: ({ row: { original: r } }) => <StatusChip status={r.status} /> },
    { id: 'severity', header: t('col.severity'), accessorFn: (r) => ['info', 'low', 'medium', 'high', 'critical'].indexOf(r.severity), cell: ({ row: { original: r } }) => <SeverityChip severity={r.severity} /> },
    { id: 'basis', header: t('col.basis'), accessorFn: (r) => r.basis, cell: ({ row: { original: r } }) => <span className="text-[13px]">{t(basisKey(r.basis))}</span> },
    { id: 'seen', header: t('col.lastSeen'), accessorFn: (r) => r.last_seen, cell: ({ row: { original: r } }) => <span className="whitespace-nowrap text-[13px] text-muted" title={fmtDateTime(r.last_seen)}>{fmtRelative(r.last_seen)}</span> },
  ]

  return (
    <>
      <PageHeader
        title={!items ? t('titleLoading') : open === 0 ? t('titleNone') : t('title', { count: open, confirmed })}
        stories={['S-MIT-1', 'S-SCAN-3']}
        meta={t('intro')}
        actions={<SampleDataNote />}
      />
      <div className="mb-3 flex flex-wrap items-center gap-2">
        <div className="max-w-full overflow-x-auto">
          <Segmented<Filter> label={t('filterLabel')} value={filter} onChange={setFilter} options={(['open', 'confirmed', 'suspected', 'resolved', 'all'] as Filter[]).map((v) => ({ value: v, label: t(`filters.${v}`) }))} />
        </div>
        {cve ? (
          <Button size="sm" onClick={() => { params.delete('cve'); setParams(params) }}><X />{t('clearCve', { cve })}</Button>
        ) : null}
      </div>
      <QueryState query={q}>
        {() => (
          <DataTable
            caption={t('caption')}
            data={rows}
            columns={columns}
            filterPlaceholder={t('filter')}
            initialSort={[{ id: 'severity', desc: true }]}
            onRowClick={(r) => navigate(`/findings/${r.id}`)}
            mobileRow={(r) => (
              <div className="grid gap-1.5">
                <div className="flex items-start justify-between gap-3">
                  <Link to={`/findings/${r.id}`} className="font-medium text-accent underline-offset-4 hover:underline">{r.cve}</Link>
                  <StatusChip status={r.status} />
                </div>
                <span className="text-sm">{r.asset?.hostname ?? r.asset?.ip ?? r.asset_id}<span className="text-muted">{r.asset ? ` (${r.asset.ip})` : ''}</span></span>
                <span className="text-[13px] text-muted">{r.kev?.display ?? '–'}</span>
                <div className="flex flex-wrap items-center gap-x-3 gap-y-1 text-[13px]">
                  <SeverityChip severity={r.severity} />
                  <span>{t(basisKey(r.basis))}</span>
                  <span className="text-muted">{fmtRelative(r.last_seen)}</span>
                </div>
              </div>
            )}
            rowTone={(r) => (r.status === 'confirmed' ? 'danger' : r.status === 'suspected' ? 'warn' : undefined)}
            empty={
              <EmptyState title={cve ? t('emptyCve', { cve }) : filter === 'open' ? t('emptyOpen') : t('emptyFilter')}>
                {t('emptyHelp')}{' '}
                <Link to="/devices" className="text-accent underline underline-offset-4">{t('emptyDevices')}</Link>{' '}
                <Link to="/scans" className="text-accent underline underline-offset-4">{t('emptyScan')}</Link>
              </EmptyState>
            }
          />
        )}
      </QueryState>
    </>
  )
}

export default function FindingsPage() {
  return <RequireModule module="mitigation"><List /></RequireModule>
}
