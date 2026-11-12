import { useMemo, useState } from 'react'
import { Link, useNavigate } from 'react-router'
import { useTranslation } from 'react-i18next'
import { toast } from 'sonner'
import { Download, Plus, Settings2, Upload } from 'lucide-react'
import { PageHeader } from '@/components/common/PageHeader'
import { DataTable, type ColumnDef } from '@/components/common/DataTable'
import { EmptyState, ModuleOff, QueryState, RequireModule, SampleDataNote } from '@/components/common/States'
import { SourceBadge } from '@/components/common/SourceBadge'
import { Chip } from '@/components/common/StatusChip'
import { Button, buttonVariants } from '@/components/ui/button'
import { Segmented } from '@/components/ui/segmented'
import { download } from '@/lib/api'
import { fmtDateTime, fmtRelative } from '@/lib/format'
import { useCan } from '@/lib/session'
import { cn } from '@/lib/utils'
import { AddDeviceDialog } from './AddDeviceDialog'
import { useDevices, useSettings } from './api'
import { ImportDialog } from './ImportDialog'
import { errMsg, KIND_ICON } from './kinds'
import { nameOf } from './nameOf'
import { PendingPanel } from './PendingPanel'
import type { DeviceRow } from './types'

type Filter = 'all' | 'pending' | 'fragile' | 'manual'

function DevicesTable({ items, filter }: { items: DeviceRow[]; filter: Filter }) {
  const { t } = useTranslation('inventory')
  const navigate = useNavigate()
  const shown = useMemo(() => items.filter((d) => (filter === 'pending' ? !d.approved : filter === 'fragile' ? d.fragile : filter === 'manual' ? d.origin === 'manual' : true)), [items, filter])
  const dash = <span className="text-muted">–</span>
  const columns: ColumnDef<DeviceRow>[] = [
    { id: 'name', header: t('col.name'), accessorFn: (d) => nameOf(d, t(`kind.${d.kind}`)), cell: ({ row }) => {
      const d = row.original
      return (
        <div className="flex flex-wrap items-center gap-x-2 gap-y-1">
          <Link to={`/devices/${d.id}`} onClick={(e) => e.stopPropagation()} className="font-medium text-accent underline-offset-4 hover:underline">{nameOf(d, t(`kind.${d.kind}`))}</Link>
          {d.is_box ? <Chip tone="accent" title={t('box.noDelete')}>{t('box.badge')}</Chip> : null}
          {!d.approved ? <Chip tone="warn">{t('chip.pending')}</Chip> : null}
          {d.suspicious ? <Chip tone="warn">{t('chip.suspicious')}</Chip> : null}
          {d.fragile ? <Chip tone="off" title={t('chip.fragileHint')}>{t('chip.fragile')}</Chip> : null}
        </div>
      )
    } },
    { id: 'ip', header: t('col.ip'), accessorFn: (d) => d.ip, cell: ({ row }) => <span className="whitespace-nowrap">{row.original.ip}</span> },
    { id: 'kind', header: t('col.kind'), accessorFn: (d) => t(`kind.${d.kind}`), cell: ({ row }) => {
      const Icon = KIND_ICON[row.original.kind]
      return <span className="inline-flex items-center gap-1.5 whitespace-nowrap"><Icon className="size-4 text-muted" aria-hidden />{t(`kind.${row.original.kind}`)}</span>
    } },
    { id: 'hw', header: t('col.hardware'), accessorFn: (d) => [d.vendor?.value, d.model?.value].filter(Boolean).join(' '), cell: ({ getValue }) => (getValue() as string) || dash },
    { id: 'os', header: t('col.os'), accessorFn: (d) => d.os?.value ?? '', cell: ({ getValue }) => (getValue() as string) || dash },
    { id: 'source', header: t('col.source'), accessorFn: (d) => d.summary?.confidence ?? -1, cell: ({ row }) => (row.original.summary ? <SourceBadge source={row.original.summary.source} confidence={row.original.summary.confidence} /> : dash) },
    { id: 'seen', header: t('col.lastSeen'), accessorFn: (d) => new Date(d.last_seen).getTime(), cell: ({ row }) => <time className="whitespace-nowrap text-[13px] text-muted" dateTime={row.original.last_seen} title={fmtDateTime(row.original.last_seen)}>{fmtRelative(row.original.last_seen)}</time> },
  ]
  return (
    <DataTable caption={t('table.caption')} data={shown} columns={columns} filterPlaceholder={t('table.search')} initialSort={[{ id: 'seen', desc: true }]}
      onRowClick={(d) => void navigate(`/devices/${d.id}`)} rowTone={(d) => (!d.approved ? 'warn' : undefined)}
      empty={t(`table.empty.${filter}`)}
      mobileRow={(d) => {
        const Icon = KIND_ICON[d.kind]
        const hw = [d.vendor?.value, d.model?.value].filter(Boolean).join(' ')
        return (
          <div className="grid gap-1.5">
            <div className="flex flex-wrap items-center gap-x-2 gap-y-1">
              <Link to={`/devices/${d.id}`} className="min-w-0 font-medium [overflow-wrap:anywhere] text-accent underline-offset-4 hover:underline">{nameOf(d, t(`kind.${d.kind}`))}</Link>
              {d.is_box ? <Chip tone="accent">{t('box.badge')}</Chip> : null}
              {!d.approved ? <Chip tone="warn">{t('chip.pending')}</Chip> : null}
              {d.suspicious ? <Chip tone="warn">{t('chip.suspicious')}</Chip> : null}
              {d.fragile ? <Chip tone="off" title={t('chip.fragileHint')}>{t('chip.fragile')}</Chip> : null}
            </div>
            <div className="flex flex-wrap items-center gap-x-3 gap-y-1 text-[13px] text-muted">
              <span className="inline-flex items-center gap-1.5"><Icon className="size-4" aria-hidden />{t(`kind.${d.kind}`)}</span>
              {d.ip && d.ip !== '—' ? <span>{d.ip}</span> : null}
              {hw ? <span className="min-w-0 [overflow-wrap:anywhere]">{hw}</span> : null}
            </div>
            <div className="flex flex-wrap items-center gap-x-3 gap-y-1 text-[12px] text-muted">
              {d.summary ? <SourceBadge source={d.summary.source} confidence={d.summary.confidence} /> : null}
              <time dateTime={d.last_seen}>{fmtRelative(d.last_seen)}</time>
            </div>
          </div>
        )
      }} />
  )
}

function Body() {
  const { t } = useTranslation('inventory')
  const q = useDevices()
  const canOp = useCan('operator')
  const canAdmin = useCan('admin')
  const hasRanges = (useSettings().data?.lan_ranges.length ?? 0) > 0 // a range is saved: the empty state must not ask for one again
  const [filter, setFilter] = useState<Filter>('all')
  const [adding, setAdding] = useState(false)
  const [importing, setImporting] = useState(false)
  const c = q.data?.counts
  const needRole = canOp ? undefined : t('common:needRole', { role: t('common:role.operator') })
  const title = !c ? t('list.titleLoading') : c.all === 0 ? t('list.titleEmpty') : c.pending > 0 ? t('list.title', { count: c.all, pending: c.pending }) : t('list.titleAllApproved', { count: c.all })

  return (
    <>
      <PageHeader title={title} stories={['S-INV-1', 'S-INV-2', 'S-INV-3']}
        meta={<span className="inline-flex flex-wrap items-center gap-2"><SampleDataNote />{t('list.meta')}</span>}
        actions={
          <>
            <Button variant="primary" disabled={!canOp} title={needRole} onClick={() => setAdding(true)}><Plus />{t('add.open')}</Button>
            <Button disabled={!canOp} title={needRole} onClick={() => setImporting(true)}><Upload />{t('import.open')}</Button>
            <Button onClick={() => void download('/inventory/export.csv', 'vedette-devices.csv').catch((e: unknown) => toast.error(errMsg(e)))}><Download />{t('export')}</Button>
            {canAdmin ? <Link to="/devices/setup" className={cn(buttonVariants({ variant: 'secondary' }))}><Settings2 />{t('setup.link')}</Link> : null}
          </>
        } />
      <QueryState query={q}>
        {(d) => d.counts.all === 0 ? (
          <EmptyState title={t('empty.title')} action={<div className="flex flex-wrap gap-2"><Button variant="primary" disabled={!canOp} title={needRole} onClick={() => setAdding(true)}>{t('add.open')}</Button><Button disabled={!canOp} title={needRole} onClick={() => setImporting(true)}>{t('import.open')}</Button>{canAdmin && !hasRanges ? <Link to="/devices/setup" className={cn(buttonVariants({ variant: 'secondary' }))}>{t('empty.range')}</Link> : null}</div>}>{t(hasRanges ? 'empty.bodyWatching' : 'empty.body')}</EmptyState>
        ) : (
          <>
            {d.items.length === 1 && d.items[0]?.is_box ? (
              <div className="mb-6"><EmptyState title={t('empty.title')} action={<div className="flex flex-wrap gap-2"><Button variant="primary" disabled={!canOp} title={needRole} onClick={() => setAdding(true)}>{t('add.open')}</Button><Button disabled={!canOp} title={needRole} onClick={() => setImporting(true)}>{t('import.open')}</Button>{canAdmin && !hasRanges ? <Link to="/devices/setup" className={cn(buttonVariants({ variant: 'secondary' }))}>{t('empty.range')}</Link> : null}</div>}>{t(hasRanges ? 'empty.bodyBoxOnlyWatching' : 'empty.bodyBoxOnly')}</EmptyState></div>
            ) : null}
            <PendingPanel data={d} />
            <section aria-labelledby="all-title">
              <div className="mb-3 flex flex-wrap items-center justify-between gap-3">
                <h2 id="all-title" className="text-base font-semibold">{t('list.all')}</h2>
                <Segmented<Filter> label={t('filter.label')} value={filter} onChange={setFilter} options={[
                  { value: 'all', label: t('filter.all', { count: d.counts.all }) },
                  { value: 'pending', label: t('filter.pending', { count: d.counts.pending }) },
                  { value: 'fragile', label: t('filter.fragile', { count: d.counts.fragile }) },
                  { value: 'manual', label: t('filter.manual', { count: d.counts.manual }) },
                ]} />
              </div>
              <DevicesTable items={d.items} filter={filter} />
            </section>
          </>
        )}
      </QueryState>
      <AddDeviceDialog open={adding} onOpenChange={setAdding} />
      <ImportDialog open={importing} onOpenChange={setImporting} />
    </>
  )
}

export default function DevicesPage() {
  const { t } = useTranslation('inventory')
  return (
    <RequireModule module="inventory" fallback={<><PageHeader title={t('off.title')} /><ModuleOff module="inventory">{t('off.body')}</ModuleOff></>}>
      <Body />
    </RequireModule>
  )
}
