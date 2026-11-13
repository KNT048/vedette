import { useEffect, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { Section, KeyValue, Panel } from '@/components/common/PageHeader'
import { EmptyState, ErrorState, Loading, QueryState } from '@/components/common/States'
import { Chip } from '@/components/common/StatusChip'
import { SourceBadge } from '@/components/common/SourceBadge'
import { DataTable, type ColumnDef } from '@/components/common/DataTable'
import { Field, Select } from '@/components/ui/input'
import { dateText } from './dates'
import { riskOf } from './services'
import { useDiff, useSnapshot, useSnapshots } from './api'
import { CERT_WARN_DAYS, type AdminRow, type CertRow, type DiffItem, type DiffChange, type HostRow, type PortRow, type Snapshot, type Target } from './types'

const daysLeft = (iso: string) => Math.ceil((new Date(iso).getTime() - Date.now()) / 864e5)

/** Step 3: results by day + comparing two days. */
export function ResultsPanel({ target, blockedText }: { target: Target; blockedText: string | null }) {
  const { t } = useTranslation('exposure')
  const list = useSnapshots(target.id)
  const [date, setDate] = useState<string | null>(null)
  const dates = list.data?.items.map((s) => s.date) ?? []
  const latest = dates[0] ?? null
  // Có ảnh chụp mới nhất (lần quét mới) thì nhảy tới nó.
  useEffect(() => { if (latest) setDate(latest) }, [latest])
  const snap = useSnapshot(target.id, date)

  return (
    <>
      <Section id="results" title={t('results.title')} description={t('results.description')}>
        <QueryState query={list}>
          {(l) => l.items.length === 0 ? (
            <EmptyState title={t('results.emptyTitle')}>{blockedText ?? t('results.emptyBody')}</EmptyState>
          ) : (
            <div className="grid gap-4">
              <Field label={t('results.pick')} htmlFor="ex-snap" className="max-w-xs">
                <Select id="ex-snap" value={date ?? ''} onChange={(e) => setDate(e.target.value)}>
                  {l.items.map((s) => <option key={s.id} value={s.date}>{dateText(s.scanned_at)}</option>)}
                </Select>
              </Field>
              {snap.isPending ? <Loading /> : snap.error ? <ErrorState error={snap.error} onRetry={() => void snap.refetch()} /> : snap.data ? <SnapshotView target={target} s={snap.data} /> : null}
            </div>
          )}
        </QueryState>
      </Section>
      {list.data && list.data.items.length > 0 ? <Compare target={target} dates={dates} label={Object.fromEntries(list.data.items.map((s) => [s.date, dateText(s.scanned_at)]))} /> : null}
    </>
  )
}

function SnapshotView({ target, s }: { target: Target; s: Snapshot }) {
  const { t } = useTranslation('exposure')
  const c = s.counts
  const hostCols: ColumnDef<HostRow>[] = [
    { id: 'name', header: t('col.name'), accessorFn: (r) => r.name },
    { id: 'ip', header: t('col.ip'), accessorFn: (r) => r.ip },
  ]
  const portCols: ColumnDef<PortRow>[] = [
    { id: 'ip', header: t('col.ip'), accessorFn: (r) => r.ip },
    { id: 'port', header: t('col.port'), accessorFn: (r) => r.port, cell: ({ row }) => <span className="tabular-nums">{row.original.port}</span> },
    { id: 'service', header: t('col.service'), accessorFn: (r) => r.service },
    { id: 'product', header: t('col.product'), accessorFn: (r) => r.product ?? '', cell: ({ row }) => row.original.product ?? <span className="text-muted">{t('common:unknown')}</span> },
    { id: 'note', header: t('col.note'), enableSorting: false, cell: ({ row }) => {
      const risk = riskOf(row.original)
      return risk ? <span className="grid gap-1"><Chip tone="warn">{t('open.attacked')}</Chip><span className="text-[12px] text-muted">{t(`risky.${risk}`)} {t('open.purpose')}</span></span> : null
    } },
  ]
  const adminCols: ColumnDef<AdminRow>[] = [
    { id: 'url', header: t('col.url'), accessorFn: (r) => r.url },
    { id: 'product', header: t('col.product'), accessorFn: (r) => r.product },
    { id: 'risk', header: t('col.risk'), accessorFn: (r) => r.risk, cell: ({ row }) => <Chip tone={row.original.risk}>{t(`admin.risk.${row.original.risk}`)}</Chip> },
  ]
  const certCols: ColumnDef<CertRow>[] = [
    { id: 'host', header: t('col.name'), accessorFn: (r) => r.host },
    { id: 'issuer', header: t('col.issuer'), accessorFn: (r) => r.issuer },
    { id: 'expires', header: t('col.expires'), accessorFn: (r) => r.expires_at, cell: ({ row }) => dateText(row.original.expires_at) },
    { id: 'left', header: t('col.left'), accessorFn: (r) => daysLeft(r.expires_at), cell: ({ row }) => {
      const d = daysLeft(row.original.expires_at)
      return d < 0 ? <Chip tone="danger">{t('cert.expired')}</Chip> : d <= 14 ? <Chip tone="danger">{t('cert.left', { count: d })}</Chip> : d <= CERT_WARN_DAYS ? <Chip tone="warn">{t('cert.left', { count: d })}</Chip> : <span className="text-[13px] text-muted">{t('cert.left', { count: d })}</span>
    } },
  ]
  return (
    <div className="grid gap-8">
      <Panel className="p-4">
        <p className="mb-3 flex flex-wrap items-center gap-x-2 text-[13px] text-muted"><SourceBadge source="nmap" at={s.scanned_at} />{t('results.sourceNote')}</p>
        <KeyValue items={[
          ...(target.kind === 'domain' ? [{ label: t('count.subdomains'), value: c.subdomains }] : []),
          { label: t('count.ips'), value: c.ips }, { label: t('count.ports'), value: c.ports },
          { label: t('count.admin'), value: c.admin_panels > 0 ? <Chip tone="danger">{c.admin_panels}</Chip> : 0 },
          { label: t('count.certs'), value: c.certs_expiring > 0 ? <Chip tone="warn">{c.certs_expiring}</Chip> : 0 },
        ]} />
      </Panel>
      {target.kind === 'domain' ? (
        <Section title={t('hosts.title')} description={t('hosts.description')}><DataTable caption={t('hosts.caption')} data={s.hosts} columns={hostCols} pageSize={20} empty={t('hosts.empty')} /></Section>
      ) : null}
      <Section title={t('ports.title')} description={t('ports.description')}><DataTable caption={t('ports.caption')} data={s.ports} columns={portCols} rowTone={(r) => (riskOf(r) ? 'warn' : undefined)} pageSize={20} empty={t('ports.empty')} filterPlaceholder={t('ports.filter')} /></Section>
      <Section title={t('admin.title')} description={t('admin.description')}>
        <DataTable caption={t('admin.caption')} data={s.admin_panels} columns={adminCols} pageSize={20} rowTone={(r) => (r.risk === 'danger' ? 'danger' : 'warn')} empty={<EmptyState title={t('admin.emptyTitle')}>{t('admin.emptyBody')}</EmptyState>} />
      </Section>
      <Section title={t('cert.title')} description={t('cert.description', { days: CERT_WARN_DAYS })}>
        <DataTable caption={t('cert.caption')} data={s.certs} columns={certCols} pageSize={20} initialSort={[{ id: 'expires', desc: false }]} empty={t('cert.empty')} />
      </Section>
    </div>
  )
}

type Row = { change: 'added' | 'removed' | 'changed'; item: DiffItem; from?: string; to?: string }

function Compare({ target, dates, label }: { target: Target; dates: string[]; label: Record<string, string> }) {
  const { t } = useTranslation('exposure')
  const [from, setFrom] = useState<string | null>(null)
  const [to, setTo] = useState<string | null>(null)
  // Danh sách ngày đổi (lần quét mới) thì so sánh lại hai ngày gần nhất.
  useEffect(() => {
    if (dates.length >= 2) { setTo(dates[0]!); setFrom(dates[1]!) }
  }, [dates.join(',')]) // eslint-disable-line react-hooks/exhaustive-deps
  const diff = useDiff(target.id, from, to)

  const columns: ColumnDef<Row>[] = [
    { id: 'change', header: t('diff.col.change'), accessorFn: (r) => r.change, cell: ({ row }) => <Chip tone={row.original.change === 'added' ? 'warn' : 'off'}>{t(`diff.change.${row.original.change}`)}</Chip> },
    { id: 'kind', header: t('diff.col.kind'), accessorFn: (r) => t(`diff.kind.${r.item.kind}`) },
    { id: 'label', header: t('diff.col.item'), accessorFn: (r) => r.item.label },
    { id: 'detail', header: t('diff.col.detail'), accessorFn: (r) => r.item.detail, cell: ({ row }) => row.original.change === 'changed' ? t('diff.certChanged', { from: dateText(row.original.from), to: dateText(row.original.to) }) : row.original.item.detail },
  ]
  const rows: Row[] = diff.data ? [
    ...diff.data.added.map((item): Row => ({ change: 'added', item })),
    ...diff.data.removed.map((item): Row => ({ change: 'removed', item })),
    ...diff.data.changed.map((c: DiffChange): Row => ({ change: 'changed', item: c, from: c.from, to: c.to })),
  ] : []

  return (
    <Section id="compare" title={t('diff.title')} description={t('diff.description')}>
      {dates.length < 2 ? <EmptyState title={t('diff.needTwoTitle')}>{t('diff.needTwoBody')}</EmptyState> : (
        <div className="grid gap-4">
          <div className="flex flex-wrap gap-4">
            <Field label={t('diff.from')} htmlFor="ex-from" className="w-48"><Select id="ex-from" value={from ?? ''} onChange={(e) => setFrom(e.target.value)}>{dates.map((d) => <option key={d} value={d}>{label[d] ?? d}</option>)}</Select></Field>
            <Field label={t('diff.to')} htmlFor="ex-to" className="w-48"><Select id="ex-to" value={to ?? ''} onChange={(e) => setTo(e.target.value)}>{dates.map((d) => <option key={d} value={d}>{label[d] ?? d}</option>)}</Select></Field>
          </div>
          {from === to ? <p role="status" className="text-sm text-warn">{t('diff.sameDate')}</p>
            : diff.isPending ? <Loading /> : diff.error ? <ErrorState error={diff.error} onRetry={() => void diff.refetch()} /> : diff.data ? (
              <>
                <p role="status" className="text-sm font-medium">{t('diff.summary', { added: diff.data.added.length, removed: diff.data.removed.length, changed: diff.data.changed.length, from: label[diff.data.from] ?? diff.data.from, to: label[diff.data.to] ?? diff.data.to })}</p>
                <DataTable caption={t('diff.caption')} data={rows} columns={columns} pageSize={30} rowTone={(r) => (r.change === 'added' && (r.item.kind === 'admin' || r.item.kind === 'port') ? 'warn' : undefined)} empty={t('diff.none')} />
              </>
            ) : null}
        </div>
      )}
    </Section>
  )
}
