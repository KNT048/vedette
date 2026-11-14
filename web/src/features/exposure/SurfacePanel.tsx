import { useTranslation } from 'react-i18next'
import { KeyValue, Notice, Panel, Section } from '@/components/common/PageHeader'
import { EmptyState, ErrorState, Loading, QueryState } from '@/components/common/States'
import { Chip, type Tone } from '@/components/common/StatusChip'
import { DataTable, type ColumnDef } from '@/components/common/DataTable'
import { dateText } from './dates'
import { useSnapshot, useSnapshots } from './api'
import type { HostClass, HostIp, HostRow, Snapshot, Target } from './types'

// S-EXP-1, INV-27 (D-567): the surface of a verified domain from its newest scan: names, then their addresses, CNAME and where each
// name was found. What serves a name (a CDN or not) does not matter (kien 2026-11-14); each address says what the scan does with it.
const CLASSES: HostClass[] = ['box', 'public', 'private']
const TONE: Record<HostClass, Tone> = { box: 'ok', public: 'accent', private: 'off' }
const SURFACE_LINES = new Set(['wordlist', 'by_name', 'address_family'])

export function SurfacePanel({ target, blockedText }: { target: Target; blockedText: string | null }) {
  const { t } = useTranslation('exposure')
  const list = useSnapshots(target.id)
  const latest = list.data?.items[0]?.date ?? null
  const snap = useSnapshot(target.id, latest)
  return (
    <Section id="surface" title={t('surface.title')} description={t('surface.description')} stories={['S-EXP-1']}>
      <QueryState query={list}>
        {(l) => l.items.length === 0 ? <EmptyState title={t('results.emptyTitle')}>{blockedText ?? t('surface.emptyBody')}</EmptyState>
          : snap.isPending ? <Loading /> : snap.error ? <ErrorState error={snap.error} onRetry={() => void snap.refetch()} /> : snap.data ? <SurfaceView s={snap.data} /> : null}
      </QueryState>
    </Section>
  )
}

function SurfaceView({ s }: { s: Snapshot }) {
  const { t } = useTranslation('exposure')
  const ips = s.hosts.flatMap((h) => h.ips ?? [])
  const count = (c: HostClass) => ips.filter((a) => a.class === c && a.family === 'ipv4').length
  const classified = s.hosts.some((h) => h.source)
  const lines = s.not_checked.filter((n) => SURFACE_LINES.has(n.kind))
  const cols: ColumnDef<HostRow>[] = [
    { id: 'name', header: t('col.name'), accessorFn: (r) => r.name, cell: ({ row }) => (
      <span className="grid gap-1">
        <span className="break-all">{row.original.name}</span>
        {row.original.source ? <span className="text-[12px] text-muted">{t(`surface.source.${row.original.source}`)}</span> : null}
      </span>
    ) },
    { id: 'cname', header: t('surface.col.cname'), accessorFn: (r) => r.cname ?? '', cell: ({ row }) => row.original.cname ? <span className="break-all text-[13px]">{row.original.cname}</span> : <span className="text-muted">{t('surface.none')}</span> },
    { id: 'ips', header: t('surface.col.addresses'), enableSorting: false, cell: ({ row }) => <Addresses h={row.original} /> },
  ]
  return (
    <div className="grid gap-6">
      <Panel className="p-4">
        <p className="mb-3 text-[13px] text-muted">{t('surface.from', { date: dateText(s.scanned_at) })}</p>
        <KeyValue items={[
          { label: t('surface.count.names'), value: s.hosts.length },
          { label: t('count.ips'), value: s.counts.ips },
          ...CLASSES.map((c) => ({ label: t(`surface.count.${c}`), value: count(c) })),
          { label: t('surface.count.ipv6'), value: ips.filter((a) => a.family === 'ipv6').length },
        ]} />
      </Panel>
      {!classified && s.hosts.length > 0 ? <Notice tone="off" role="note" title={t('surface.older')} /> : null}
      <DataTable caption={t('surface.caption')} data={s.hosts} columns={cols} pageSize={30} empty={t('hosts.empty')} filterPlaceholder={t('surface.filter')} />
      {lines.length > 0 ? (
        <div>
          <h3 className="mb-2 text-sm font-semibold">{t('checked.notChecked')}</h3>
          <ul aria-label={t('surface.notChecked')} className="grid gap-1 text-sm">{lines.map((n, i) => <li key={i}>{n.text}</li>)}</ul>
        </div>
      ) : null}
    </div>
  )
}

function Addresses({ h }: { h: HostRow }) {
  const { t } = useTranslation('exposure')
  if (!h.source) return <span className="text-[13px]">{h.ip || t('surface.none')}</span>
  if (!h.ips || h.ips.length === 0) return <span className="text-[13px] text-muted">{h.cname ? t('surface.dangling') : t('surface.noAddress')}</span>
  return <ul className="grid gap-1.5">{h.ips.map((a) => <li key={a.ip} className="grid gap-0.5"><Address a={a} /></li>)}</ul>
}

function Address({ a }: { a: HostIp }) {
  const { t } = useTranslation('exposure')
  return (
    <>
      <span className="flex flex-wrap items-center gap-2"><span className="break-all font-mono text-[13px]">{a.ip}</span><Chip tone={TONE[a.class]}>{t(`surface.class.${a.class}`)}</Chip></span>
      <span className="text-[12px] text-muted">
        {a.family === 'ipv6' && a.class !== 'private' ? t('surface.ipv6') : t(`surface.note.${a.class}`)}
      </span>
    </>
  )
}
