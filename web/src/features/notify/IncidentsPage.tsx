import { useState } from 'react'
import { Link, useNavigate } from 'react-router'
import { useTranslation } from 'react-i18next'
import { PageHeader, Section } from '@/components/common/PageHeader'
import { DataTable, type ColumnDef } from '@/components/common/DataTable'
import { EmptyState, QueryState, RequireModule, SampleDataNote } from '@/components/common/States'
import { SeverityChip } from '@/components/common/StatusChip'
import { Segmented } from '@/components/ui/segmented'
import { fmtDateTime } from '@/lib/format'
import { useCan } from '@/lib/session'
import { useChannels, useIncidents } from './api'
import { DeliveryBadges, IncidentStatusChip } from './shared'
import { INCIDENT_KINDS, type Incident, type IncidentKind } from './types'

const link = 'text-accent underline-offset-4 hover:underline'

function Seen({ i }: { i: Incident }) {
  const { t } = useTranslation('notify')
  return <span className="whitespace-nowrap text-[13px]">{i.first_seen === i.last_seen ? t('incidents.seenOnce', { first: fmtDateTime(i.first_seen) }) : t('incidents.seen', { first: fmtDateTime(i.first_seen), last: fmtDateTime(i.last_seen) })}</span>
}
function Handled({ i }: { i: Incident }) {
  const { t } = useTranslation('notify')
  return <div className="grid gap-0.5"><IncidentStatusChip status={i.status} />{i.handled_by ? <span className="text-[12px] text-muted">{t('incidents.statusBy', { user: i.handled_by, time: fmtDateTime(i.handled_at) })}</span> : null}</div>
}
function RespondLink({ i }: { i: Incident }) {
  const { t } = useTranslation('notify')
  return <Link to={`/response?incident=${encodeURIComponent(i.id)}`} onClick={(e) => e.stopPropagation()} aria-label={t('incidents.respondFor', { title: i.title })} className={`${link} whitespace-nowrap`}>{t('incidents.respond')}</Link>
}

function Content() {
  const { t } = useTranslation('notify')
  const navigate = useNavigate()
  const q = useIncidents()
  // the link to set up channels only while none is on; the list is the admin's, so others (403) see no link to a page they cannot open
  const admin = useCan('admin')
  const channels = useChannels({ retry: false, enabled: admin }) // not asked of a role that would get 403
  const noChannel = channels.data !== undefined && !channels.data.channels.some((c) => c.enabled)
  const [filter, setFilter] = useState<'open' | 'all'>('open')
  const [kind, setKind] = useState<IncidentKind | 'all'>('all')
  const fresh = q.data?.incidents.filter((a) => a.status === 'new').length ?? 0
  const title = !q.data ? t('incidents.titleLoading') : fresh === 0 ? t('incidents.titleNone') : t('incidents.title', { count: fresh })
  const columns: ColumnDef<Incident>[] = [
    { id: 'incident', header: t('incidents.col.incident'), accessorFn: (r) => r.title, cell: ({ row: { original: r } }) => (
      <div className="grid"><Link to={`/incidents/${r.id}`} onClick={(e) => e.stopPropagation()} className={`font-medium ${link}`}>{r.title}</Link><span className="text-[12px] text-muted">{t(`incidents.kind.${r.kind}`)}</span></div>
    ) },
    { id: 'severity', header: t('incidents.col.severity'), accessorFn: (r) => ['info', 'low', 'medium', 'high', 'critical'].indexOf(r.severity), cell: ({ row }) => <SeverityChip severity={row.original.severity} /> },
    { id: 'device', header: t('incidents.col.device'), accessorFn: (r) => r.devices.map((d) => d.name).join(', '), cell: ({ row: { original: r } }) => (
      <span className="flex flex-wrap gap-x-2">{r.devices.map((d) => <Link key={d.id} to={`/devices/${d.id}`} onClick={(e) => e.stopPropagation()} className={link}>{d.name}</Link>)}</span>
    ) },
    { id: 'status', header: t('incidents.col.status'), accessorFn: (r) => r.status, cell: ({ row }) => <Handled i={row.original} /> },
    { id: 'seen', header: t('incidents.col.seen'), accessorFn: (r) => r.last_seen, cell: ({ row }) => <Seen i={row.original} /> },
    { id: 'count', header: t('incidents.col.count'), accessorFn: (r) => r.count, cell: ({ row }) => t('incidents.times', { count: row.original.count }) },
    { id: 'sent', header: t('incidents.col.sent'), enableSorting: false, cell: ({ row }) => <DeliveryBadges sends={row.original.sends} /> },
    { id: 'respond', header: t('incidents.col.respond'), enableSorting: false, cell: ({ row }) => <RespondLink i={row.original} /> },
  ]
  return (
    <>
      <PageHeader title={title} stories={['S-ALERT-3']} meta={q.data ? <span className="inline-flex flex-wrap items-center gap-2">{t('incidents.meta')} {t('incidents.retention')}<SampleDataNote /></span> : null} />
      <QueryState query={q}>
        {(d) => {
          const rows = d.incidents.filter((a) => (filter === 'all' || a.status !== 'resolved') && (kind === 'all' || a.kind === kind))
          return (
            <Section id="list" title={t('incidents.caption')}>
              <div className="mb-3 flex flex-wrap gap-2">
                <Segmented className="max-w-full overflow-x-auto" label={t('incidents.kindFilter')} value={kind} onChange={setKind} options={[{ value: 'all', label: t('incidents.kf.all') }, ...INCIDENT_KINDS.map((k) => ({ value: k, label: t(`incidents.kf.${k}`) }))]} />
                <Segmented className="max-w-full overflow-x-auto" label={t('incidents.filter')} value={filter} onChange={setFilter} options={[{ value: 'open', label: t('incidents.open') }, { value: 'all', label: t('incidents.all') }]} />
              </div>
              {rows.length === 0 ? (
                <EmptyState title={filter === 'open' ? t('incidents.emptyOpenTitle') : t('incidents.emptyAllTitle')} action={noChannel ? <Link to="/settings/channels" className={link}>{t('incidents.setupChannels')}</Link> : undefined}>{t('incidents.emptyBody')}</EmptyState>
              ) : (
                <DataTable caption={t('incidents.caption')} data={rows} columns={columns} onRowClick={(r) => navigate(`/incidents/${r.id}`)} rowTone={(r) => (r.status === 'new' ? (r.severity === 'critical' ? 'danger' : 'warn') : undefined)} initialSort={[{ id: 'seen', desc: true }]}
                  mobileRow={(r) => (
                    <div className="grid gap-1.5">
                      <div className="flex items-start justify-between gap-3">
                        <Link to={`/incidents/${r.id}`} onClick={(e) => e.stopPropagation()} className={`font-medium ${link}`}>{r.title}</Link>
                        <SeverityChip severity={r.severity} />
                      </div>
                      <p className="text-[13px] text-muted">{t(`incidents.kind.${r.kind}`)}, {r.devices.map((x) => x.name).join(', ')}, {t('incidents.times', { count: r.count })}</p>
                      <div className="flex flex-wrap items-center gap-x-3 gap-y-1 text-[13px]"><Handled i={r} /><DeliveryBadges sends={r.sends} /><Seen i={r} /></div>
                      <div><RespondLink i={r} /></div>
                    </div>
                  )} />
              )}
            </Section>
          )
        }}
      </QueryState>
    </>
  )
}

export default function IncidentsPage() {
  return <RequireModule module="notify"><Content /></RequireModule>
}
