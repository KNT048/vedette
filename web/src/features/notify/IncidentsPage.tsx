import { useRef, useState, type MouseEvent, type RefObject } from 'react'
import { Link, useNavigate } from 'react-router'
import { useTranslation } from 'react-i18next'
import { toast } from 'sonner'
import { PageHeader, Section } from '@/components/common/PageHeader'
import { DataTable, type ColumnDef } from '@/components/common/DataTable'
import { EmptyState, QueryState, RequireModule, SampleDataNote } from '@/components/common/States'
import { SeverityChip } from '@/components/common/StatusChip'
import { Button } from '@/components/ui/button'
import { Checkbox } from '@/components/ui/checkbox'
import { Dialog, DialogContent, DialogFooter } from '@/components/ui/dialog'
import { Field, Textarea } from '@/components/ui/input'
import { Segmented } from '@/components/ui/segmented'
import { ApiError } from '@/lib/api'
import { fmtDateTime } from '@/lib/format'
import { useModules } from '@/lib/modules'
import { useCan } from '@/lib/session'
import { useBulkIncidents, useChannels, useIncidents } from './api'
import { MAX_BULK_INCIDENTS } from './contract'
import { DeliveryBadges, IncidentStatusChip, kindKey } from './shared'
import { INCIDENT_KINDS, type Incident, type IncidentKind } from './types'

const link = 'text-accent underline-offset-4 hover:underline'
type BulkStatus = 'acknowledged' | 'resolved'

/** Một trạng thái, một ghi chú cho các incident đã chọn (D-551, INV-25): mỗi incident vẫn có dòng kiểm toán riêng; incident đã Resolved giữ nguyên. */
function BulkDialog({ ids, status, onOpenChange, opener, onDone }: { ids: string[]; status: BulkStatus | null; onOpenChange: (v: boolean) => void; opener: RefObject<HTMLButtonElement | null>; onDone: () => void }) {
  const { t } = useTranslation('notify')
  const bulk = useBulkIncidents()
  const [note, setNote] = useState('')
  const [error, setError] = useState<string | undefined>()
  const [was, setWas] = useState(status)
  if (status !== was) { setWas(status); if (status) { setNote(''); setError(undefined) } }
  function submit() {
    if (!status) return
    bulk.mutate({ ids, status, ...(note.trim() ? { note: note.trim() } : {}) }, {
      onSuccess: (r) => {
        const parts = [t(`bulk.done.${status}`, { count: r.updated })]
        if (r.already_resolved > 0) parts.push(t('bulk.alreadyResolved', { count: r.already_resolved }))
        if (r.already_acknowledged > 0) parts.push(t('bulk.alreadyAcknowledged', { count: r.already_acknowledged }))
        toast.success(parts.join('. '))
        onOpenChange(false)
        onDone()
      },
      onError: (e) => setError(e instanceof ApiError ? e.message : String(e)),
    })
  }
  return (
    <Dialog open={status !== null} onOpenChange={onOpenChange}>
      <DialogContent title={status ? t(`bulk.title.${status}`, { count: ids.length }) : ''} description={t('bulk.description')} onCloseAutoFocus={(e) => { e.preventDefault(); opener.current?.focus() }}>
        <Field htmlFor="bulk-inc-note" label={t('detail.note')} hint={t('bulk.noteHint')} error={error}>
          <Textarea id="bulk-inc-note" value={note} maxLength={500} onChange={(e) => setNote(e.target.value)} placeholder={t('detail.notePlaceholder')} />
        </Field>
        <DialogFooter>
          <Button onClick={() => onOpenChange(false)}>{t('common:cancel')}</Button>
          <Button variant="primary" disabled={bulk.isPending} onClick={submit}>{status ? t(`bulk.submit.${status}`, { count: ids.length }) : null}</Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}

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
  // a container-only install cannot run the honeypot (module state available=false, D-381): no trap can be touched, so no trap filter
  const noTraps = useModules().data?.modules.find((m) => m.id === 'honeypot')?.available === false
  const kinds = INCIDENT_KINDS.filter((k) => k !== 'trap' || !noTraps)
  const can = useCan('operator')
  const [selected, setSelected] = useState<ReadonlySet<string>>(new Set())
  const [bulk, setBulk] = useState<BulkStatus | null>(null)
  const opener = useRef<HTMLButtonElement>(null)
  const fresh = q.data?.incidents.filter((a) => a.status === 'new').length ?? 0
  const title = !q.data ? t('incidents.titleLoading') : fresh === 0 ? t('incidents.titleNone') : t('incidents.title', { count: fresh })
  const rows = (q.data?.incidents ?? []).filter((a) => (filter === 'all' || a.status !== 'resolved') && (kind === 'all' || a.kind === kind))
  // Only what is shown can stay selected: changing a filter never acts on hidden rows (as on Findings, D-484).
  const shown = rows.filter((r) => selected.has(r.id)).map((r) => r.id)
  const allShown = rows.length > 0 && shown.length === rows.length
  const toggle = (id: string, on: boolean) => setSelected((s) => { const n = new Set(s); if (on) n.add(id); else n.delete(id); return n })
  const pick = (r: Incident) => (
    // A click on the box selects; it never opens the incident (the row click does).
    <span onClick={(e) => e.stopPropagation()} className="inline-flex">
      <Checkbox checked={selected.has(r.id)} onCheckedChange={(v) => toggle(r.id, v === true)} aria-label={t('bulk.select', { title: r.title })} />
    </span>
  )
  const open = (s: BulkStatus) => (e: MouseEvent<HTMLButtonElement>) => { opener.current = e.currentTarget; setBulk(s) }
  const columns: ColumnDef<Incident>[] = [
    ...(can ? [{ id: 'select', enableSorting: false, header: () => <Checkbox checked={allShown ? true : shown.length > 0 ? 'indeterminate' : false} onCheckedChange={(v) => setSelected(v === true ? new Set(rows.map((r) => r.id)) : new Set())} aria-label={t('bulk.selectAll', { count: rows.length })} />, cell: ({ row: { original: r } }) => pick(r) } satisfies ColumnDef<Incident>] : []),
    { id: 'incident', header: t('incidents.col.incident'), accessorFn: (r) => r.title, cell: ({ row: { original: r } }) => (
      <div className="grid"><Link to={`/incidents/${r.id}`} onClick={(e) => e.stopPropagation()} className={`font-medium ${link}`}>{r.title}</Link><span className="text-[12px] text-muted">{t(kindKey(r))}</span></div>
    ) },
    { id: 'severity', header: t('incidents.col.severity'), accessorFn: (r) => ['info', 'low', 'medium', 'high', 'critical'].indexOf(r.severity), cell: ({ row }) => <SeverityChip severity={row.original.severity} /> },
    { id: 'device', header: t('incidents.col.device'), accessorFn: (r) => r.devices.map((d) => d.name).join(', '), cell: ({ row: { original: r } }) => (
      <span className="flex flex-wrap gap-x-2">{r.devices.map((d) => <Link key={d.id} to={`/devices/${d.id}`} onClick={(e) => e.stopPropagation()} className={link}>{d.name}</Link>)}</span>
    ) },
    { id: 'status', header: t('incidents.col.status'), accessorFn: (r) => r.status, cell: ({ row }) => <Handled i={row.original} /> },
    { id: 'seen', header: t('incidents.col.seen'), accessorFn: (r) => r.last_seen, cell: ({ row }) => <Seen i={row.original} /> },
    { id: 'count', header: t('incidents.col.count'), accessorFn: (r) => r.count, cell: ({ row }) => t('incidents.times', { count: row.original.count }) },
    { id: 'sent', header: t('incidents.col.sent'), enableSorting: false, cell: ({ row }) => <DeliveryBadges sends={row.original.sends} notSent={row.original.not_sent} admin={admin} /> },
    { id: 'respond', header: t('incidents.col.respond'), enableSorting: false, cell: ({ row }) => <RespondLink i={row.original} /> },
  ]
  return (
    <>
      <PageHeader title={title} stories={['S-ALERT-3']} meta={q.data ? <span className="inline-flex flex-wrap items-center gap-2">{t('incidents.meta')} {t('incidents.retention')}<SampleDataNote /></span> : null} />
      <QueryState query={q}>
        {() => (
          <Section id="list" title={t('incidents.caption')}>
            <div className="mb-3 flex flex-wrap gap-2">
              <Segmented className="max-w-full overflow-x-auto" label={t('incidents.kindFilter')} value={kind} onChange={setKind} options={[{ value: 'all', label: t('incidents.kf.all') }, ...kinds.map((k) => ({ value: k, label: t(`incidents.kf.${k}`) }))]} />
              <Segmented className="max-w-full overflow-x-auto" label={t('incidents.filter')} value={filter} onChange={setFilter} options={[{ value: 'open', label: t('incidents.open') }, { value: 'all', label: t('incidents.all') }]} />
            </div>
            {can && shown.length > 0 ? (
              <div role="region" aria-label={t('bulk.region')} className="mb-3 flex flex-wrap items-center gap-2 rounded-md border border-rule bg-sunken px-3 py-2 text-sm">
                <span className="font-medium">{t('bulk.selected', { count: shown.length })}</span>
                {shown.length > MAX_BULK_INCIDENTS ? <span className="text-[13px] text-danger">{t('bulk.tooMany', { max: MAX_BULK_INCIDENTS })}</span> : null}
                <Button size="sm" disabled={shown.length > MAX_BULK_INCIDENTS} onClick={open('acknowledged')}>{t('detail.acknowledge')}</Button>
                <Button size="sm" variant="primary" disabled={shown.length > MAX_BULK_INCIDENTS} onClick={open('resolved')}>{t('detail.resolve')}</Button>
                <Button size="sm" onClick={() => setSelected(new Set())}>{t('bulk.clear')}</Button>
              </div>
            ) : null}
            {rows.length === 0 ? (
              <EmptyState title={filter === 'open' ? t('incidents.emptyOpenTitle') : t('incidents.emptyAllTitle')} action={noChannel ? <Link to="/settings/channels" className={link}>{t('incidents.setupChannels')}</Link> : undefined}>{t(noTraps ? 'incidents.emptyBodyNoTraps' : 'incidents.emptyBody')}</EmptyState>
            ) : (
              <DataTable caption={t('incidents.caption')} data={rows} columns={columns} onRowClick={(r) => navigate(`/incidents/${r.id}`)} rowTone={(r) => (r.status === 'new' ? (r.severity === 'critical' ? 'danger' : 'warn') : undefined)} initialSort={[{ id: 'seen', desc: true }]}
                mobileRow={(r) => (
                  <div className="flex items-start gap-3">
                    {can ? <span className="pt-0.5">{pick(r)}</span> : null}
                    <div className="grid flex-1 gap-1.5">
                      <div className="flex items-start justify-between gap-3">
                        <Link to={`/incidents/${r.id}`} onClick={(e) => e.stopPropagation()} className={`font-medium ${link}`}>{r.title}</Link>
                        <SeverityChip severity={r.severity} />
                      </div>
                      <p className="text-[13px] text-muted">{t(kindKey(r))}, {r.devices.map((x) => x.name).join(', ')}, {t('incidents.times', { count: r.count })}</p>
                      <div className="flex flex-wrap items-center gap-x-3 gap-y-1 text-[13px]"><Handled i={r} /><DeliveryBadges sends={r.sends} notSent={r.not_sent} admin={admin} /><Seen i={r} /></div>
                      <div><RespondLink i={r} /></div>
                    </div>
                  </div>
                )} />
            )}
          </Section>
        )}
      </QueryState>
      <BulkDialog ids={shown} status={bulk} onOpenChange={(v) => { if (!v) setBulk(null) }} opener={opener} onDone={() => setSelected(new Set())} />
    </>
  )
}

export default function IncidentsPage() {
  return <RequireModule module="notify"><Content /></RequireModule>
}
