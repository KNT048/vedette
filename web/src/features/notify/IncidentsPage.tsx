import { useCallback, useEffect, useRef, useState, type MouseEvent, type RefObject } from 'react'
import { Link, useNavigate, useSearchParams } from 'react-router'
import { useTranslation } from 'react-i18next'
import { toast } from 'sonner'
import { PageHeader } from '@/components/common/PageHeader'
import { KpiStrip, PageTabs } from '@/components/common/PageFrame'
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
import { DeliveryBadges, IncidentStatusChip, kindKey, needsFix } from './shared'
import { X } from 'lucide-react'
import { INCIDENT_KINDS, type Incident, type IncidentKind } from './types'

const link = 'text-accent underline-offset-4 hover:underline'
type BulkStatus = 'acknowledged' | 'resolved'
/** The two lists (D-543): Open = new + acknowledged, Resolved. `?severity=urgent` (high and critical) and `?sent=no` narrow Open; the KPI cells link there. */
type Tab = 'open' | 'resolved'
const urgent = (i: Incident) => i.severity === 'high' || i.severity === 'critical'

/** Tells the page which rows the table shows now (page, sort, filter), so the select-all banner never speaks of another page. */
function PageWatch({ ids, onChange }: { ids: string[]; onChange: (key: string) => void }) {
  const key = ids.join(',')
  useEffect(() => { onChange(key) }, [key, onChange])
  return null
}

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
  return <div className="grid gap-0.5"><IncidentStatusChip status={i.status} />{i.resolved_reason ? <span className="text-[12px] text-muted">{t('incidents.closedBy', { reason: i.resolved_reason, time: fmtDateTime(i.handled_at) })}</span> : i.handled_by ? <span className="text-[12px] text-muted">{t('incidents.statusBy', { user: i.handled_by, time: fmtDateTime(i.handled_at) })}</span> : null}</div>
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
  const [params, setParams] = useSearchParams()
  const tab: Tab = params.get('tab') === 'resolved' ? 'resolved' : 'open'
  const onlyUrgent = params.get('severity') === 'urgent'
  const onlyUnsent = params.get('sent') === 'no'
  const setParam = (k: string, v: string) => { const p = new URLSearchParams(params); if (v) p.set(k, v); else p.delete(k); setParams(p, { replace: true }) }
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
  const all = q.data?.incidents ?? []
  const openRows = all.filter((a) => a.status !== 'resolved')
  const rowsFor = (x: Tab) => all.filter((a) => (x === 'open' ? a.status !== 'resolved' && (!onlyUrgent || urgent(a)) && (!onlyUnsent || needsFix(a.not_sent)) : a.status === 'resolved') && (kind === 'all' || a.kind === kind))
  const rows = rowsFor(tab)
  const kpis = q.data ? [
    { value: openRows.length, label: t('kpi.open'), to: '?tab=open' },
    { value: openRows.filter(urgent).length, label: t('kpi.urgent'), to: '?tab=open&severity=urgent' },
    { value: openRows.filter((a) => needsFix(a.not_sent)).length, label: t('kpi.notSent'), to: '?tab=open&sent=no' },
  ] : []
  // Only what is shown can stay selected: changing a filter never acts on hidden rows (as on Findings, D-484).
  const shown = rows.filter((r) => selected.has(r.id)).map((r) => r.id)
  // Gmail pattern (Opus r1 MED-3): the header box selects the page the table shows; a banner then offers every matching incident.
  const [pageIds, setPageIds] = useState<string[] | null>(null)
  const pageAll = pageIds !== null && rows.length > pageIds.length && pageIds.every((id) => selected.has(id))
  const clear = () => { setSelected(new Set()); setPageIds(null) }
  // another page, sort or filter: the banner of the page the box selected goes (the selection stays)
  const onPage = useCallback((key: string) => setPageIds((p) => (p && p.join(',') !== key ? null : p)), [])
  const toggle = (id: string, on: boolean) => setSelected((s) => { const n = new Set(s); if (on) n.add(id); else n.delete(id); return n })
  const pick = (r: Incident) => (
    // A click on the box selects; it never opens the incident (the row click does).
    <span onClick={(e) => e.stopPropagation()} className="inline-flex">
      <Checkbox checked={selected.has(r.id)} onCheckedChange={(v) => toggle(r.id, v === true)} aria-label={t('bulk.select', { title: r.title })} />
    </span>
  )
  const open = (s: BulkStatus) => (e: MouseEvent<HTMLButtonElement>) => { opener.current = e.currentTarget; setBulk(s) }
  const columns: ColumnDef<Incident>[] = [
    ...(can && tab === 'open' ? [{ id: 'select', enableSorting: false, header: ({ table }) => {
      const page = table.getRowModel().rows.map((r) => r.original.id)
      const on = page.filter((id) => selected.has(id)).length
      const set = (v: boolean) => {
        setSelected((s) => { const n = new Set(s); for (const id of page) { if (v) n.add(id); else n.delete(id) } return n })
        setPageIds(v ? page : null)
      }
      return <><Checkbox checked={page.length > 0 && on === page.length ? true : on > 0 ? 'indeterminate' : false} onCheckedChange={(v) => set(v === true)} aria-label={t('bulk.selectPage', { count: page.length })} /><PageWatch ids={page} onChange={onPage} /></>
    }, cell: ({ row: { original: r } }) => pick(r) } satisfies ColumnDef<Incident>] : []),
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
  const panel = (
    <QueryState query={q}>
      {() => (
        <>
          <div className="mb-3 flex flex-wrap gap-2">
            <Segmented className="max-w-full overflow-x-auto" label={t('incidents.kindFilter')} value={kind} onChange={(v) => { setKind(v); setPageIds(null) }} options={[{ value: 'all', label: t('incidents.kf.all') }, ...kinds.map((k) => ({ value: k, label: t(`incidents.kf.${k}`) }))]} />
            {tab === 'open' && onlyUrgent ? <Button size="sm" onClick={() => setParam('severity', '')}><X />{t('incidents.clearUrgent')}</Button> : null}
            {tab === 'open' && onlyUnsent ? <Button size="sm" onClick={() => setParam('sent', '')}><X />{t('incidents.clearUnsent')}</Button> : null}
          </div>
          {tab === 'open' && can && shown.length > 0 ? (
            <div role="region" aria-label={t('bulk.region')} className="mb-3 flex flex-wrap items-center gap-2 rounded-md border border-rule bg-sunken px-3 py-2 text-sm">
              <span className="font-medium">{t('bulk.selected', { count: shown.length })}</span>
              {shown.length > MAX_BULK_INCIDENTS ? <span className="text-[13px] text-danger">{t('bulk.tooMany', { max: MAX_BULK_INCIDENTS })}</span> : null}
              <Button size="sm" disabled={shown.length > MAX_BULK_INCIDENTS} onClick={open('acknowledged')}>{t('detail.acknowledge')}</Button>
              <Button size="sm" variant="primary" disabled={shown.length > MAX_BULK_INCIDENTS} onClick={open('resolved')}>{t('detail.resolve')}</Button>
              <Button size="sm" onClick={clear}>{t('bulk.clear')}</Button>
              {pageAll ? (
                <span className="flex basis-full flex-wrap items-center gap-2 text-[13px]">
                  {shown.length === rows.length ? t('bulk.everySelected', { count: rows.length }) : (
                    <>{t('bulk.pageSelected', { count: pageIds.length })}<Button size="sm" variant="link" onClick={() => setSelected(new Set(rows.map((r) => r.id)))}>{t('bulk.selectEvery', { count: rows.length })}</Button></>
                  )}
                </span>
              ) : null}
            </div>
          ) : null}
          {rows.length === 0 ? (
            <EmptyState title={tab === 'open' ? t('incidents.emptyOpenTitle') : t('incidents.emptyResolvedTitle')} action={noChannel ? <Link to="/settings/channels" className={link}>{t('incidents.setupChannels')}</Link> : undefined}>{t(noTraps ? 'incidents.emptyBodyNoTraps' : 'incidents.emptyBody')}</EmptyState>
          ) : (
            <DataTable caption={t('incidents.caption')} data={rows} columns={columns} onRowClick={(r) => navigate(`/incidents/${r.id}`)} rowTone={(r) => (r.status === 'new' ? (r.severity === 'critical' ? 'danger' : 'warn') : undefined)} initialSort={[{ id: 'seen', desc: true }]}
              mobileRow={(r) => (
                <div className="flex items-start gap-3">
                  {can && tab === 'open' ? <span className="pt-0.5">{pick(r)}</span> : null}
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
        </>
      )}
    </QueryState>
  )
  return (
    <>
      <PageHeader title={title} stories={['S-ALERT-3', 'S-UI-1']} meta={q.data ? <span className="inline-flex flex-wrap items-center gap-2">{t('incidents.meta')} {t('incidents.retention')}<SampleDataNote /></span> : null} />
      {kpis.length ? <KpiStrip label={t('kpi.label')} items={kpis} /> : null}
      <PageTabs label={t('tabs.label')} tabs={[
        { id: 'open', label: t('tabs.open'), panel, badge: { count: openRows.filter(urgent).length, label: t('tabs.openBadge') } },
        { id: 'resolved', label: t('tabs.resolved'), panel },
      ]} />
      <BulkDialog ids={shown} status={bulk} onOpenChange={(v) => { if (!v) setBulk(null) }} opener={opener} onDone={clear} />
    </>
  )
}

export default function IncidentsPage() {
  return <RequireModule module="notify"><Content /></RequireModule>
}
