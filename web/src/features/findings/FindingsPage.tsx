import { useRef, useState, type RefObject } from 'react'
import { Link, useNavigate, useSearchParams } from 'react-router'
import { Trans, useTranslation } from 'react-i18next'
import { toast } from 'sonner'
import { X } from 'lucide-react'
import { PageHeader } from '@/components/common/PageHeader'
import { DataTable, type ColumnDef } from '@/components/common/DataTable'
import { EmptyState, QueryState, RequireModule, SampleDataNote } from '@/components/common/States'
import { Button } from '@/components/ui/button'
import { Checkbox, RadioGroup, RadioItem } from '@/components/ui/checkbox'
import { Dialog, DialogContent, DialogFooter } from '@/components/ui/dialog'
import { Field, Input, Select, Textarea } from '@/components/ui/input'
import { Segmented } from '@/components/ui/segmented'
import { fmtDate, fmtDateTime, fmtRelative } from '@/lib/format'
import { useCan } from '@/lib/session'
import { AcceptUntil, FindingStatusChip } from './AcceptRisk'
import { untilOk } from './accept'
import { useBulkStatus, useFindings } from './api'
import { basisKey, deviceName, hasIp, isOpen, riskRank, unverified } from './basis'
import { MAX_BULK } from './contract'
import { errMsg } from './errors'
import { RiskChip } from './Risk'
import type { BulkAction, FindingRow, VersionNeeded } from './types'

type Filter = 'open' | 'confirmed' | 'suspected' | 'accepted' | 'resolved' | 'all'
const match: Record<Filter, (f: FindingRow) => boolean> = {
  open: (f) => isOpen(f.status),
  confirmed: (f) => f.status === 'confirmed',
  suspected: (f) => f.status === 'suspected',
  accepted: (f) => f.status === 'risk_accepted',
  resolved: (f) => !isOpen(f.status),
  all: () => true,
}
/** Độ chắc chắn (D-484): tất cả / đã xác nhận hoặc theo phiên bản / chỉ khớp tên sản phẩm. */
type Certainty = 'all' | 'likely' | 'unverified'
const certain: Record<Certainty, (f: FindingRow) => boolean> = { all: () => true, likely: (f) => !unverified(f), unverified }
const BULK: BulkAction[] = ['patched', 'mitigated', 'false_positive', 'not_relevant', 'accept_risk']

/** Một hành động, một ghi chú cho các phát hiện đã chọn (W1-12): mỗi phát hiện vẫn có dòng lịch sử và kiểm toán riêng. */
function BulkDialog({ ids, open, onOpenChange, opener, onDone }: { ids: string[]; open: boolean; onOpenChange: (v: boolean) => void; opener: RefObject<HTMLButtonElement | null>; onDone: () => void }) {
  const { t } = useTranslation('findings')
  const bulk = useBulkStatus()
  const [action, setAction] = useState<BulkAction>('patched')
  const [note, setNote] = useState('')
  const [until, setUntil] = useState('')
  const [error, setError] = useState<string | undefined>()
  const [untilError, setUntilError] = useState<string | undefined>()
  const [wasOpen, setWasOpen] = useState(open)
  if (open !== wasOpen) { setWasOpen(open); if (open) { setAction('patched'); setNote(''); setUntil(''); setError(undefined); setUntilError(undefined) } }
  const accept = action === 'accept_risk'
  const needNote = action === 'false_positive' || action === 'not_relevant' || accept
  function submit() {
    const badUntil = accept && !untilOk(until)
    setUntilError(badUntil ? t('accept.untilRequired') : undefined)
    if (needNote && note.trim().length < 3) { setError(t(accept ? 'accept.noteRequired' : 'status.noteRequired')); return }
    if (badUntil) return
    setError(undefined)
    bulk.mutate({ ids, action, note: note.trim(), ...(accept ? { until } : {}) }, {
      onSuccess: (r) => { toast.success(r.skipped > 0 ? `${t('bulk.done', { count: r.updated })}. ${t('bulk.skipped', { count: r.skipped })}` : t('bulk.done', { count: r.updated })); onOpenChange(false); onDone() },
      onError: (e) => setError(errMsg(e)),
    })
  }
  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent title={t('bulk.title', { count: ids.length })} description={t('bulk.description')} onCloseAutoFocus={(e) => { e.preventDefault(); opener.current?.focus() }}>
        <RadioGroup value={action} onValueChange={(v) => { setAction(v as BulkAction); setError(undefined); setUntilError(undefined) }} aria-label={t('status.title')}>
          {BULK.map((a) => (
            <div key={a} className="flex items-start gap-2.5">
              <RadioItem id={`bulk-${a}`} value={a} className="mt-1" />
              <label htmlFor={`bulk-${a}`} className="grid text-sm"><span className="font-medium">{t(`status.${a}`)}</span><span className="text-[13px] text-muted">{t(`status.${a}Hint`)}</span></label>
            </div>
          ))}
        </RadioGroup>
        {accept ? <AcceptUntil id="bulk-until" value={until} onChange={(v) => { setUntil(v); setUntilError(undefined) }} error={untilError} /> : null}
        <Field htmlFor="bulk-note" label={needNote ? t('status.noteLabelRequired') : t('status.noteLabel')} hint={t('bulk.noteHint')} error={error}>
          <Textarea id="bulk-note" value={note} maxLength={500} onChange={(e) => setNote(e.target.value)} aria-invalid={!!error} aria-describedby={error ? 'bulk-note-error' : undefined} />
        </Field>
        <DialogFooter>
          <Button onClick={() => onOpenChange(false)}>{t('common:cancel')}</Button>
          <Button variant="primary" disabled={bulk.isPending} onClick={submit}>{t('bulk.submit', { count: ids.length })}</Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}

/** The status, and for an accepted risk the day it ends (D-498). */
function StatusCell({ r }: { r: FindingRow }) {
  const { t } = useTranslation('findings')
  return (
    <span className="grid justify-items-start gap-0.5">
      <FindingStatusChip f={r} />
      {r.status === 'risk_accepted' && r.accepted_until ? <span className="whitespace-nowrap text-[12px] text-muted">{t('accept.rowUntil', { date: fmtDate(r.accepted_until) })}</span> : null}
    </span>
  )
}

function List() {
  const { t } = useTranslation('findings')
  const navigate = useNavigate()
  const can = useCan('operator')
  const [params, setParams] = useSearchParams()
  const cve = params.get('cve')?.toUpperCase() ?? ''
  const device = params.get('device') ?? ''
  const product = params.get('product') ?? ''
  const setParam = (k: string, v: string) => { if (v) params.set(k, v); else params.delete(k); setParams(params, { replace: true }) }
  const [filter, setFilter] = useState<Filter>('open')
  const [certainty, setCertainty] = useState<Certainty>('all')
  const [search, setSearch] = useState('')
  const [selected, setSelected] = useState<ReadonlySet<string>>(new Set())
  const [bulkOpen, setBulkOpen] = useState(false)
  const opener = useRef<HTMLButtonElement>(null)
  const q = useFindings()
  const items = q.data?.items
  const open = items?.filter((f) => isOpen(f.status)).length ?? 0
  const confirmed = items?.filter((f) => f.status === 'confirmed').length ?? 0
  const name = (r: FindingRow) => deviceName(r.asset, t('removedDevice'))
  const devices = [...new Map((items ?? []).map((f) => [f.asset_id, name(f)])).entries()].sort((a, b) => a[1].localeCompare(b[1]))
  const products = [...new Set((items ?? []).map((f) => f.kev?.display ?? '').filter(Boolean))].sort()
  const s = search.trim().toLowerCase()
  const rows = (items ?? []).filter(match[filter]).filter(certain[certainty])
    .filter((f) => (!cve || f.cve === cve) && (!device || f.asset_id === device) && (!product || f.kev?.display === product))
    .filter((f) => !s || [f.cve, name(f), f.asset?.ip ?? '', f.kev?.display ?? ''].some((v) => v.toLowerCase().includes(s)))
  // Only what is shown can stay selected: changing a filter never acts on hidden rows.
  const shown = rows.filter((r) => selected.has(r.id)).map((r) => r.id)
  const allShown = rows.length > 0 && shown.length === rows.length
  const toggle = (id: string, on: boolean) => setSelected((s) => { const n = new Set(s); if (on) n.add(id); else n.delete(id); return n })
  const toggleAll = (on: boolean) => setSelected(on ? new Set(rows.map((r) => r.id)) : new Set())

  const pick = (r: FindingRow) => (
    // A click on the box selects; it never opens the finding (the row click does).
    <span onClick={(e) => e.stopPropagation()} className="inline-flex">
      <Checkbox checked={selected.has(r.id)} onCheckedChange={(v) => toggle(r.id, v === true)} aria-label={t('bulk.select', { cve: r.cve, device: name(r) })} />
    </span>
  )
  const columns: ColumnDef<FindingRow>[] = [
    ...(can ? [{ id: 'select', enableSorting: false, header: () => <Checkbox checked={allShown ? true : shown.length > 0 ? 'indeterminate' : false} onCheckedChange={(v) => toggleAll(v === true)} aria-label={t('bulk.selectAll', { count: rows.length })} />, cell: ({ row: { original: r } }) => pick(r) } satisfies ColumnDef<FindingRow>] : []),
    { id: 'device', header: t('col.device'), accessorFn: (r) => name(r), cell: ({ row: { original: r } }) => (
      <div className="grid">
        {r.asset ? <Link to={`/devices/${r.asset.id}`} title={name(r)} className="line-clamp-2 max-w-64 font-medium text-accent underline-offset-4 [overflow-wrap:anywhere] hover:underline">{name(r)}</Link> : <span className="font-medium">{name(r)}</span>}
        <span className="text-[12px] text-muted">{hasIp(r.asset) ? r.asset?.ip : r.asset ? t('noIp') : ''}</span>
      </div>
    ) },
    { id: 'cve', header: t('col.cve'), accessorFn: (r) => r.cve, cell: ({ row: { original: r } }) => <Link to={`/findings/${r.id}`} className="whitespace-nowrap font-medium text-accent underline-offset-4 hover:underline">{r.cve}</Link> },
    { id: 'product', header: t('col.product'), accessorFn: (r) => r.kev?.display ?? '', cell: ({ row: { original: r } }) => <span>{r.kev?.display ?? '–'}</span> },
    { id: 'status', header: t('col.status'), accessorFn: (r) => r.status, cell: ({ row: { original: r } }) => <StatusCell r={r} /> },
    { id: 'severity', header: t('col.severity'), accessorFn: riskRank, cell: ({ row: { original: r } }) => <RiskChip f={r} /> },
    { id: 'basis', header: t('col.basis'), accessorFn: (r) => r.basis, cell: ({ row: { original: r } }) => <span className={unverified(r) ? 'text-[13px] text-muted' : 'text-[13px]'}>{t(basisKey(r.basis))}</span> },
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
      <div className="mb-3 grid gap-2">
        <div className="flex flex-wrap items-center gap-2">
          <div className="max-w-full overflow-x-auto">
            <Segmented<Filter> label={t('filterLabel')} value={filter} onChange={setFilter} options={(['open', 'confirmed', 'suspected', 'accepted', 'resolved', 'all'] as Filter[]).map((v) => ({ value: v, label: t(`filters.${v}`) }))} />
          </div>
          <div className="max-w-full overflow-x-auto">
            <Segmented<Certainty> label={t('certainty.label')} value={certainty} onChange={setCertainty} options={(['all', 'likely', 'unverified'] as Certainty[]).map((v) => ({ value: v, label: t(`certainty.${v}`) }))} />
          </div>
          {cve ? (
            <Button size="sm" onClick={() => setParam('cve', '')}><X />{t('clearCve', { cve })}</Button>
          ) : null}
        </div>
        <div className="flex flex-wrap items-center gap-2">
          <Input className="h-9 w-full sm:max-w-xs" value={search} onChange={(e) => setSearch(e.target.value)} placeholder={t('filter')} aria-label={t('filter')} />
          <Select className="w-full sm:w-auto sm:max-w-64" value={device} onChange={(e) => setParam('device', e.target.value)} aria-label={t('deviceFilter')}>
            <option value="">{t('allDevices')}</option>
            {devices.map(([id, n]) => <option key={id} value={id}>{n}</option>)}
          </Select>
          <Select className="w-full sm:w-auto sm:max-w-64" value={product} onChange={(e) => setParam('product', e.target.value)} aria-label={t('productFilter')}>
            <option value="">{t('allProducts')}</option>
            {products.map((p) => <option key={p} value={p}>{p}</option>)}
          </Select>
        </div>
        {can && shown.length > 0 ? (
          <div role="region" aria-label={t('bulk.region')} className="flex flex-wrap items-center gap-2 rounded-md border border-rule bg-sunken px-3 py-2 text-sm">
            <span className="font-medium">{t('bulk.selected', { count: shown.length })}</span>
            {shown.length > MAX_BULK ? <span className="text-[13px] text-danger">{t('bulk.tooMany', { max: MAX_BULK })}</span> : null}
            <Button ref={opener} size="sm" variant="primary" disabled={shown.length > MAX_BULK} onClick={() => setBulkOpen(true)}>{t('status.mark')}</Button>
            <Button size="sm" onClick={() => setSelected(new Set())}>{t('bulk.clear')}</Button>
          </div>
        ) : null}
      </div>
      {q.data?.version_needed.length ? <VersionNeededList items={q.data.version_needed} /> : null}
      <QueryState query={q}>
        {() => (
          <DataTable
            caption={t('caption')}
            data={rows}
            columns={columns}
            initialSort={[{ id: 'severity', desc: true }]}
            onRowClick={(r) => navigate(`/findings/${r.id}`)}
            mobileRow={(r) => (
              <div className="flex items-start gap-3">
                {can ? <span className="pt-0.5">{pick(r)}</span> : null}
                <div className="grid flex-1 gap-1.5">
                  <div className="flex items-start justify-between gap-3">
                    <Link to={`/findings/${r.id}`} className="font-medium text-accent underline-offset-4 hover:underline">{r.cve}</Link>
                    <StatusCell r={r} />
                  </div>
                  <span className="text-sm [overflow-wrap:anywhere]">{name(r)}<span className="text-muted">{hasIp(r.asset) ? ` (${r.asset?.ip})` : r.asset ? ` (${t('noIp')})` : ''}</span></span>
                  <span className="text-[13px] text-muted">{r.kev?.display ?? '–'}</span>
                  <div className="flex flex-wrap items-center gap-x-3 gap-y-1 text-[13px]">
                    <RiskChip f={r} />
                    <span>{t(basisKey(r.basis))}</span>
                    <span className="text-muted">{fmtRelative(r.last_seen)}</span>
                  </div>
                </div>
              </div>
            )}
            rowTone={(r) => (r.status === 'confirmed' ? 'danger' : r.status === 'suspected' && !unverified(r) ? 'warn' : undefined)}
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
      <BulkDialog ids={shown} open={bulkOpen} onOpenChange={setBulkOpen} opener={opener} onDone={() => setSelected(new Set())} />
    </>
  )
}

/** D-500 (S-INV-2): a software on the exploited list without a usable version is ONE line here, not one finding per CVE. */
function VersionNeededList({ items }: { items: VersionNeeded[] }) {
  const { t } = useTranslation('findings')
  return (
    <section aria-labelledby="version-needed-title" className="mb-3 rounded-md border border-warn/50 bg-warn-soft/60 px-3 py-2 text-[13px]">
      <h2 id="version-needed-title" className="font-medium">{t('versionNeeded.title', { count: items.length })}</h2>
      <p className="text-muted">{t('versionNeeded.help')}</p>
      <ul className="mt-1 grid gap-0.5">
        {items.map((n) => {
          // One naming rule (D-471, W5-1): the API's `asset.name`. A hand-added product IS the device ("Microsoft Office (no device)"):
          // the line names it once instead of "<device>: <product> …".
          const name = deviceName(n.asset, t('removedDevice'))
          const self = name === n.software || name === t('inventory:noDevice', { product: n.software })
          const link = <Link to={`/devices/${n.asset_id}`} className="font-medium text-accent underline-offset-4 hover:underline" />
          return (
            <li key={`${n.asset_id}/${n.software_id}`}>
              {self ? null : <><Link to={`/devices/${n.asset_id}`} className="font-medium text-accent underline-offset-4 hover:underline">{name}</Link>{': '}</>}
              <Trans t={t} i18nKey={n.version === null ? 'versionNeeded.missing' : 'versionNeeded.unreadable'} count={n.cves}
                values={{ software: self ? name : n.software, version: n.version ?? '' }} components={{ sw: self ? link : <span /> }} />
            </li>
          )
        })}
      </ul>
    </section>
  )
}

export default function FindingsPage() {
  return <RequireModule module="findings"><List /></RequireModule>
}
