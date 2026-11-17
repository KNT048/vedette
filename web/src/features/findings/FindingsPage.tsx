import { useEffect, useRef, useState, type RefObject } from 'react'
import { Link, useNavigate, useSearchParams } from 'react-router'
import { Trans, useTranslation } from 'react-i18next'
import { toast } from 'sonner'
import { X } from 'lucide-react'
import { Notice, PageHeader } from '@/components/common/PageHeader'
import { KpiStrip, PageTabs } from '@/components/common/PageFrame'
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
import { useBulkStatus, useFindings, usePlan, useToFix } from './api'
import { basisKey, deviceName, hasIp, isOpen, riskRank, unverified } from './basis'
import { MAX_BULK } from './contract'
import { errMsg } from './errors'
import { RiskChip } from './Risk'
import { UncheckedList } from './UncheckedList'
import { ToFixTab, UnprovedList, unproved } from './ToFix'
import { useFixAction } from './fix'
import type { BulkAction, FindingRow, VersionNeeded } from './types'
import { NotRelevantToggle, isNotRelevant } from './notRelevant'

/** The three lists (D-543): Open = confirmed + suspected, Accepted risk, Handled = patched / mitigated / false positive / not relevant. */
type Tab = 'open' | 'accepted' | 'handled'
const inTab: Record<Tab, (f: FindingRow) => boolean> = {
  open: (f) => isOpen(f.status),
  accepted: (f) => f.status === 'risk_accepted',
  handled: (f) => !isOpen(f.status) && f.status !== 'risk_accepted',
}
/** Inside Open: `?status=confirmed|suspected` narrows it (the KPI "confirmed" cell links there). */
type OpenStatus = 'all' | 'confirmed' | 'suspected'
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
      <DialogContent title={t('bulk.title', { count: ids.length })} description={t('bulk.description')} info={t('bulk.descriptionInfo')} onCloseAutoFocus={(e) => { e.preventDefault(); opener.current?.focus() }}>
        <RadioGroup value={action} onValueChange={(v) => { setAction(v as BulkAction); setError(undefined); setUntilError(undefined) }} aria-label={t('status.title')}>
          {BULK.map((a) => (
            <div key={a} className="flex items-start gap-2.5">
              <RadioItem id={`bulk-${a}`} value={a} className="mt-1" />
              <label htmlFor={`bulk-${a}`} className="grid text-sm"><span className="font-medium">{t(`status.${a}`)}</span><span className="text-meta text-muted">{t(`status.${a}Hint`)}</span></label>
            </div>
          ))}
        </RadioGroup>
        {accept ? <AcceptUntil id="bulk-until" value={until} onChange={(v) => { setUntil(v); setUntilError(undefined) }} error={untilError} /> : null}
        <Field htmlFor="bulk-note" label={needNote ? t('status.noteLabelRequired') : t('status.noteLabel')} hint={t('bulk.noteHint')} error={error}>
          <Textarea id="bulk-note" value={note} maxLength={500} onChange={(e) => setNote(e.target.value)} aria-invalid={!!error} aria-describedby={error ? 'bulk-note-error' : undefined} />
        </Field>
        <DialogFooter>
          <Button onClick={() => onOpenChange(false)}>{t('common:cancel')}</Button>
          {/* empty-guard: the bulk dialog opens only from the selection bar, which shows only with a selection */}
          <Button variant="primary" busy={bulk.isPending} busyLabel={t('common:busy.saving')} onClick={submit}>{t('bulk.submit', { count: ids.length })}</Button>
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
      {r.status === 'risk_accepted' && r.accepted_until ? <span className="whitespace-nowrap text-caption text-muted">{t('accept.rowUntil', { date: fmtDate(r.accepted_until) })}</span> : null}
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
  const severity = params.get('severity') ?? ''
  const fixKey = params.get('fix') ?? '' // D-545: the findings one update fixes, as rows (to select and handle them)
  const status: OpenStatus = params.get('status') === 'confirmed' ? 'confirmed' : params.get('status') === 'suspected' ? 'suspected' : 'all'
  // kien G5: Handled hides what was closed as not relevant until `?notrelevant=show` (a shareable link, like the other filters)
  const showNotRelevant = params.get('notrelevant') === 'show'
  const setParam = (k: string, v: string) => { if (v) params.set(k, v); else params.delete(k); setParams(params, { replace: true }) }
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
  const rowsFor = (tab: Tab, notRelevant = showNotRelevant) => (items ?? []).filter(inTab[tab]).filter((f) => notRelevant || !isNotRelevant(f)).filter(certain[certainty])
    .filter((f) => tab !== 'open' || status === 'all' || f.status === status)
    .filter((f) => (!cve || f.cve === cve) && (!device || f.asset_id === device) && (!product || f.kev?.display === product) && (!severity || f.severity === severity) && (!fixKey || f.fix?.group === fixKey))
    .filter((f) => !s || [f.cve, name(f), f.asset?.ip ?? '', f.kev?.display ?? ''].some((v) => v.toLowerCase().includes(s)))
  // The tab being shown decides which rows are selectable: selection is cleared on a tab change by the filter below (hidden rows never stay selected).
  const tabId = (['open', 'accepted', 'handled'] as Tab[]).find((x) => x === params.get('tab')) ?? 'open'
  // D-545: in Open, the findings one update fixes together are one item above the table, not one row each (unless ?fix= asks for them).
  // kien G8: the findings one update fixes are an action of To fix; this list is every open finding, one row each
  const rows = rowsFor(tabId)
  const fixAction = useFixAction()
  const fixShown = fixKey ? items?.find((f) => f.fix?.group === fixKey)?.fix : undefined
  // Only what is shown can stay selected: changing a filter never acts on hidden rows.
  const shown = rows.filter((r) => selected.has(r.id)).map((r) => r.id)
  const allShown = rows.length > 0 && shown.length === rows.length
  const toggle = (id: string, on: boolean) => setSelected((s) => { const n = new Set(s); if (on) n.add(id); else n.delete(id); return n })
  const toggleAll = (on: boolean) => setSelected(on ? new Set(rows.map((r) => r.id)) : new Set())
  // A filter of the page is on (the table's own search box is the page's here): an empty table then means "no match", not "none yet".
  const filtersOn = (tab: Tab) => !!(cve || device || product || severity || fixKey || s) || certainty !== 'all' || (tab === 'open' && status !== 'all')
  const clearFilters = () => {
    for (const k of ['cve', 'device', 'product', 'severity', 'fix', 'status']) params.delete(k)
    setParams(params, { replace: true })
    setSearch('')
    setCertainty('all')
  }

  const week = new Date(Date.now() + 7 * 86_400_000).toISOString().slice(0, 10)
  const kpis = items ? [
    { value: open, label: t('kpi.open'), to: '?tab=open' },
    { value: confirmed, label: t('kpi.confirmed'), to: '?tab=open&status=confirmed' },
    { value: items.filter((f) => isOpen(f.status) && f.severity === 'critical').length, label: t('kpi.critical'), to: '?tab=open&severity=critical' },
    { value: items.filter((f) => f.status === 'risk_accepted' && f.accepted_until && f.accepted_until <= week).length, label: t('kpi.ending'), to: '?tab=accepted' },
  ] : []

  const pick = (r: FindingRow) => (
    // A click on the box selects; it never opens the finding (the row click does).
    <span onClick={(e) => e.stopPropagation()} className="inline-flex">
      <Checkbox checked={selected.has(r.id)} onCheckedChange={(v) => toggle(r.id, v === true)} aria-label={t('bulk.select', { cve: r.cve, device: name(r) })} />
    </span>
  )
  const columns: ColumnDef<FindingRow>[] = [
    // kien G5: no "Select all 0 findings" on an empty list
    ...(can && rows.length > 0 ? [{ id: 'select', enableSorting: false, header: () => <Checkbox checked={allShown ? true : shown.length > 0 ? 'indeterminate' : false} onCheckedChange={(v) => toggleAll(v === true)} aria-label={t('bulk.selectAll', { count: rows.length })} />, cell: ({ row: { original: r } }) => pick(r) } satisfies ColumnDef<FindingRow>] : []),
    { id: 'device', header: t('col.device'), accessorFn: (r) => name(r), cell: ({ row: { original: r } }) => (
      <div className="grid">
        {r.asset ? <Link to={`/devices/${r.asset.id}`} title={name(r)} className="line-clamp-2 max-w-64 font-medium text-accent underline-offset-4 [overflow-wrap:anywhere] hover:underline">{name(r)}</Link> : <span className="font-medium">{name(r)}</span>}
        <span className="text-caption text-muted">{hasIp(r.asset) ? r.asset?.ip : r.asset ? t('noIp') : ''}</span>
      </div>
    ) },
    { id: 'cve', header: t('col.cve'), accessorFn: (r) => r.cve, cell: ({ row: { original: r } }) => <Link to={`/findings/${r.id}`} className="whitespace-nowrap font-medium text-accent underline-offset-4 hover:underline">{r.cve}</Link> },
    { id: 'product', header: t('col.product'), accessorFn: (r) => r.kev?.display ?? '', cell: ({ row: { original: r } }) => <span>{r.kev?.display ?? '–'}</span> },
    { id: 'status', header: t('col.status'), accessorFn: (r) => r.status, cell: ({ row: { original: r } }) => <StatusCell r={r} /> },
    // #825: the CVSS score sits under the exploited risk, never instead of it, in the same cell (no extra column: the table fits 1280 px as before)
    { id: 'severity', header: t('col.severity'), accessorFn: riskRank, cell: ({ row: { original: r } }) => (
      <RiskChip f={r} />
    ) },
    // hidden, sorted from "Sort by": highest first, no score last both ways
    { id: 'cvss', header: t('col.cvss'), accessorFn: (r) => r.cvss?.score, sortUndefined: 'last', sortDescFirst: true },
    { id: 'basis', header: t('col.basis'), accessorFn: (r) => r.basis, cell: ({ row: { original: r } }) => <span className={unverified(r) ? 'text-meta text-muted' : 'text-meta'}>{t(basisKey(r.basis))}</span> },
    { id: 'seen', header: t('col.lastSeen'), accessorFn: (r) => r.last_seen, sortDescFirst: true, cell: ({ row: { original: r } }) => <span className="whitespace-nowrap text-meta text-muted" title={fmtDateTime(r.last_seen)}>{fmtRelative(r.last_seen)}</span> },
  ]

  const panel = (tab: Tab) => (
    <>
      <div className="mb-3 grid gap-2">
        <div className="flex flex-wrap items-center gap-2">
          <div className="max-w-full overflow-x-auto">
            {tab === 'open' ? <Segmented<OpenStatus> label={t('filterLabel')} value={status} onChange={(v) => setParam('status', v === 'all' ? '' : v)} options={(['all', 'confirmed', 'suspected'] as OpenStatus[]).map((v) => ({ value: v, label: t(`filters.${v}`) }))} /> : null}
          </div>
          <div className="max-w-full overflow-x-auto">
            <Segmented<Certainty> label={t('certainty.label')} value={certainty} onChange={setCertainty} options={(['all', 'likely', 'unverified'] as Certainty[]).map((v) => ({ value: v, label: t(`certainty.${v}`) }))} />
          </div>
          {severity ? (
            <Button size="sm" onClick={() => setParam('severity', '')}><X />{t('clearSeverity', { severity: t(`common:severity.${severity}`) })}</Button>
          ) : null}
          {cve ? (
            <Button size="sm" onClick={() => setParam('cve', '')}><X />{t('clearCve', { cve })}</Button>
          ) : null}
          {fixKey ? (
            <Button size="sm" onClick={() => setParam('fix', '')}><X />{t('fix.clear')}</Button>
          ) : null}
        </div>
        {fixShown ? <p className="text-sm">{t('fix.filtered', { action: fixAction(fixShown) })}</p> : null}
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
            {shown.length > MAX_BULK ? <span className="text-meta text-danger">{t('bulk.tooMany', { max: MAX_BULK })}</span> : null}
            <Button ref={opener} size="sm" variant="primary" disabled={shown.length > MAX_BULK} onClick={() => setBulkOpen(true)}>{t('status.mark')}</Button>
            <Button size="sm" onClick={() => setSelected(new Set())}>{t('bulk.clear')}</Button>
          </div>
        ) : null}
      </div>
      {tab === 'handled' ? <div className="mb-3"><NotRelevantToggle count={rowsFor('handled', true).filter(isNotRelevant).length} shown={showNotRelevant} onChange={(v) => setParam('notrelevant', v ? 'show' : '')} /></div> : null}
      <QueryState query={q}>
        {() => tab === 'open' && rows.length === 0 && !filtersOn('open') ? (
          // docs/UI.md §6: nothing open is good news: the drawing, and what to do next (not a table with an empty row)
          <EmptyState art="no-findings" title={t('emptyOpen')} info={t('emptyHelpInfo')}
            action={<span className="flex flex-wrap justify-center gap-x-4 gap-y-2 text-sm">
              <Link to="/devices" className="text-accent underline underline-offset-4">{t('emptyDevices')}</Link>
              <Link to="/settings/scanning" className="text-accent underline underline-offset-4">{t('emptyScan')}</Link>
            </span>}>
            {t('emptyHelp')}
          </EmptyState>
        ) : (
          <DataTable
            caption={t('caption')}
            data={rows}
            columns={columns}
            initialSort={[{ id: 'severity', desc: true }]}
            sortSelect
            hiddenColumns={['cvss']}
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
                  <span className="text-meta text-muted">{r.kev?.display ?? '–'}</span>
                  <div className="flex flex-wrap items-center gap-x-3 gap-y-1 text-meta">
                    <RiskChip f={r} />
                    <span>{t(basisKey(r.basis))}</span>
                    <span className="text-muted">{fmtRelative(r.last_seen)}</span>
                  </div>
                </div>
              </div>
            )}
            rowTone={(r) => (r.status === 'confirmed' ? 'danger' : r.status === 'suspected' && !unverified(r) ? 'warn' : undefined)}
            // docs/UI.md §6: a filter that hides every row says so and clears it; the other lists say plainly that they are empty
            filtered={filtersOn(tab)}
            onClearFilters={clearFilters}
            emptyFiltered={cve ? (
              <span className="inline-flex flex-wrap items-center justify-center gap-x-2 gap-y-1">
                {t('emptyCve', { cve })}
                <Button size="sm" variant="link" onClick={clearFilters}>{t('common:table.clearFilters')}</Button>
              </span>
            ) : undefined}
            empty={t('emptyFilter')}
          />
        )}
      </QueryState>
    </>
  )

  const toFix = useToFix()
  // kien G8, review r1 of #943: a link that carries a finding filter (?cve=, ?fix=, the old shapes of the CVE page, Home and the device
  // page) opens the findings table with it, never To fix, which would drop it
  const filterTab = !params.get('tab') && (params.get('cve') || params.get('fix')) ? 'open' : null
  useEffect(() => { if (filterTab) { params.set('tab', filterTab); setParams(params, { replace: true }) } }, [filterTab, params, setParams])
  const toFixDevices = (toFix.data?.devices ?? []).filter((x) => !device || x.asset.id === device)
  const need = (q.data?.version_needed ?? []).filter((x) => !device || x.asset_id === device)
  const unc = (q.data?.unchecked ?? []).filter((x) => !device || x.asset_id === device)
  const inputCount = need.length + unc.length + toFixDevices.reduce((n, x) => n + unproved(x).length, 0)
  // review r1 of #943: never "nothing needs your input" while the unproved matches are unread or failed
  const inputPanel = (
    <QueryState query={q}>
      {() => inputCount === 0 && toFix.data ? (
        <EmptyState title={t('input.empty')}>{t('input.emptyBody')}</EmptyState>
      ) : (
        <div className="grid gap-6">
          {need.length ? <VersionNeededList items={need} /> : null}
          {unc.length ? <UncheckedList items={unc} /> : null}
          {toFix.isError ? <p role="alert" className="text-sm text-danger">{t('input.toFixError', { reason: errMsg(toFix.error) })}</p>
            : toFix.isPending ? <p className="text-sm text-muted">{t('input.toFixPending')}</p> : <UnprovedList devices={toFixDevices} />}
          {toFix.data?.truncated ? <p className="text-meta text-muted">{t('input.truncated')}</p> : null}
        </div>
      )}
    </QueryState>
  )
  return (
    <>
      <PageHeader
        title={!items ? t('titleLoading') : open === 0 ? t('titleNone') : t('title', { count: open, confirmed })}
        stories={['S-MIT-1', 'S-SCAN-3']}
        meta={t('intro')}
        info={<><p>{t('introInfo')}</p><p>{t('introStatus')}</p></>}
        actions={<SampleDataNote />}
      />
      {kpis.length ? <KpiStrip label={t('kpi.label')} items={kpis} /> : null}
      <PlanLine />
      <PageTabs label={t('tabs.label')} tabs={[
        // kien G8: To fix (by device, then what to do) is the default; what only a person can settle is Needs your input
        { id: 'fix', label: t('tabs.fix'), panel: <ToFixTab q={toFix} /> },
        { id: 'input', label: t('tabs.input'), panel: inputPanel, badge: inputCount ? { count: inputCount, label: t('tabs.inputBadge') } : undefined },
        { id: 'open', label: t('tabs.open'), panel: panel('open'), badge: { count: confirmed, label: t('tabs.openBadge') } },
        { id: 'accepted', label: t('tabs.accepted'), panel: panel('accepted') },
        { id: 'handled', label: t('tabs.handled'), panel: panel('handled') },
      ]} />
      <BulkDialog ids={shown} open={bulkOpen} onOpenChange={setBulkOpen} opener={opener} onDone={() => setSelected(new Set())} />
    </>
  )
}

/** D-613 (S-TIER-1): one line to Updates to plan when updates there fix CVEs not exploited yet; those are never findings. M2-9 (walk
 * n74): each number links to the tab that shows that many updates: "1 update to plan fixes CVEs likely to be exploited" opens Likely
 * (its heading says "1 update to plan for CVEs likely to be exploited"), "(3 in all)" opens All; no likely one: the count opens All. */
function PlanLine() {
  const { t } = useTranslation('findings')
  const n = usePlan().data
  if (!n?.compared || n.items.length === 0) return null
  const all = n.items.length
  const likely = n.items.filter((i) => i.likely > 0).length
  const link = 'text-accent underline underline-offset-4'
  // empty-guard: PlanLine returns null when the plan has no item, so all is at least 1
  if (likely === 0) return <p className="mb-4 text-sm"><Link to="/plan?tier=all" className={link}>{t('plan.line', { count: all })}</Link></p>
  return (
    <p className="mb-4 text-sm">
      <Link to="/plan?tier=likely" className={link}>{t('plan.lineLikely', { count: likely })}</Link>
      {likely < all ? <>{' ('}<Link to="/plan?tier=all" className={link}>{t('plan.lineAll', { count: all })}</Link>{')'}</> : null}
    </p>
  )
}

/** D-500 (S-INV-2): a software on the exploited list without a usable version is ONE line here, not one finding per CVE. */
function VersionNeededList({ items }: { items: VersionNeeded[] }) {
  const { t } = useTranslation('findings')
  return (
    <section aria-labelledby="version-needed-title">
    <Notice tone="warn" title={<span id="version-needed-title">{t('versionNeeded.title', { count: items.length })}</span>} info={t('versionNeeded.helpInfo')}>
      <p>{t('versionNeeded.help')}</p>
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
    </Notice>
    </section>
  )
}

export default function FindingsPage() {
  return <RequireModule module="findings" page><List /></RequireModule>
}
