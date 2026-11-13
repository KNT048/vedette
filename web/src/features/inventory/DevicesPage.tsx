import { createElement, useMemo, useState } from 'react'
import { Link, useNavigate, useSearchParams } from 'react-router'
import { useTranslation } from 'react-i18next'
import { toast } from 'sonner'
import { Download, Plus, Settings2 } from 'lucide-react'
import { PageHeader } from '@/components/common/PageHeader'
import { KpiStrip, PageTabs } from '@/components/common/PageFrame'
import { DataTable, type ColumnDef } from '@/components/common/DataTable'
import { EmptyState, ModuleOff, QueryState, RequireModule, SampleDataNote } from '@/components/common/States'
import { SourceBadge } from '@/components/common/SourceBadge'
import { Chip } from '@/components/common/StatusChip'
import { Button, buttonVariants } from '@/components/ui/button'
import { Segmented } from '@/components/ui/segmented'
import { Label, Select } from '@/components/ui/input'
import { download } from '@/lib/api'
import { fmtDateTime, fmtRelative, rawProductLine } from '@/lib/format'
import { useCan } from '@/lib/session'
import { cn } from '@/lib/utils'
import { categoryLabel, categoryOf, DEVICE_CATEGORIES, kindLabel } from '@/lib/deviceTypes'
import { AddDeviceDialog } from './AddDeviceDialog'
import { AddWays } from './AddWays'
import { useDevices, useSettings } from './api'
import { ImportDialog } from './ImportDialog'
import { errMsg, kindIcon, shownKind } from './kinds'
import { nameOf } from './nameOf'
import { PendingPanel } from './PendingPanel'
import type { DeviceRow, DevicesResponse } from './types'

// D-471: the All devices filter lives in ?show= so a KPI cell, a toast and a shared link open the same view.
const FILTERS = ['all', 'recent', 'manual', 'agent', 'fragile'] as const
type Filter = (typeof FILTERS)[number]
const DAY = 24 * 60 * 60 * 1000

/** Approved by a person (or osquery enrolment) in the last 24 hours: where a device someone just approved is found again (D-471). */
const recent = (d: DeviceRow, now: number) => !!d.approved_at && now - new Date(d.approved_at).getTime() < DAY
/** Reported by osquery or Wazuh: an agent is the source of its make/model/OS, or of some of its software. */
const fromAgent = (d: DeviceRow) => d.summary?.source === 'agent' || d.software.some((s) => s.source === 'agent')
const matches = (d: DeviceRow, f: Filter, now: number) => (f === 'recent' ? recent(d, now) : f === 'manual' ? d.origin === 'manual' : f === 'agent' ? fromAgent(d) : f === 'fragile' ? d.fragile : true)

/** The category a row is listed under: that of its type, or of what it most likely is while its type is unknown (D-511). */
const categoryOfRow = (d: DeviceRow) => categoryOf(shownKind(d).kind)

/** Type cell (D-511): icon, type and category; a guess says "likely" and its evidence on hover. */
function TypeCell({ d }: { d: DeviceRow }) {
  const { t } = useTranslation('inventory')
  const { kind, guessed } = shownKind(d)
  return (
    <span className="inline-flex flex-wrap items-center gap-x-1.5 gap-y-0.5" title={guessed ? d.guess?.evidence : undefined}>
      {createElement(kindIcon(kind), { className: 'size-4 shrink-0 text-muted', 'aria-hidden': true })}
      <span className="whitespace-nowrap">{kindLabel(kind)}</span>
      {guessed ? <Chip tone="off">{t('guess.likely')}</Chip> : null}
      {kind !== 'unknown' ? <span className="whitespace-nowrap text-[12px] text-muted">{categoryLabel(categoryOf(kind))}</span> : null}
    </span>
  )
}

function DevicesTable({ items, filter, category, now }: { items: DeviceRow[]; filter: Filter; category: string; now: number }) {
  const { t } = useTranslation('inventory')
  const navigate = useNavigate()
  const shown = useMemo(() => items.filter((d) => matches(d, filter, now) && (category === '' || categoryOfRow(d) === category)), [items, filter, category, now])
  const dash = <span className="text-muted">–</span>
  const columns: ColumnDef<DeviceRow>[] = [
    { id: 'name', header: t('col.name'), accessorFn: (d) => nameOf(d, kindLabel(d.kind)), cell: ({ row }) => {
      const d = row.original
      return (
        <div className="flex flex-wrap items-center gap-x-2 gap-y-1">
          <Link to={`/devices/${d.id}`} onClick={(e) => e.stopPropagation()} className="font-medium text-accent underline-offset-4 hover:underline">{nameOf(d, kindLabel(d.kind))}</Link>
          {d.is_box ? <Chip tone="accent" title={t('box.noDelete')}>{t('box.badge')}</Chip> : null}
          {!d.approved ? <Chip tone="warn">{t('chip.pending')}</Chip> : null}
          {d.suspicious ? <Chip tone="warn">{t('chip.suspicious')}</Chip> : null}
          {d.fragile ? <Chip tone="off" title={t('chip.fragileHint')}>{t('chip.fragile')}</Chip> : null}
        </div>
      )
    } },
    { id: 'ip', header: t('col.ip'), accessorFn: (d) => d.ip, cell: ({ row }) => <span className="whitespace-nowrap">{row.original.ip}</span> },
    { id: 'kind', header: t('col.kind'), accessorFn: (d) => { const k = shownKind(d).kind; return `${kindLabel(k)} ${categoryLabel(categoryOf(k))}` }, cell: ({ row }) => <TypeCell d={row.original} /> },
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
        const hw = [d.vendor?.value, d.model?.value].filter(Boolean).join(' ')
        return (
          <div className="grid gap-1.5">
            <div className="flex flex-wrap items-center gap-x-2 gap-y-1">
              <Link to={`/devices/${d.id}`} className="min-w-0 font-medium [overflow-wrap:anywhere] text-accent underline-offset-4 hover:underline">{nameOf(d, kindLabel(d.kind))}</Link>
              {d.is_box ? <Chip tone="accent">{t('box.badge')}</Chip> : null}
              {!d.approved ? <Chip tone="warn">{t('chip.pending')}</Chip> : null}
              {d.suspicious ? <Chip tone="warn">{t('chip.suspicious')}</Chip> : null}
              {d.fragile ? <Chip tone="off" title={t('chip.fragileHint')}>{t('chip.fragile')}</Chip> : null}
            </div>
            <div className="flex flex-wrap items-center gap-x-3 gap-y-1 text-[13px] text-muted">
              <TypeCell d={d} />
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

/** The All devices tab: one filter row (in ?show=) over the whole list. */
/** `now`: when the list was read, so "the last 24 h" does not move while the page is open. */
function AllDevices({ data, now }: { data: DevicesResponse; now: number }) {
  const { t } = useTranslation('inventory')
  const [params, setParams] = useSearchParams()
  const raw = params.get('show')
  const filter: Filter = FILTERS.find((f) => f === raw) ?? 'all'
  const setFilter = (f: Filter) => { const p = new URLSearchParams(params); if (f === 'all') p.delete('show'); else p.set('show', f); setParams(p, { replace: true }) }
  const count = (f: Filter) => data.items.filter((d) => matches(d, f, now)).length
  // D-511: filter by category, in ?cat=; only the categories some device is in are offered.
  const perCategory = new Map<string, number>()
  for (const d of data.items) perCategory.set(categoryOfRow(d), (perCategory.get(categoryOfRow(d)) ?? 0) + 1)
  const rawCat = params.get('cat') ?? ''
  const category = perCategory.has(rawCat) ? rawCat : ''
  const setCategory = (c: string) => { const p = new URLSearchParams(params); if (c === '') p.delete('cat'); else p.set('cat', c); setParams(p, { replace: true }) }
  return (
    <section aria-label={t('tabs.all')}>
      <div className="mb-3 flex flex-wrap items-end gap-3">
        <Segmented<Filter> label={t('filter.label')} value={filter} onChange={setFilter} options={FILTERS.map((f) => ({ value: f, label: t(`filter.${f}`, { count: f === 'all' ? data.counts.all : count(f) }) }))} />
        <span className="inline-flex items-center gap-2">
          <Label htmlFor="device-category" className="text-[13px] font-normal text-muted">{t('filter.category')}</Label>
          <Select id="device-category" className="w-auto" value={category} onChange={(e) => setCategory(e.target.value)}>
            <option value="">{t('filter.allCategories')}</option>
            {DEVICE_CATEGORIES.filter((c) => perCategory.has(c.id)).map((c) => <option key={c.id} value={c.id}>{`${c.label} (${perCategory.get(c.id)})`}</option>)}
          </Select>
        </span>
      </div>
      <DevicesTable items={data.items} filter={filter} category={category} now={now} />
    </section>
  )
}

type SoftwareRow = { key: string; display: string; raw: string | null; version: string | null; source: DeviceRow['software'][number]['source']; confidence: number; device: DeviceRow }

/** The Software tab (D-471): every software row of every device, so "which devices run Microsoft Office, at which version" is one search. */
function AllSoftware({ items }: { items: DeviceRow[] }) {
  const { t } = useTranslation('inventory')
  const rows = useMemo<SoftwareRow[]>(() => items.flatMap((d) => d.software.map((s) => ({
    key: `${d.id}/${s.id}`, display: s.display, raw: rawProductLine(s.display, s.vendor, s.product), version: s.version, source: s.source, confidence: s.confidence, device: d,
  }))), [items])
  if (!rows.length) return <EmptyState title={t('softwareTab.empty')}>{t('softwareTab.emptyBody')}</EmptyState>
  const device = (d: DeviceRow) => <Link to={`/devices/${d.id}`} onClick={(e) => e.stopPropagation()} className="font-medium text-accent underline-offset-4 [overflow-wrap:anywhere] hover:underline">{nameOf(d, kindLabel(d.kind))}</Link>
  const version = (v: string | null) => v || <span className="text-muted">{t('software.noVersion')}</span>
  const columns: ColumnDef<SoftwareRow>[] = [
    { id: 'name', header: t('software.name'), accessorFn: (r) => r.display, cell: ({ row }) => <div className="grid"><span className="font-medium">{row.original.display}</span>{row.original.raw ? <span className="text-[12px] text-muted">{row.original.raw}</span> : null}</div> },
    { id: 'version', header: t('software.version'), accessorFn: (r) => r.version ?? '', cell: ({ row }) => version(row.original.version) },
    { id: 'device', header: t('softwareTab.device'), accessorFn: (r) => `${nameOf(r.device, kindLabel(r.device.kind))} ${r.device.ip}`, cell: ({ row }) => device(row.original.device) },
    { id: 'source', header: t('obs.source'), accessorFn: (r) => r.confidence, cell: ({ row }) => <SourceBadge source={row.original.source} confidence={row.original.confidence} /> },
  ]
  return (
    <section aria-label={t('tabs.software')} className="grid gap-3">
      <p className="max-w-3xl text-[13px] text-muted">{t('softwareTab.description')}</p>
      <DataTable caption={t('softwareTab.caption')} data={rows} columns={columns} filterPlaceholder={t('softwareTab.search')} initialSort={[{ id: 'name', desc: false }]}
        mobileRow={(r) => (
          <div className="grid gap-1">
            <span className="text-sm font-medium [overflow-wrap:anywhere]">{r.display} {version(r.version)}</span>
            <span className="text-[13px]">{device(r.device)}</span>
            <span className="text-[12px] text-muted"><SourceBadge source={r.source} confidence={r.confidence} /></span>
          </div>
        )} />
    </section>
  )
}

/** The empty state. When a range is saved it says Vedette is watching it instead of asking for one again (S-INV-1); the settings are read only here, and only by an admin. */
function NoDevices({ boxOnly, canOp, canAdmin, needRole, onAdd, onImport }: { boxOnly: boolean; canOp: boolean; canAdmin: boolean; needRole: string | undefined; onAdd: () => void; onImport: () => void }) {
  const { t } = useTranslation('inventory')
  const st = useSettings(canAdmin)
  // Only an admin can read the settings: everyone else, and an admin while they load or fail, gets a text that claims nothing about ranges.
  const ranges = canAdmin && st.data ? (st.data.lan_ranges.length > 0 ? 'saved' : 'none') : 'unknown'
  const kind = ranges === 'saved' ? 'Watching' : ranges === 'none' ? '' : 'Neutral'
  const body = (boxOnly ? 'empty.bodyBoxOnly' : 'empty.body') + kind
  return (
    <EmptyState title={boxOnly ? t('empty.titleBoxOnly') : t('empty.title')} action={<div className="flex flex-wrap gap-2"><Button variant="primary" disabled={!canOp} title={needRole} onClick={onAdd}>{t('add.open')}</Button><Button disabled={!canOp} title={needRole} onClick={onImport}>{t('import.open')}</Button>{ranges === 'none' ? <Link to="/devices/setup" className={cn(buttonVariants({ variant: 'secondary' }))}>{t('empty.range')}</Link> : null}</div>}>{t(body)}</EmptyState>
  )
}

function Body() {
  const { t } = useTranslation('inventory')
  const q = useDevices()
  const canOp = useCan('operator')
  const canAdmin = useCan('admin')
  const [adding, setAdding] = useState(false)
  const [importing, setImporting] = useState(false)
  const c = q.data?.counts
  const needRole = canOp ? undefined : t('common:needRole', { role: t('common:role.operator') })
  const title = !c ? t('list.titleLoading') : c.all === 0 ? t('list.titleEmpty') : c.all === 1 && q.data?.items[0]?.is_box ? t('list.titleBoxOnly') : c.pending > 0 ? t('list.title', { count: c.all, pending: c.pending }) : t('list.titleAllApproved', { count: c.all })
  const ways = <AddWays canOp={canOp} canAdmin={canAdmin} needRole={needRole} onAdd={() => setAdding(true)} onImport={() => setImporting(true)} />

  return (
    <>
      <PageHeader title={title} stories={['S-INV-1', 'S-INV-2', 'S-INV-3', 'S-INV-4']}
        meta={<span className="inline-flex flex-wrap items-center gap-2"><SampleDataNote />{t('list.meta')}</span>}
        actions={
          <>
            <Button variant="primary" disabled={!canOp} title={needRole} onClick={() => setAdding(true)}><Plus />{t('add.open')}</Button>
            {/* Item 26b: next to "Add a device", and its name says the agents (osquery downloads, tokens) are there too. Admin only, like the page. */}
            {canAdmin ? <Link to="/devices/setup" className={cn(buttonVariants({ variant: 'secondary' }))}><Settings2 />{t('setup.link')}</Link> : null}
            <Button onClick={() => void download('/inventory/export.csv', 'vedette-devices.csv').catch((e: unknown) => toast.error(errMsg(e)))}><Download />{t('export')}</Button>
          </>
        } />
      <QueryState query={q}>
        {(d) => {
          if (d.counts.all === 0) return <><NoDevices boxOnly={false} canOp={canOp} canAdmin={canAdmin} needRole={needRole} onAdd={() => setAdding(true)} onImport={() => setImporting(true)} /><div className="mt-8">{ways}</div></>
          const now = q.dataUpdatedAt
          return (
            <>
              <KpiStrip label={t('kpi.label')} items={[
                { value: d.counts.all, label: t('kpi.devices'), to: '/devices?tab=all' },
                { value: d.counts.pending, label: t('kpi.review'), to: '/devices?tab=review' },
                // ponytail: counted from the listed rows (MaxListed = 2000); past that, add counts.recent on the server.
                { value: d.items.filter((x) => recent(x, now)).length, label: t('kpi.recent'), to: '/devices?tab=all&show=recent' },
                { value: d.counts.manual, label: t('kpi.manual'), to: '/devices?tab=all&show=manual' },
              ]} />
              {d.items.length === 1 && d.items[0]?.is_box ? (
                <div className="mb-6"><NoDevices boxOnly canOp={canOp} canAdmin={canAdmin} needRole={needRole} onAdd={() => setAdding(true)} onImport={() => setImporting(true)} /></div>
              ) : null}
              <PageTabs label={t('tabs.label')} tabs={[
                { id: 'all', label: t('tabs.all'), panel: <AllDevices data={d} now={now} /> },
                { id: 'review', label: t('tabs.review'), panel: <PendingPanel data={d} />, badge: { count: d.counts.pending, label: t('tabs.reviewBadge') } },
                { id: 'software', label: t('tabs.software'), panel: <AllSoftware items={d.items} /> },
                { id: 'add', label: t('tabs.add'), panel: ways },
              ]} />
            </>
          )
        }}
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
