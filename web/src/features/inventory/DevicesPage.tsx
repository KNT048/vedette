import { createElement, useDeferredValue, useEffect, useMemo, useRef, useState } from 'react'
import { Link, Navigate, useNavigate, useSearchParams } from 'react-router'
import { useTranslation } from 'react-i18next'
import { toast } from 'sonner'
import { Download, Plus, Settings2 } from 'lucide-react'
import { slotComponents } from '@/app/feature'
import { PageHeader } from '@/components/common/PageHeader'
import { InfoTip } from '@/components/common/InfoTip'
import { PageTabs } from '@/components/common/PageFrame'
import { DataTable, type ColumnDef } from '@/components/common/DataTable'
import { groupState, useRowSelection } from '@/components/common/Selection'
import { Slot } from '@/components/common/Slot'
import { EmptyState, ModuleOff, QueryState, RequireModule, SampleDataNote } from '@/components/common/States'
import { Chip } from '@/components/common/StatusChip'
import { Tooltip } from '@/components/ui/tooltip'
import { hasToken, TokenSearch, type TokenChip } from '@/components/common/TokenSearch'
import { Button, buttonVariants } from '@/components/ui/button'
import { Checkbox } from '@/components/ui/checkbox'
import { download } from '@/lib/api'
import { fmtDateTime, fmtRelative } from '@/lib/format'
import { useCan } from '@/lib/session'
import { cn } from '@/lib/utils'
import { categoryLabel, categoryOf, kindLabel } from '@/lib/deviceTypes'
import { AddDialog, METHODS, type Method } from './AddDialog'
import { usePossibleSame, useDevices, useSettings } from './api'
import { deviceKeys, feedsOfRow, filterDevices, fromOldUrl, matchSoftware, softwareValues, type SameIds } from './deviceQuery'
import { errMsg, kindIcon, shownKind } from './kinds'
import { declaredSoftwareOnly, nameOf } from './nameOf'
import { PendingPanel } from './PendingPanel'
import { SameChip } from './SameDevice'
import type { DeviceRow } from './types'

/** Where the scan feature (#850) plugs "Scan selected" / "Scan the LAN now" into the Devices list: a component registered as
 *  `slots['devices.actions']` gets `{ selectedIds: string[]; selected: DeviceRow[]; clearSelection: () => void }` (selected: the rows
 *  themselves, so a button can leave out the devices it may not touch and say why, #877 r1 M2). While nothing is registered the list has
 *  no selection column. The device page has `device.actions` (`{ assetId }`) for "Check this device now". */
export const DEVICES_ACTIONS_SLOT = 'devices.actions'

/** Type cell (D-511): icon, type, and the category when it says more than the type ("Switch Network", not "Server Servers");
 *  a guess says "likely" and its evidence on hover. */
function TypeCell({ d, dense }: { d: DeviceRow; dense?: boolean }) {
  const { t } = useTranslation('inventory')
  const { kind, guessed } = shownKind(d)
  const type = kindLabel(kind)
  const cat = kind === 'unknown' ? '' : categoryLabel(categoryOf(kind))
  const saysMore = cat && !cat.toLowerCase().startsWith(type.toLowerCase().slice(0, 4))
  return (
    <span className="inline-flex items-center gap-x-1.5 whitespace-nowrap" title={cat && guessed && d.guess?.evidence ? `${cat}: ${d.guess.evidence}` : (guessed ? d.guess?.evidence : cat) || undefined}>
      {createElement(kindIcon(kind), { className: 'size-4 shrink-0 text-muted', 'aria-hidden': true })}
      <span>{type}</span>
      {guessed ? <Chip tone="off">{t('guess.likely')}</Chip> : null}
      {saysMore && !dense ? <span className="text-caption text-muted">{cat}</span> : null}
    </span>
  )
}

/** Maker and model, without saying the maker twice when the model already starts with it ("Fortinet FortiGate 60F" stays, a
 *  model "HP LaserJet Pro" under maker "HP" is not "HP HP LaserJet Pro"). */
function hardwareLine(d: DeviceRow) {
  const vendor = d.vendor?.value ?? ''
  const model = d.model?.value ?? ''
  if (vendor && model.toLowerCase().startsWith(vendor.toLowerCase())) return model
  return [vendor, model].filter(Boolean).join(' ')
}

const FEED_ORDER = ['osquery', 'wazuh', 'snmp', 'scan', 'passive', 'manual'] as const
/** Sources cell (#849): which feeds report on the device, in the order they win (agent, SNMP, scan, passive), and "low confidence"
 *  when the weakest value is a guess. The device page has every value with its own source and confidence. */
function SourcesCell({ d, compact }: { d: DeviceRow; compact?: boolean }) {
  const { t } = useTranslation('inventory')
  const feeds = feedsOfRow(d)
  const list = FEED_ORDER.filter((f) => feeds.has(f)).map((f) => t(`search.short.${f}`))
  if (!list.length) return <span className="text-muted">–</span>
  const low = (d.summary?.confidence ?? 1) < 0.5
  const lowNote = low ? <span className="text-warn"> {t('search.lowConfidence')}</span> : null
  if (!compact || list.length === 1) return <span className="whitespace-nowrap text-meta text-muted">{list.join(', ')}{lowNote}</span>
  // One line on a desktop row (#849 review): the source that wins and "+2" for the eye; the whole list is read out (sr-only), the mouse
  // gets it in a tooltip that does not repeat it to a screen reader (describe={false}); no extra Tab stop. The device page has each value.
  const all = list.join(', ')
  return (
    <span className="whitespace-nowrap text-meta text-muted">
      <Tooltip content={all} side="top" describe={false}>
        <span aria-hidden className="inline-flex items-center gap-1"><span>{list[0]}</span><span className="tabular-nums">{`+${list.length - 1}`}</span></span>
      </Tooltip>
      <span className="sr-only">{all}</span>{lowNote}
    </span>
  )
}

/** "5 min. ago": the short relative time of a dense row; the exact time is in the title. */
function shortAgo(iso: string, now: number, locale: string) {
  const diff = (new Date(iso).getTime() - now) / 1000
  const abs = Math.abs(diff)
  const rtf = new Intl.RelativeTimeFormat(locale, { numeric: 'auto', style: 'narrow' })
  if (abs < 60) return rtf.format(0, 'second')
  if (abs < 3600) return rtf.format(Math.round(diff / 60), 'minute')
  if (abs < 86400) return rtf.format(Math.round(diff / 3600), 'hour')
  return rtf.format(Math.round(diff / 86400), 'day')
}

/** `dense` (a desktop row, one line): no ⓘ; the explanation is read out with the chip (sr-only) and shown to the mouse in a Tooltip that
 *  does not repeat it (#849 review L1). Elsewhere (phone rows) the chip keeps its ⓘ; the device page too. */
function NameChips({ d, dense }: { d: DeviceRow; dense?: boolean }) {
  const { t } = useTranslation('inventory')
  const tip = (chip: React.ReactNode, topic: string, text: string) => (dense
    ? <span className="inline-flex"><Tooltip content={text} side="top" describe={false}><span>{chip}</span></Tooltip><span className="sr-only">{text}</span></span>
    : <span className="inline-flex items-center gap-1">{chip}<InfoTip topic={topic}>{text}</InfoTip></span>)
  return (
    <>
      {d.is_box ? tip(<Chip tone="accent">{t('box.badge')}</Chip>, t('box.badge'), t('box.noDelete')) : null}
      {d.suspicious ? <Chip tone="warn">{t('chip.suspicious')}</Chip> : null}
      {d.fragile ? tip(<Chip tone="off">{t('chip.fragile')}</Chip>, t('chip.fragile'), t('chip.fragileHint')) : null}
    </>
  )
}

/** The query of both lists, kept in ?q= so a link, a reload and Back keep it. The box reads a local copy: a router update is a
 *  transition, and a controlled input fed straight from the URL drops keystrokes typed before it lands. A ?q= this page did not
 *  write itself (Back, a link, the old-URL redirect) replaces the copy. */
function useDeviceQuery() {
  const [params, setParams] = useSearchParams()
  const inUrl = params.get('q') ?? ''
  const [q, setLocal] = useState(inUrl)
  const written = useRef<string[]>([])
  useEffect(() => {
    const i = written.current.indexOf(inUrl)
    if (i >= 0) { written.current.splice(0, i + 1); return }
    written.current = []
    setLocal(inUrl)
  }, [inUrl])
  const setQ = (v: string) => {
    setLocal(v)
    const next = v.trim() ? v : ''
    written.current.push(next)
    setParams((p) => { const n = new URLSearchParams(p); if (next) n.set('q', next); else n.delete('q'); return n }, { replace: true })
  }
  return { q, setQ, clear: () => setQ('') }
}
type Query = ReturnType<typeof useDeviceQuery>

/** The search box of both lists. */
function DeviceSearch({ rows, now, query, same }: { rows: DeviceRow[]; now: number; query: Query; same: SameIds }) {
  const { t } = useTranslation('inventory')
  const keys = useMemo(() => deviceKeys(rows, now, same), [rows, now, same])
  const count = (key: string, value: string) => keys.find((x) => x.key === key)?.values?.find((v) => v.value === value)?.count
  const chips: TokenChip[] = [
    { token: 'fragile', label: t('search.chip.fragile'), count: rows.filter((d) => d.fragile).length },
    { token: 'source:snmp', label: t('search.chip.snmp'), count: count('source', 'snmp') },
    { token: 'source:osquery', label: t('search.chip.osquery'), count: count('source', 'osquery') },
    { token: 'source:manual', label: t('search.chip.manual'), count: count('source', 'manual') },
    { token: 'has:findings', label: t('search.chip.findings'), count: count('has', 'findings') },
    { token: 'possible:same', label: t('search.chip.same'), count: count('possible', 'same') }, // D-599: rows to merge or keep separate
  ]
  // A chip that would show 0 is left out (To review would read "SNMP 0, osquery 0, Manual 0"), unless it is on (#849 review L11).
  const shownChips = chips.filter((c) => c.count !== 0 || hasToken(query.q, c.token))
  return <TokenSearch value={query.q} onChange={query.setQ} keys={keys} chips={shownChips} label={t('search.label')} placeholder={t('search.placeholder')} chipsLabel={t('search.chipsLabel')} />
}

/** "12 of 40 devices", read out as the list changes (WCAG 4.1.3): the live region is always there (empty without a search), so the
 *  first change and "0 of 40" are announced too; the Clear button shows only while something matches (the empty table has its own). */
function MatchLine({ q, shown, total, onClear }: { q: string; shown: number; total: number; onClear: () => void }) {
  const { t } = useTranslation('inventory')
  return (
    <div className={q ? 'flex flex-wrap items-center gap-x-3 text-meta text-muted' : 'sr-only'}>
      <span role="status" aria-live="polite" className="tabular-nums">{q ? t('search.matches', { shown, count: total }) : ''}</span>
      {q && shown ? <Button size="sm" variant="link" onClick={onClear}>{t('search.clear')}</Button> : null}
    </div>
  )
}

/** Devices: the approved list (#849). */
function DevicesList({ rows, now, query, same }: { rows: DeviceRow[]; now: number; query: Query; same: SamePairsBy }) {
  const { t, i18n } = useTranslation('inventory')
  const navigate = useNavigate()
  const { q, clear } = query
  const deferred = useDeferredValue(q)
  const shown = useMemo(() => filterDevices(rows, deferred, now, same.ids), [rows, deferred, now, same.ids])
  const swWanted = useMemo(() => softwareValues(deferred), [deferred])
  const selecting = slotComponents(DEVICES_ACTIONS_SLOT).length > 0
  const [sel, ops] = useRowSelection()
  const shownIds = shown.map((d) => d.id)
  const dash = <span className="text-muted">–</span>
  const nameLink = (d: DeviceRow, cls = '') => <Link to={`/devices/${d.id}`} onClick={(e) => e.stopPropagation()} className={cn('font-medium text-accent underline-offset-4 hover:underline', cls)}>{nameOf(d, kindLabel(d.kind))}</Link>
  const columns: ColumnDef<DeviceRow>[] = [
    ...(selecting ? [{
      id: 'select', enableSorting: false,
      header: () => <Checkbox aria-label={t('select.all')} checked={groupState(shownIds, sel)} onCheckedChange={(v) => (v === true ? ops.add(shownIds) : ops.remove(shownIds))} />,
      cell: ({ row }) => <span onClick={(e) => e.stopPropagation()}><Checkbox aria-label={t('select.one', { name: nameOf(row.original, kindLabel(row.original.kind)) })} checked={sel.has(row.original.id)} onCheckedChange={(v) => ops.toggle(row.original.id, v === true)} /></span>,
    } satisfies ColumnDef<DeviceRow>] : []),
    { id: 'name', header: t('col.name'), accessorFn: (d) => nameOf(d, kindLabel(d.kind)), cell: ({ row }) => (
      <div className="flex items-center gap-x-2 whitespace-nowrap">{nameLink(row.original, 'whitespace-nowrap')}<NameChips d={row.original} dense /><SameChip id={row.original.id} others={same.others.get(row.original.id) ?? []} /></div>
    ) },
    { id: 'ip', header: t('col.ip'), accessorFn: (d) => d.ip, cell: ({ row }) => <span className="whitespace-nowrap tabular-nums">{row.original.ip}</span> },
    { id: 'kind', header: t('col.kind'), accessorFn: (d) => { const k = shownKind(d).kind; return `${kindLabel(k)} ${categoryLabel(categoryOf(k))}` }, cell: ({ row }) => <TypeCell d={row.original} dense /> },
    // #849 review: one line per row at 1280. Make, model and OS share a column, cut with an ellipsis (the whole text on hover, the
    // device page has each value); the OS in muted text after the model.
    { id: 'hw', header: t('col.device'), accessorFn: (d) => [d.vendor?.value, d.model?.value, d.os?.value].filter(Boolean).join(' '), cell: ({ row }) => {
      // #849 review r2 M1: the OS or firmware version decides the CVE match, so it is never the part cut: the maker and model shrink
      // (ellipsis), the OS keeps its width. The whole text stays in the DOM (screen readers read it) and the name opens the device.
      const d = row.original
      const hw = hardwareLine(d)
      const os = d.os?.value ?? ''
      if (!hw && !os) return dash
      return (
        <span className="flex max-w-64 items-baseline gap-1.5 2xl:max-w-md" title={[hw, os].filter(Boolean).join(', ')}>
          {hw ? <span className="min-w-0 truncate">{hw}</span> : null}
          {os ? <span className="shrink-0 whitespace-nowrap text-muted">{os}</span> : null}
        </span>
      )
    } },
    // M2: with software: in the search the list answers "which devices run it, at which version" (the old Software tab), as runZero does.
    ...(swWanted.length ? [{
      id: 'matched', header: t('col.matched'), accessorFn: (d: DeviceRow) => matchSoftware(d, swWanted).map((x) => x.display).join(' '),
      cell: ({ row }: { row: { original: DeviceRow } }) => {
        const m = matchSoftware(row.original, swWanted)
        if (!m.length) return dash
        const line = (x: DeviceRow['software'][number]) => `${x.display} ${x.version ?? t('software.noVersion')}`
        return (
          <span className="flex items-center gap-1.5 whitespace-nowrap" title={m.map((x) => `${line(x)} (${t(`common:source.${x.source}`, { defaultValue: x.source })})`).join('\n')}>
            <span className="font-medium">{m[0]!.display}</span><span className="tabular-nums">{m[0]!.version ?? <span className="text-muted">{t('software.noVersion')}</span>}</span>
            {m.length > 1 ? <span className="text-meta text-muted tabular-nums">{`+${m.length - 1}`}</span> : null}
          </span>
        )
      },
    } satisfies ColumnDef<DeviceRow>] : []),
    { id: 'source', header: t('col.sources'), accessorFn: (d) => FEED_ORDER.filter((f) => feedsOfRow(d).has(f)).join(' '), cell: ({ row }) => <SourcesCell d={row.original} compact /> },
    { id: 'seen', header: t('col.lastSeen'), accessorFn: (d) => new Date(d.last_seen).getTime(), cell: ({ row }) => <time className="whitespace-nowrap text-meta text-muted" dateTime={row.original.last_seen} title={fmtDateTime(row.original.last_seen)}>{shortAgo(row.original.last_seen, now, i18n.language || 'en')}</time> },
  ]
  return (
    <section aria-label={t('tabs.devices')} className="grid min-w-0 gap-3">
      <DeviceSearch rows={rows} now={now} query={query} same={same.ids} />
      <MatchLine q={q} shown={shown.length} total={rows.length} onClear={clear} />
      {selecting ? <div className="flex flex-wrap items-center gap-2"><Slot name={DEVICES_ACTIONS_SLOT} props={{ selectedIds: [...sel], selected: rows.filter((d) => sel.has(d.id)), clearSelection: ops.clear }} /></div> : null}
      <DataTable caption={t('table.caption')} data={shown} columns={columns} initialSort={[{ id: 'seen', desc: true }]}
        onRowClick={(d) => void navigate(`/devices/${d.id}`)}
        empty={t('table.emptyApproved')} filtered={!!q} onClearFilters={clear}
        mobileRow={(d) => {
          const hw = [d.vendor?.value, d.model?.value].filter(Boolean).join(' ')
          return (
            <div className="grid gap-1.5">
              <div className="flex flex-wrap items-center gap-x-2 gap-y-1">
                {selecting ? <Checkbox aria-label={t('select.one', { name: nameOf(d, kindLabel(d.kind)) })} checked={sel.has(d.id)} onCheckedChange={(v) => ops.toggle(d.id, v === true)} /> : null}
                {nameLink(d, 'min-w-0 [overflow-wrap:anywhere]')}
                <NameChips d={d} />
              </div>
              <div className="flex flex-wrap items-center gap-x-3 gap-y-1 text-meta text-muted">
                <TypeCell d={d} />
                {d.ip && d.ip !== '—' ? <span className="tabular-nums">{d.ip}</span> : null}
                {hw ? <span className="min-w-0 [overflow-wrap:anywhere]">{hw}</span> : null}
              </div>
              {swWanted.length ? (() => {
                // the phone's Matched software line (#849 review r2 M2): what software: found on this device, with its version
                const m = matchSoftware(d, swWanted)
                return m.length ? <p className="text-meta">{m.map((x) => `${x.display} ${x.version ?? t('software.noVersion')}`).join(', ')}</p> : null
              })() : null}
              <div className="flex flex-wrap items-center gap-x-3 gap-y-1 text-caption text-muted">
                <SourcesCell d={d} />
                <time dateTime={d.last_seen}>{fmtRelative(d.last_seen)}</time>
              </div>
            </div>
          )
        }} />
    </section>
  )
}

/** To review: found by a scan or by listening, not approved yet (S-INV-3). Same search box. */
function ReviewList({ rows, now, notifyNew, notifyAvailable, query, same }: { rows: DeviceRow[]; now: number; notifyNew: boolean; notifyAvailable: boolean; query: Query; same: SamePairsBy }) {
  const { q, clear } = query
  const deferred = useDeferredValue(q)
  const shown = useMemo(() => filterDevices(rows, deferred, now, same.ids), [rows, deferred, now, same.ids])
  return (
    <section className="grid min-w-0 gap-3">
      <PendingPanel items={shown} total={rows.length} notifyNew={notifyNew} notifyAvailable={notifyAvailable} sameAs={same.others}
        search={<><DeviceSearch rows={rows} now={now} query={query} same={same.ids} /><MatchLine q={q} shown={shown.length} total={rows.length} onClear={clear} /></>} filtered={!!q} onClear={clear} />
    </section>
  )
}

/** D-599 (#829): the pairs of GET /inventory/possible-same by device: the names of the others, and every id in a pair. One cached read. */
type SamePairsBy = { ids: SameIds; others: ReadonlyMap<string, string[]> }
function usePairsByDevice(): SamePairsBy {
  const q = usePossibleSame()
  return useMemo(() => {
    const others = new Map<string, string[]>()
    for (const p of q.data?.items ?? []) {
      others.set(p.a.id, [...(others.get(p.a.id) ?? []), p.b.name])
      others.set(p.b.id, [...(others.get(p.b.id) ?? []), p.a.name])
    }
    return { ids: new Set(others.keys()), others }
  }, [q.data])
}

/** The empty state. When a range is saved it says Vedette is watching it instead of asking for one again (S-INV-1); the settings are read only here, and only by an admin. */
function NoDevices({ boxOnly, canOp, canAdmin, needRole, onAdd }: { boxOnly: boolean; canOp: boolean; canAdmin: boolean; needRole: string | undefined; onAdd: (m: Method) => void }) {
  const { t } = useTranslation('inventory')
  const st = useSettings(canAdmin)
  const ranges = canAdmin && st.data ? (st.data.lan_ranges.length > 0 ? 'saved' : 'none') : 'unknown'
  const kind = ranges === 'saved' ? 'Watching' : ranges === 'none' ? '' : 'Neutral'
  const body = (boxOnly ? 'empty.bodyBoxOnly' : 'empty.body') + kind
  return (
    <EmptyState art={boxOnly ? undefined : 'no-devices'} title={boxOnly ? t('empty.titleBoxOnly') : t('empty.title')} info={t('empty.info')} action={<div className="flex flex-wrap gap-2"><Button variant="primary" disabled={!canOp} title={needRole} onClick={() => onAdd('manual')}>{t('add.open')}</Button><Button disabled={!canOp} title={needRole} onClick={() => onAdd('csv')}>{t('import.open')}</Button>{ranges === 'none' ? <Link to="/devices/setup?tab=scope#range-input" className={cn(buttonVariants({ variant: 'secondary' }))}>{t('empty.range')}</Link> : null}</div>}>{t(body)}</EmptyState>
  )
}

function Body() {
  const { t } = useTranslation('inventory')
  const [params, setParams] = useSearchParams()
  const q = useDevices()
  const query = useDeviceQuery()
  const same = usePairsByDevice()
  const canOp = useCan('operator')
  const canAdmin = useCan('admin')
  const needRole = canOp ? undefined : t('common:needRole', { role: t('common:role.operator') })
  const rawAdd = params.get('add')
  const addMethod = METHODS.find((m) => m === rawAdd) ?? (rawAdd ? 'manual' : null)
  const setAdd = (m: Method | null) => { const p = new URLSearchParams(params); if (m) p.set('add', m); else p.delete('add'); setParams(p, { replace: true }) }
  const old = fromOldUrl(params)
  const lists = useMemo(() => {
    const items = q.data?.items ?? []
    const real = items.filter((d) => !declaredSoftwareOnly(d))
    return { approved: real.filter((d) => d.approved), pending: real.filter((d) => !d.approved), declared: items.length - real.length }
  }, [q.data])
  if (old) return <Navigate replace to={{ search: `?${old}` }} />
  const all = lists.approved.length + lists.pending.length
  // Declared software is not a device (#849): one line says where it is, also when it is all there is (#849 review L13).
  const declaredLine = lists.declared > 0 ? (
    <p className="mt-4 text-meta text-muted">
      {t('declaredPage.elsewhere', { count: lists.declared })}{' '}
      <Link to="/settings/declared-software" className="text-accent underline-offset-4 hover:underline">{t('declaredPage.open')}</Link>
    </p>
  ) : null
  const pending = lists.pending.length
  const title = !q.data ? t('list.titleLoading') : all === 0 ? t('list.titleEmpty') : all === 1 && lists.approved[0]?.is_box ? t('list.titleBoxOnly') : pending > 0 ? t('list.title', { count: all, pending }) : t('list.titleAllApproved', { count: all })

  return (
    <>
      <PageHeader title={title} stories={['S-INV-1', 'S-INV-2', 'S-INV-3', 'S-INV-4']}
        meta={<span className="inline-flex flex-wrap items-center gap-2"><SampleDataNote />{t('list.meta')}</span>} info={t('list.metaInfo')}
        actions={
          <>
            <Button onClick={() => void download('/inventory/export.csv', 'vedette-devices.csv').catch((e: unknown) => toast.error(errMsg(e)))}><Download />{t('export')}</Button>
            {canAdmin ? <Link to="/devices/setup" className={cn(buttonVariants({ variant: 'secondary' }))}><Settings2 />{t('setup.link')}</Link> : null}
            <Button variant="primary" disabled={!canOp} title={needRole} onClick={() => setAdd('manual')}><Plus />{t('add.open')}</Button>
          </>
        } />
      <QueryState query={q}>
        {(d) => {
          if (all === 0) return <><NoDevices boxOnly={false} canOp={canOp} canAdmin={canAdmin} needRole={needRole} onAdd={setAdd} />{declaredLine}</>
          const now = q.dataUpdatedAt
          return (
            <>
              {all === 1 && lists.approved[0]?.is_box ? (
                <div className="mb-6"><NoDevices boxOnly canOp={canOp} canAdmin={canAdmin} needRole={needRole} onAdd={setAdd} /></div>
              ) : null}
              <PageTabs label={t('tabs.label')} tabs={[
                { id: 'devices', label: t('tabs.devices'), panel: <DevicesList rows={lists.approved} now={now} query={query} same={same} /> },
                { id: 'review', label: t('tabs.review'), panel: <ReviewList rows={lists.pending} now={now} notifyNew={d.notify_new} notifyAvailable={d.notify_available} query={query} same={same} />, badge: { count: pending, label: t('tabs.reviewBadge') } },
              ]} />
              {declaredLine}
            </>
          )
        }}
      </QueryState>
      {/* M1: ?add= opens the dialog only for someone who may add (a viewer's old ?tab=add link lands on the list). The URL follows the
          method picked, so a reload reopens it there (L12); the dialog is keyed on open/closed only, so that does not remount it. */}
      <AddDialog key={addMethod && canOp ? 'open' : 'closed'} open={!!addMethod && canOp} method={addMethod ?? 'manual'} onMethod={setAdd} onOpenChange={(o) => { if (!o) setAdd(null) }} />
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
