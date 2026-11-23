import { createElement, useDeferredValue, useEffect, useMemo, useRef, useState } from 'react'
import { Link, Navigate, useNavigate, useSearchParams } from 'react-router'
import { useTranslation } from 'react-i18next'
import { toast } from 'sonner'
import { Download, GitMerge, MoreHorizontal, Plus, Settings2 } from 'lucide-react'
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
import { DownloadButton } from '@/components/common/DownloadButton'
import { Button, buttonVariants } from '@/components/ui/button'
import { Checkbox } from '@/components/ui/checkbox'
import { DropdownMenu, DropdownMenuContent, DropdownMenuItem, DropdownMenuTrigger } from '@/components/ui/dropdown-menu'
import { fmtDateTime, fmtRelative } from '@/lib/format'
import { useCan } from '@/lib/session'
import { cn } from '@/lib/utils'
import { categoryLabel, categoryOf, kindLabel } from '@/lib/deviceTypes'
import { AddDialog, METHODS, type Method } from './AddDialog'
import { usePossibleSame, useDevices, useSettings, useSoftwareMatches } from './api'
import { deviceKeys, feedsOfRow, filterDevices, fromOldUrl, matchSoftware, softwareMatches, softwareValues, type SameIds, type SoftwareMatches } from './deviceQuery'
import { errMsg, kindIcon, shownKind } from './kinds'
import { declaredSoftwareOnly, nameOf, neverSeen } from './nameOf'
import { RiskMarker, riskRank } from './RiskMarker'
import { PendingPanel } from './PendingPanel'
import { IgnoredPanel } from './IgnoreDevice'
import { SameChip } from './SameDevice'
import { MergeFlow, type MergeStart } from './MergeDialog'
import { MERGE_MAX_FROM, type Suggestion } from './mergeLogic'
import { SnmpNotices } from './SnmpCard'
import type { DeviceRow, ListSoftware, SoftwareName } from './types'

/** Where the scan feature (#850) plugs "Scan selected" / "Scan the LAN now" into the Devices list: a component registered as
 *  `slots['devices.actions']` gets `{ selectedIds: string[]; selected: DeviceRow[]; clearSelection: () => void }` (selected: the rows
 *  themselves, so a button can leave out the devices it may not touch and say why, #877 r1 M2). While nothing is registered the list has
 *  no selection column. The device page has `device.actions` (`{ assetId }`) for "Check this device now". */
export const DEVICES_ACTIONS_SLOT = 'devices.actions'

/** Type cell: icon, type, and the category when it says more than the type ("Switch Network", not "Server Servers");
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

/** Under the name: maker and model on one line cut with an ellipsis, then the OS. The OS or firmware version decides the CVE match, so it
 *  is never the part cut: it wraps in full ("Windows Server 2025 Standard Evaluation 10.0.26100.1742"). The whole text is also the title. */
function HardwareLine({ d }: { d: DeviceRow }) {
  const hw = hardwareLine(d)
  const os = d.os?.value ?? ''
  if (!hw && !os) return null
  return (
    <span className="flex flex-wrap items-baseline gap-x-1.5 text-meta text-muted" title={[hw, os].filter(Boolean).join(', ')}>
      {hw ? <span className="min-w-0 max-w-full truncate">{hw}</span> : null}
      {os ? <span className="min-w-0 max-w-full break-words">{os}</span> : null}
    </span>
  )
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

/** A row's Last seen: the last report of a sensor, scan or agent. A hand-added device none has reported reads Never, with when a
 *  person added it (in the title of a dense row, `now` given; in the words on a phone row). */
function LastSeen({ d, now }: { d: DeviceRow; now?: number }) {
  const { t, i18n } = useTranslation('inventory')
  if (neverSeen(d)) {
    return now === undefined
      ? <span>{t('col.neverSeenAdded', { when: fmtRelative(d.first_seen) })}</span>
      : <span className="whitespace-nowrap text-meta text-muted" title={t('col.neverSeenTitle', { when: fmtDateTime(d.first_seen) })}>{t('col.neverSeen')}</span>
  }
  return now === undefined
    ? <time dateTime={d.last_seen}>{fmtRelative(d.last_seen)}</time>
    : <time className="whitespace-nowrap text-meta text-muted" dateTime={d.last_seen} title={fmtDateTime(d.last_seen)}>{shortAgo(d.last_seen, now, i18n.language || 'en')}</time>
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
      {d.private_mac ? tip(<Chip tone="off">{t('chip.privateMac')}</Chip>, t('chip.privateMac'), d.quiet ? t('chip.quietHint') : t('chip.privateMacHint')) : null}
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
/** What Body puts in the toolbar of both lists: the count line and the page's buttons. */
type Bar = { all: number; pending: number; actions: React.ReactNode }

function DeviceSearch({ rows, top, now, query, same, bar, shown }: { rows: DeviceRow[]; top: SoftwareName[]; now: number; query: Query; same: SameIds; bar: Bar; shown: number }) {
  const { t } = useTranslation('inventory')
  const keys = useMemo(() => deviceKeys(rows, now, same, top), [rows, now, same, top])
  const count = (key: string, value: string) => keys.find((x) => x.key === key)?.values?.find((v) => v.value === value)?.count
  const chips: TokenChip[] = [
    // The devices that carry risk first, as Defender's exposure filter does
    { token: 'risk:exploited', label: t('search.chip.exploited'), count: count('risk', 'exploited') },
    { token: 'risk:update_recommended', label: t('search.chip.update'), count: count('risk', 'update_recommended') },
    { token: 'fragile', label: t('search.chip.fragile'), count: rows.filter((d) => d.fragile).length },
    { token: 'source:snmp', label: t('search.chip.snmp'), count: count('source', 'snmp') },
    { token: 'source:osquery', label: t('search.chip.osquery'), count: count('source', 'osquery') },
    { token: 'source:manual', label: t('search.chip.manual'), count: count('source', 'manual') },
    { token: 'has:findings', label: t('search.chip.findings'), count: count('has', 'findings') },
    { token: 'possible:same', label: t('search.chip.same'), count: count('possible', 'same') }, // rows to merge or keep separate
  ]
  // A chip that would show 0 is left out (To review would read "SNMP 0, osquery 0, Manual 0"), unless it is on (#849 review L11).
  const shownChips = chips.filter((c) => c.count !== 0 || hasToken(query.q, c.token))
  return <TokenSearch value={query.q} onChange={query.setQ} keys={keys} chips={shownChips} label={t('search.label')} placeholder={t('search.placeholder')} chipsLabel={t('search.chipsLabel')} summary={<CountLine q={query.q} shown={shown} total={rows.length} bar={bar} />} actions={bar.actions} />
}

/** The toolbar's one count line, read out as the list changes (WCAG 4.1.3; the live region is always there so the first change and
 *  "0 of 32" are announced). Without a search: "34 devices, 2 not yet approved" (every device, both lists). With one: "1 of 32 devices
 *  shown" (this list; the other list's devices are not in it) and the not-yet-approved count. */
function CountLine({ q, shown, total, bar }: { q: string; shown: number; total: number; bar: Bar }) {
  const { t } = useTranslation('inventory')
  const text = q.trim()
    ? [t('search.shownOf', { shown, count: total }), bar.pending > 0 ? t('search.pending', { count: bar.pending }) : ''].filter(Boolean).join(' · ')
    : bar.pending > 0 ? t('list.title', { count: bar.all, pending: bar.pending }) : t('list.titleAllApproved', { count: bar.all })
  return <span role="status" aria-live="polite" className="text-meta text-muted tabular-nums">{text}</span>
}

/** How long the search's `software:` words must stay the same before the server is asked: each answer reads every device's lines. */
const SOFTWARE_SETTLE_MS = 300

/** `v` once it has stayed the same for `ms` (the first value at once, so a link with software: in it asks at once). */
function useSettled(v: string, ms: number): string {
  const [settled, setSettled] = useState(v)
  useEffect(() => {
    const id = setTimeout(() => setSettled(v), ms)
    return () => clearTimeout(id)
  }, [v, ms])
  return settled
}

/** The server's answer for the search's `software:` words (the list carries no software lines): `matches` is undefined while there
 *  are none or before the first answer; `waiting` while the answer for the words typed now is not in yet (an empty list then means
 *  "not known yet", not "no device runs it"); `error` when that answer failed. */
function useMatches(swWanted: string[]): { matches: SoftwareMatches | undefined; waiting: boolean; error: unknown } {
  const key = swWanted.join(',')
  const settled = useSettled(key, SOFTWARE_SETTLE_MS)
  const r = useSoftwareMatches(useMemo(() => (settled ? settled.split(',') : []), [settled]))
  const on = swWanted.length > 0
  const matches = useMemo(() => (on && r.data ? softwareMatches(r.data.items) : undefined), [on, r.data])
  const error = on && settled === key && r.isError ? r.error : null
  return { matches, waiting: on && !error && (settled !== key || r.isPlaceholderData || !r.data), error }
}

/** What an empty list says while the `software:` answer is not in, or when it failed; undefined: the usual "no match". */
function SoftwareNote({ waiting, error }: { waiting: boolean; error: unknown }) {
  const { t } = useTranslation('inventory')
  if (error) return <span role="alert">{errMsg(error)}</span>
  return waiting ? <span>{t('search.softwareWaiting')}</span> : null
}

/** Devices: the approved list (#849). */
function DevicesList({ rows, top, now, query, same, bar }: { rows: DeviceRow[]; top: SoftwareName[]; now: number; query: Query; same: SamePairsBy; bar: Bar }) {
  const { t } = useTranslation('inventory')
  const navigate = useNavigate()
  const { q, clear } = query
  const deferred = useDeferredValue(q)
  const swWanted = useMemo(() => softwareValues(deferred), [deferred])
  const sw = useMatches(swWanted)
  const { matches } = sw
  const shown = useMemo(() => filterDevices(rows, deferred, now, same.ids, matches), [rows, deferred, now, same.ids, matches])
  const admin = useCan('admin')
  // the selection serves the scan buttons (slot) and, for an admin, Merge
  const selecting = slotComponents(DEVICES_ACTIONS_SLOT).length > 0 || admin
  const [sel, ops] = useRowSelection()
  const [merging, setMerging] = useState<MergeStart | null>(null)
  const shownIds = shown.map((d) => d.id)
  const rowMenu = (d: DeviceRow) => (admin && !d.is_box ? <RowMenu d={d} suggested={same.suggested.get(d.id) ?? []} onMerge={setMerging} /> : null)
  const dash = <span className="text-muted">–</span>
  const nameLink = (d: DeviceRow, cls = '') => <Link to={`/devices/${d.id}`} onClick={(e) => e.stopPropagation()} className={cn('font-medium text-accent underline-offset-4 hover:underline', cls)}>{nameOf(d, kindLabel(d.kind))}</Link>
  const columns: ColumnDef<DeviceRow>[] = [
    ...(selecting ? [{
      id: 'select', enableSorting: false,
      header: () => <Checkbox aria-label={t('select.all')} checked={groupState(shownIds, sel)} onCheckedChange={(v) => (v === true ? ops.add(shownIds) : ops.remove(shownIds))} />,
      cell: ({ row }) => <span onClick={(e) => e.stopPropagation()}><Checkbox aria-label={t('select.one', { name: nameOf(row.original, kindLabel(row.original.kind)) })} checked={sel.has(row.original.id)} onCheckedChange={(v) => ops.toggle(row.original.id, v === true)} /></span>,
    } satisfies ColumnDef<DeviceRow>] : []),
    // One cell for the name and what the device is: the name (cut with an ellipsis, in full on hover), and under it maker, model and OS.
    // The cell takes the width the other columns leave (min-w-0: its text never widens the table), so the list fits a laptop window.
    { id: 'name', header: t('col.name'), accessorFn: (d) => nameOf(d, kindLabel(d.kind)), cell: ({ row }) => {
      const d = row.original
      const name = nameOf(d, kindLabel(d.kind))
      return (
        <div className="min-w-0">
          <div className="flex items-center gap-x-2">
            <Link to={`/devices/${d.id}`} onClick={(e) => e.stopPropagation()} title={name} className="min-w-0 truncate font-medium text-accent underline-offset-4 hover:underline">{name}</Link>
            <NameChips d={d} dense /><SameChip id={d.id} others={same.others.get(d.id) ?? []} />
          </div>
          <HardwareLine d={d} />
        </div>
      )
    } },
    // The risk marker, sortable (worst first on the first click); empty for a clean device
    { id: 'risk', header: t('risk.column'), sortDescFirst: true, accessorFn: (d) => riskRank(d.risk), cell: ({ row }) => <RiskMarker id={row.original.id} risk={row.original.risk} /> },
    { id: 'ip', header: t('col.ip'), accessorFn: (d) => d.ip, cell: ({ row }) => <span className="whitespace-nowrap tabular-nums">{row.original.ip}</span> },
    { id: 'kind', header: t('col.kind'), accessorFn: (d) => { const k = shownKind(d).kind; return `${kindLabel(k)} ${categoryLabel(categoryOf(k))}` }, cell: ({ row }) => <TypeCell d={row.original} dense /> },
    // M2: with software: in the search the list answers "which devices run it, at which version" (the old Software tab), as runZero does.
    ...(swWanted.length ? [{
      id: 'matched', header: t('col.matched'), accessorFn: (d: DeviceRow) => matchSoftware(d, swWanted, matches).map((x) => x.display).join(' '),
      cell: ({ row }: { row: { original: DeviceRow } }) => {
        const m = matchSoftware(row.original, swWanted, matches)
        if (!m.length) return dash
        const line = (x: ListSoftware) => `${x.display} ${x.version ?? t('software.noVersion')}`
        return (
          <span className="flex items-center gap-1.5 whitespace-nowrap" title={m.map((x) => `${line(x)} (${t(`common:source.${x.source}`, { defaultValue: x.source })})`).join('\n')}>
            <span className="font-medium">{m[0]!.display}</span><span className="tabular-nums">{m[0]!.version ?? <span className="text-muted">{t('software.noVersion')}</span>}</span>
            {m.length > 1 ? <span className="text-meta text-muted tabular-nums">{`+${m.length - 1}`}</span> : null}
          </span>
        )
      },
    } satisfies ColumnDef<DeviceRow>] : []),
    { id: 'source', header: t('col.sources'), accessorFn: (d) => FEED_ORDER.filter((f) => feedsOfRow(d).has(f)).join(' '), cell: ({ row }) => <SourcesCell d={row.original} compact /> },
    // a hand-added device no report has seen sorts as the oldest and reads Never, its added time in the tooltip
    { id: 'seen', header: t('col.lastSeen'), accessorFn: (d) => (neverSeen(d) ? 0 : new Date(d.last_seen).getTime()), cell: ({ row }) => <LastSeen d={row.original} now={now} /> },
    ...(admin ? [{ id: 'actions', enableSorting: false, header: () => <span className="sr-only">{t('software.actions')}</span>, cell: ({ row }: { row: { original: DeviceRow } }) => rowMenu(row.original) } satisfies ColumnDef<DeviceRow>] : []),
  ]
  return (
    <section aria-label={t('tabs.devices')} className="grid min-w-0 gap-3">
      <DeviceSearch rows={rows} top={top} now={now} query={query} same={same.ids} bar={bar} shown={shown.length} />
      {selecting ? (
        <div className="flex flex-wrap items-start gap-2">
          {admin ? <MergeSelected rows={rows} sel={sel} onMerge={setMerging} /> : null}
          <Slot name={DEVICES_ACTIONS_SLOT} props={{ selectedIds: [...sel], selected: rows.filter((d) => sel.has(d.id)), clearSelection: ops.clear }} />
        </div>
      ) : null}
      <DataTable caption={t('table.caption')} data={shown} columns={columns} initialSort={[{ id: 'seen', desc: true }]} fillColumn="name"
        search={false} urlKey="devices" resetPageOn={deferred}
        onRowClick={(d) => void navigate(`/devices/${d.id}`)}
        empty={t('table.emptyApproved')} filtered={!!q} onClearFilters={clear}
        emptyFiltered={sw.waiting || sw.error ? <SoftwareNote {...sw} /> : undefined}
        mobileRow={(d) => {
          const hw = [d.vendor?.value, d.model?.value].filter(Boolean).join(' ')
          return (
            <div className="grid gap-1.5">
              <div className="flex flex-wrap items-center gap-x-2 gap-y-1">
                {selecting ? <Checkbox aria-label={t('select.one', { name: nameOf(d, kindLabel(d.kind)) })} checked={sel.has(d.id)} onCheckedChange={(v) => ops.toggle(d.id, v === true)} /> : null}
                {nameLink(d, 'min-w-0 [overflow-wrap:anywhere]')}
                <RiskMarker id={d.id} risk={d.risk} />
                <NameChips d={d} />
                <span className="ml-auto">{rowMenu(d)}</span>
              </div>
              <div className="flex flex-wrap items-center gap-x-3 gap-y-1 text-meta text-muted">
                <TypeCell d={d} />
                {d.ip && d.ip !== '—' ? <span className="tabular-nums">{d.ip}</span> : null}
                {hw ? <span className="min-w-0 [overflow-wrap:anywhere]">{hw}</span> : null}
              </div>
              {swWanted.length ? (() => {
                // the phone's Matched software line (#849): what software: found on this device, with its version
                const m = matchSoftware(d, swWanted, matches)
                return m.length ? <p className="text-meta">{m.map((x) => `${x.display} ${x.version ?? t('software.noVersion')}`).join(', ')}</p> : null
              })() : null}
              <div className="flex flex-wrap items-center gap-x-3 gap-y-1 text-caption text-muted">
                <SourcesCell d={d} />
                <LastSeen d={d} />
              </div>
            </div>
          )
        }} />
      {/* the list keeps its page, search and sort underneath; the devices that went leave the selection */}
      {merging ? <MergeFlow start={merging} onClose={() => setMerging(null)} onMerged={(kept, gone) => ops.remove([kept, ...gone])} /> : null}
    </section>
  )
}

/** "Merge (n)" over the selection (admin): the box is left out (it is always its own device); one device alone, or more than one merge
 *  takes, keeps the button there but off, with the reason next to it. */
function MergeSelected({ rows, sel, onMerge }: { rows: DeviceRow[]; sel: ReadonlySet<string>; onMerge: (s: MergeStart) => void }) {
  const { t } = useTranslation('inventory')
  const picked = rows.filter((d) => sel.has(d.id))
  const ids = picked.filter((d) => !d.is_box).map((d) => d.id)
  const box = picked.some((d) => d.is_box)
  if (!ids.length) return box && sel.size > 1 ? <p className="text-meta text-muted" role="status">{t('merge.bulkBoxLeftOut')}</p> : null
  const tooMany = ids.length > MERGE_MAX_FROM + 1
  const one = ids.length < 2
  return (
    <div className="grid gap-1">
      <Button size="sm" variant="primary" disabled={tooMany || one} aria-label={t('merge.bulkLabel', { count: ids.length })} aria-describedby={one ? 'merge-bulk-one' : undefined} onClick={() => onMerge({ ids })}><GitMerge />{t('merge.bulk', { count: ids.length })}</Button>
      {one ? <p id="merge-bulk-one" className="text-meta text-muted" role="status">{t('merge.bulkOne')}</p> : null}
      {tooMany ? <p className="text-meta text-muted" role="status">{t('merge.bulkTooMany', { max: MERGE_MAX_FROM + 1, from: MERGE_MAX_FROM })}</p> : null}
      {box ? <p className="text-meta text-muted" role="status">{t('merge.bulkBoxLeftOut')}</p> : null}
    </div>
  )
}

/** A row's menu (admin): "Merge with…" (pick the twins), and "Merge with X" for each device the box suggests as the same one. */
function RowMenu({ d, suggested, onMerge }: { d: DeviceRow; suggested: (Suggestion & { name: string })[]; onMerge: (s: MergeStart) => void }) {
  const { t } = useTranslation('inventory')
  const name = nameOf(d, kindLabel(d.kind))
  return (
    <span onClick={(e) => e.stopPropagation()} className="inline-flex">
      <DropdownMenu>
        <DropdownMenuTrigger asChild>
          <Button size="icon" variant="ghost" aria-label={t('merge.rowMenu', { name })} title={t('merge.rowMenu', { name })}><MoreHorizontal /></Button>
        </DropdownMenuTrigger>
        <DropdownMenuContent align="end">
          {suggested.map((s) => (
            <DropdownMenuItem key={s.id} onSelect={() => onMerge({ ids: [d.id, s.id] })}><GitMerge />{t('merge.withSuggested', { name: s.name })}</DropdownMenuItem>
          ))}
          <DropdownMenuItem onSelect={() => onMerge({ pickFor: { id: d.id, label: name, name: d.name, hostname: d.hostname, vendor: d.vendor, model: d.model, macs: d.mac ? [d.mac] : [] }, suggested })}>
            <GitMerge />{t('merge.withMenu')}
          </DropdownMenuItem>
        </DropdownMenuContent>
      </DropdownMenu>
    </span>
  )
}

/** To review: found by a scan or by listening, not approved yet (S-INV-3). Same search box. */
function ReviewList({ rows, top, now, notifyNew, notifyAvailable, query, same, bar }: { rows: DeviceRow[]; top: SoftwareName[]; now: number; notifyNew: boolean; notifyAvailable: boolean; query: Query; same: SamePairsBy; bar: Bar }) {
  const { q, clear } = query
  const deferred = useDeferredValue(q)
  const swWanted = useMemo(() => softwareValues(deferred), [deferred])
  const sw = useMatches(swWanted)
  const { matches } = sw
  const shown = useMemo(() => filterDevices(rows, deferred, now, same.ids, matches), [rows, deferred, now, same.ids, matches])
  return (
    <section className="grid min-w-0 gap-3">
      <PendingPanel items={shown} total={rows.length} notifyNew={notifyNew} notifyAvailable={notifyAvailable} sameAs={same.others}
        search={<><DeviceSearch rows={rows} top={top} now={now} query={query} same={same.ids} bar={bar} shown={shown.length} /></>} filtered={!!q} onClear={clear}
        none={sw.waiting || sw.error ? <SoftwareNote {...sw} /> : undefined} />
    </section>
  )
}

/** #829: the pairs of GET /inventory/possible-same by device: the names of the others, and every id in a pair. One cached read. */
type SamePairsBy = { ids: SameIds; others: ReadonlyMap<string, string[]>; suggested: ReadonlyMap<string, (Suggestion & { name: string })[]> }
function usePairsByDevice(): SamePairsBy {
  const q = usePossibleSame()
  return useMemo(() => {
    const others = new Map<string, string[]>()
    const suggested = new Map<string, (Suggestion & { name: string })[]>()
    for (const p of q.data?.items ?? []) {
      others.set(p.a.id, [...(others.get(p.a.id) ?? []), p.b.name])
      others.set(p.b.id, [...(others.get(p.b.id) ?? []), p.a.name])
      suggested.set(p.a.id, [...(suggested.get(p.a.id) ?? []), { id: p.b.id, name: p.b.name, reason: p.reason, why: p.why }])
      suggested.set(p.b.id, [...(suggested.get(p.b.id) ?? []), { id: p.a.id, name: p.a.name, reason: p.reason, why: p.why }])
    }
    return { ids: new Set(others.keys()), others, suggested }
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
    <EmptyState art={boxOnly ? undefined : 'no-devices'} title={boxOnly ? t('empty.titleBoxOnly') : t('empty.title')} info={t('empty.info')} action={<div className="flex flex-wrap gap-2"><Button variant="primary" disabled={!canOp} title={needRole} onClick={() => onAdd('manual')}>{t('add.open')}</Button><Button disabled={!canOp} title={needRole} onClick={() => onAdd('csv')}>{t('import.open')}</Button>{ranges === 'none' ? <Link to="/settings/scanning?tab=safety#range-input" className={cn(buttonVariants({ variant: 'secondary' }))}>{t('empty.range')}</Link> : null}</div>}>{t(body)}</EmptyState>
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
    // A quiet private-address device is listed with the devices and counts as To review only once it earns a look (the server decides: `quiet`)
    return { approved: real.filter((d) => d.approved || d.quiet), pending: real.filter((d) => !d.approved && !d.quiet), declared: items.length - real.length }
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
  // The title names the page; "12 devices, 2 not yet approved" is the small line of the toolbar over the list
  const title = !q.data ? t('list.titleLoading') : all === 0 ? t('list.titleEmpty') : all === 1 && lists.approved[0]?.is_box ? t('list.titleBoxOnly') : t('list.titleLoading')
  // Export, Settings and Add live in the list's toolbar; with no list yet (loading, no devices) the header keeps Settings and Add.
  const buttons = (withExport: boolean) => (
    <>
      {/* Nothing to export before the first device */}
      {withExport && all > 0 ? <DownloadButton variant="ghost" path="/inventory/export.csv" filename="vedette-devices.csv" onError={(e) => toast.error(errMsg(e))}><Download />{t('export')}</DownloadButton> : null}
      {canAdmin ? <Link to="/devices/setup" aria-label={t('setup.linkLabel')} title={t('setup.linkLabel')} className={cn(buttonVariants({ variant: 'ghost' }))}><Settings2 />{t('setup.link')}</Link> : null}
      <Button variant="primary" disabled={!canOp} title={needRole} onClick={() => setAdd('manual')}><Plus />{t('add.open')}</Button>
    </>
  )
  const bar: Bar = { all, pending, actions: buttons(true) }

  return (
    <>
      <PageHeader title={title} stories={['S-INV-1', 'S-INV-2', 'S-INV-3', 'S-INV-4']}
        meta={<SampleDataNote />} info={<><p>{t('list.meta')}</p><p>{t('list.metaInfo')}</p></>}
        actions={all === 0 ? buttons(false) : undefined} />
      {/* what the box changed by itself in SNMP settings, for an admin, until dismissed */}
      <SnmpNotices />
      <QueryState query={q}>
        {(d) => {
          if (all === 0) return <><NoDevices boxOnly={false} canOp={canOp} canAdmin={canAdmin} needRole={needRole} onAdd={setAdd} />{declaredLine}</>
          const now = q.dataUpdatedAt
          return (
            <>
              {all === 1 && lists.approved[0]?.is_box ? (
                <div className="mb-6"><NoDevices boxOnly canOp={canOp} canAdmin={canAdmin} needRole={needRole} onAdd={setAdd} /></div>
              ) : null}
              {/* #949: findings could not answer; the list still shows, quietly without risk marks */}
              {d.risk_unavailable ? <p role="status" className="mb-3 text-meta text-muted">{t('risk.unavailable')}</p> : null}
              <PageTabs label={t('tabs.label')} tabs={[
                { id: 'devices', label: t('tabs.devices'), panel: <DevicesList rows={lists.approved} top={d.top_software.devices} now={now} query={query} same={same} bar={bar} /> },
                { id: 'review', label: t('tabs.review'), panel: <ReviewList rows={lists.pending} top={d.top_software.review} now={now} notifyNew={d.notify_new} notifyAvailable={d.notify_available} query={query} same={same} bar={bar} />, badge: { count: pending, label: t('tabs.reviewBadge'), tone: 'off' } },
                // The devices a person ignored, only while there are any (an old ?tab=ignored link lands on Devices then)
                ...(d.counts.ignored > 0 ? [{ id: 'ignored', label: t('tabs.ignoredCount', { count: d.counts.ignored }), panel: <IgnoredPanel /> }] : []),
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
