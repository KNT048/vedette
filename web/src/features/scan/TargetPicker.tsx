// The target picker of Scan now (S-SCAN-1, S-SCAN-4 D-472): search, filters, subnet groups and pages over every device,
// with the selection kept outside the list. Bulk actions tick only devices that need no hand pick (D-126 (2)) and say
// what they left for the person's own tick.
import { useMemo, useState } from 'react'
import { Link } from 'react-router'
import { useTranslation } from 'react-i18next'
import { ChevronDown, ChevronRight } from 'lucide-react'
import { Pager, groupState, pageOf } from '@/components/common/Selection'
import { Chip } from '@/components/common/StatusChip'
import { Button } from '@/components/ui/button'
import { Checkbox } from '@/components/ui/checkbox'
import { Input, Select } from '@/components/ui/input'
import type { ScanTarget } from './types'

const PAGE_SIZE = 50
const NO_IP = 'none'

type Show = 'all' | 'selected' | 'pick' | 'findings'
type Seen = 'any' | '1' | '7' | '30' | 'older'
interface Filters { q: string; kind: string; subnet: string; approved: 'all' | 'yes' | 'no'; seen: Seen; show: Show }
const NONE: Filters = { q: '', kind: '', subnet: '', approved: 'all', seen: 'any', show: 'all' }

const V4 = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/

/** The group of an address: its IPv4 /24 or IPv6 /64; NO_IP when the device has none. */
function subnetOf(ip: string): string {
  const m = V4.exec(ip)
  if (m) return `${m[1]}.${m[2]}.${m[3]}.0/24`
  if (!ip.includes(':')) return NO_IP
  const [head = '', tail = ''] = ip.split('::')
  const h = head ? head.split(':') : []
  const tl = tail ? tail.split(':') : []
  const parts = ip.includes('::') ? [...h, ...Array<string>(Math.max(0, 8 - h.length - tl.length)).fill('0'), ...tl] : h
  return `${parts.slice(0, 4).map((p) => p.toLowerCase().replace(/^0+(?=.)/, '')).join(':')}::/64`
}

/** Sort key: IPv4 by number, then IPv6, then no address. */
const order = (ip: string): [number, number, string] => {
  const m = V4.exec(ip)
  if (m) return [0, ((+m[1]! * 256 + +m[2]!) * 256 + +m[3]!) * 256 + +m[4]!, '']
  return ip.includes(':') ? [1, 0, ip] : [2, 0, ip]
}
const cmp = (a: string, b: string) => {
  const [x, y] = [order(a), order(b)]
  return x[0] - y[0] || x[1] - y[1] || x[2].localeCompare(y[2])
}

const bulkOf = (list: ScanTarget[]) => list.filter((x) => x.selectable && !x.pick_only)
const deviceFilters = (f: Filters) => !!(f.kind || f.subnet || f.approved !== 'all' || f.seen !== 'any')
const DAY = 864e5

function matches(x: ScanTarget, f: Filters, sel: ReadonlySet<string>, now: number): boolean {
  const q = f.q.trim().toLowerCase()
  if (q) {
    const hay = [x.label, x.ip, x.mac ?? '', x.vendor ?? ''].join('\n').toLowerCase()
    const mac = (x.mac ?? '').replace(/[:.-]/g, '').toLowerCase()
    const qmac = q.replace(/[:.-]/g, '')
    if (!hay.includes(q) && !(qmac.length >= 4 && mac.includes(qmac))) return false
  }
  if (x.kind === 'external' && deviceFilters(f)) return false
  if (f.kind && x.device_kind !== f.kind) return false
  if (f.subnet && subnetOf(x.ip) !== f.subnet) return false
  if (f.approved !== 'all' && x.approved !== (f.approved === 'yes')) return false
  if (f.seen !== 'any') {
    const age = x.last_seen ? now - Date.parse(x.last_seen) : Infinity
    if (f.seen === 'older' ? age <= 30 * DAY : age > +f.seen * DAY) return false
  }
  switch (f.show) {
    case 'selected': return sel.has(x.id)
    case 'pick': return x.selectable && x.pick_only
    case 'findings': return x.findings > 0
  }
  return true
}

/** What a bulk action did: shown until the next action or filter change (D-472). */
interface Report { selected: number; needTick: number; blocked: number; tickWhy: [string, number][]; blockedWhy: [string, number][]; unapproved: boolean; subnet?: string }

/** Counts by cause, most first (W2-5: a fresh box's "Select all" ticks 0, and the page says why). */
const tally = (list: ScanTarget[], key: (x: ScanTarget) => string): [string, number][] => {
  const m = new Map<string, number>()
  for (const x of list) m.set(key(x), (m.get(key(x)) ?? 0) + 1)
  return [...m].sort((a, b) => b[1] - a[1])
}
const tickCause = (x: ScanTarget) => (x.box ? 'box' : x.device_kind === 'unknown' ? 'unknown' : x.fragile ? 'fragile' : 'manual')

function reportOf(scope: ScanTarget[], selected: number, sel: ReadonlySet<string>, subnet?: string): Report {
  const tick = scope.filter((x) => x.selectable && x.pick_only && !sel.has(x.id))
  const blocked = scope.filter((x) => !x.selectable)
  return { selected, needTick: tick.length, blocked: blocked.length, tickWhy: tally(tick, tickCause), blockedWhy: tally(blocked, (x) => x.reason ?? 'out_of_scope'),
    unapproved: blocked.some((x) => x.reason === 'unapproved'), subnet }
}

function TargetRow({ t: target, checked, onChange }: { t: ScanTarget; checked: boolean; onChange: (v: boolean) => void }) {
  const { t } = useTranslation('scan')
  const id = `tg-${target.id}`
  const extra = [target.vendor, target.mac].filter(Boolean).join(', ')
  return (
    <li className={`flex flex-wrap items-center gap-x-3 gap-y-1 py-2 pr-3 ${target.kind === 'internal' ? 'pl-9' : 'pl-3'}`}>
      <Checkbox id={id} checked={checked} disabled={!target.selectable} onCheckedChange={(v) => onChange(v === true)} />
      <label htmlFor={id} className={target.selectable ? 'text-sm' : 'text-sm text-muted'}>
        <span className="font-medium">{target.label}</span>{target.ip && target.ip !== '—' ? <> <span className="text-muted">{target.ip}</span></> : null}
      </label>
      {extra ? <span className="text-[12px] text-muted">{extra}</span> : null}
      {target.findings > 0 ? <Chip tone="warn">{t('start.findings', { count: target.findings })}</Chip> : null}
      {target.fragile && target.selectable ? <Chip tone="off" title={t('start.fragileHint')}>{t('start.fragile')}</Chip> : null}
      {target.pick_only ? <span className="text-[13px] text-muted">{t(target.box ? 'start.pickBox' : target.device_kind === 'unknown' ? 'start.pickUnknown' : target.fragile ? 'start.pickFragile' : 'start.pickManual')}</span> : null}
      {target.reason ? <span className="text-[13px] text-muted">{t(`reason.${target.reason}`)}</span> : null}
      {target.reason && target.kind === 'internal' ? (
        <Link to={`/devices/${encodeURIComponent(target.id)}`} aria-label={t('start.openDeviceAria', { label: target.label })} className="text-[13px] text-accent underline underline-offset-4">{t('start.openDevice')}</Link>
      ) : null}
    </li>
  )
}

type Entry = { type: 'group'; key: string; cont: boolean } | { type: 'row'; x: ScanTarget }

export function TargetPicker({ targets, sel, onToggle, onAdd, onRemove, onReplace, onClear }: {
  targets: ScanTarget[]
  /** The effective selection (pick-only devices only with a hand tick). */
  sel: ReadonlySet<string>
  onToggle: (id: string, v: boolean) => void
  onAdd: (ids: string[]) => void
  onRemove: (ids: string[]) => void
  onReplace: (ids: string[]) => void
  onClear: () => void
}) {
  const { t } = useTranslation('scan')
  const [f, setF] = useState<Filters>(NONE)
  const [page, setPage] = useState(0)
  const [closed, setClosed] = useState<ReadonlySet<string>>(() => new Set())
  const [report, setReport] = useState<Report | null>(null)
  const [now] = useState(() => Date.now()) // "last seen" filters count from when the picker opened
  const filter = (next: Filters) => { setF(next); setPage(0); setReport(null) }
  const patch = (p: Partial<Filters>) => filter({ ...f, ...p })

  const internal = useMemo(() => targets.filter((x) => x.kind === 'internal').sort((a, b) => cmp(a.ip, b.ip)), [targets])
  const external = targets.filter((x) => x.kind === 'external')
  const shown = internal.filter((x) => matches(x, f, sel, now))
  const shownExt = external.filter((x) => matches(x, f, sel, now))
  const filtered = f.q.trim() !== '' || deviceFilters(f) || f.show !== 'all'

  const groups = new Map<string, ScanTarget[]>()
  for (const x of shown) { const k = subnetOf(x.ip); const g = groups.get(k); if (g) g.push(x); else groups.set(k, [x]) }
  const allSubnets = useMemo(() => [...new Set(internal.map((x) => subnetOf(x.ip)))], [internal])
  const kinds = useMemo(() => [...new Set(internal.map((x) => x.device_kind).filter((k): k is NonNullable<typeof k> => !!k))]
    .sort((a, b) => t(`inventory:kind.${a}`).localeCompare(t(`inventory:kind.${b}`))), [internal, t])
  const groupLabel = (k: string) => (k === NO_IP ? t('start.noIpGroup') : k)

  const entries: Entry[] = []
  for (const [key, list] of groups) {
    entries.push({ type: 'group', key, cont: false })
    if (!closed.has(key)) for (const x of list) entries.push({ type: 'row', x })
  }
  const pg = pageOf(entries, page, PAGE_SIZE)
  const first = pg.rows[0]
  const rows: Entry[] = first?.type === 'row' ? [{ type: 'group', key: subnetOf(first.x.ip), cont: true }, ...pg.rows] : pg.rows

  const bulk = (scope: ScanTarget[], subnet?: string) => {
    const ids = bulkOf(scope).map((x) => x.id)
    onAdd(ids)
    setReport(reportOf(scope, ids.length, sel, subnet))
  }
  const withFindings = () => {
    const scope = targets.filter((x) => x.findings > 0)
    const ids = bulkOf(scope).map((x) => x.id)
    onReplace(ids)
    setF({ ...NONE, show: 'findings' })
    setPage(0)
    setReport(reportOf(scope, ids.length, new Set()))
  }

  return (
    <div className="grid gap-3">
      <div className="flex flex-wrap items-center gap-2" role="search" aria-label={t('start.filtersLabel')}>
        <Input type="search" className="sm:w-64" value={f.q} onChange={(e) => patch({ q: e.target.value })} placeholder={t('start.searchPlaceholder')} aria-label={t('start.search')} />
        <Select className="sm:w-auto" aria-label={t('start.fKind')} value={f.kind} onChange={(e) => patch({ kind: e.target.value })}>
          <option value="">{t('start.fKindAll')}</option>
          {kinds.map((k) => <option key={k} value={k}>{t(`inventory:kind.${k}`)}</option>)}
        </Select>
        <Select className="sm:w-auto" aria-label={t('start.fSubnet')} value={f.subnet} onChange={(e) => patch({ subnet: e.target.value })}>
          <option value="">{t('start.fSubnetAll')}</option>
          {allSubnets.map((k) => <option key={k} value={k}>{groupLabel(k)}</option>)}
        </Select>
        <Select className="sm:w-auto" aria-label={t('start.fApproved')} value={f.approved} onChange={(e) => patch({ approved: e.target.value as Filters['approved'] })}>
          <option value="all">{t('start.fApprovedAll')}</option>
          <option value="yes">{t('start.fApprovedYes')}</option>
          <option value="no">{t('start.fApprovedNo')}</option>
        </Select>
        <Select className="sm:w-auto" aria-label={t('start.fSeen')} value={f.seen} onChange={(e) => patch({ seen: e.target.value as Seen })}>
          {(['any', '1', '7', '30', 'older'] as const).map((v) => <option key={v} value={v}>{t(`start.fSeen_${v}`)}</option>)}
        </Select>
        <Select className="sm:w-auto" aria-label={t('start.fShow')} value={f.show} onChange={(e) => patch({ show: e.target.value as Show })}>
          {(['all', 'selected', 'pick', 'findings'] as const).map((v) => <option key={v} value={v}>{t(`start.fShow_${v}`)}</option>)}
        </Select>
        {filtered ? <Button size="sm" onClick={() => filter(NONE)}>{t('start.clearFilters')}</Button> : null}
      </div>

      <div className="flex flex-wrap items-center gap-2">
        <Button size="sm" onClick={() => bulk(shown)}>{t('start.selectAll')}</Button>
        <Button size="sm" onClick={withFindings}>{t('start.selectFindings')}</Button>
        <Button size="sm" onClick={() => { onClear(); setReport(null) }}>{t('start.selectNone')}</Button>
        <span className="text-[13px] font-medium" aria-live="polite">{t('start.selected', { count: sel.size })}</span>
        {f.show === 'selected'
          ? <Button size="sm" variant="link" onClick={() => patch({ show: 'all' })}>{t('start.showAll')}</Button>
          : <Button size="sm" variant="link" disabled={sel.size === 0} onClick={() => patch({ show: 'selected' })}>{t('start.showSelected')}</Button>}
      </div>
      {report ? (
        <p role="status" className="rounded-md border border-rule bg-sunken px-3 py-2 text-[13px]">
          {t('start.report', { count: report.selected })}
          {report.needTick ? <>{' '}{t('start.reportTick', { count: report.needTick, why: report.tickWhy.map(([k, n]) => t(`start.tickWhy_${k}`, { count: n })).join(', ') })}{' '}
            <button type="button" className="text-accent underline underline-offset-4" onClick={() => { setF({ ...f, show: 'pick', subnet: report.subnet ?? f.subnet }); setPage(0) }}>{t('start.showThem')}</button></> : null}
          {report.blocked ? <>{' '}{t('start.reportBlocked', { count: report.blocked, why: report.blockedWhy.map(([k, n]) => t(`start.blockedWhy_${k}`, { count: n })).join(', ') })}</> : null}
          {report.unapproved ? <>{' '}<Link to="/devices" className="text-accent underline underline-offset-4">{t('start.reviewDevices')}</Link></> : null}
        </p>
      ) : null}

      <div className="rounded-md border border-rule bg-surface">
        <p className="border-b border-rule bg-sunken px-3 py-1.5 text-[12px] font-medium text-muted">
          {filtered ? t('start.internalCount', { count: shown.length, total: internal.length }) : t('start.internalAll', { count: internal.length })}
        </p>
        {internal.length === 0 ? <p className="px-3 py-3 text-sm text-muted">{t('start.noInternal')}</p>
          : shown.length === 0 ? (
            <div className="flex flex-wrap items-center gap-3 px-3 py-3 text-sm text-muted">
              <span>{t('start.noMatch')}</span>
              <Button size="sm" onClick={() => filter(NONE)}>{t('start.clearFilters')}</Button>
            </div>
          ) : (
            <ul className="divide-y divide-rule" aria-label={t('start.internal')}>
              {rows.map((e) => {
                if (e.type === 'row') return <TargetRow key={e.x.id} t={e.x} checked={sel.has(e.x.id)} onChange={(v) => onToggle(e.x.id, v)} />
                const list = groups.get(e.key) ?? []
                const ids = bulkOf(list).map((x) => x.id)
                // Shown: ticked only when every row that can be scanned is (pick-only rows count, so a bulk tick reads as
                // partial); clicked: ticks the rows that need no own tick, or clears the group once they all are.
                const state = groupState(list.filter((x) => x.selectable).map((x) => x.id), sel)
                const full = groupState(ids, sel) === true
                const open = !closed.has(e.key)
                const label = groupLabel(e.key)
                const selected = list.filter((x) => sel.has(x.id)).length
                return (
                  <li key={`g-${e.key}-${e.cont}`} className="flex flex-wrap items-center gap-x-3 gap-y-1 bg-sunken/60 px-3 py-1.5">
                    <Checkbox checked={ids.length ? state : false} disabled={!ids.length} aria-label={t('start.groupSelect', { subnet: label })}
                      title={ids.length ? undefined : t('start.groupNone')}
                      onCheckedChange={() => (full ? onRemove(list.map((x) => x.id)) : bulk(list, e.key))} />
                    <button type="button" aria-expanded={open} className="inline-flex items-center gap-1 text-sm font-medium"
                      onClick={() => setClosed((s) => { const n = new Set(s); if (open) n.add(e.key); else n.delete(e.key); return n })}>
                      {open ? <ChevronDown className="size-4" aria-hidden /> : <ChevronRight className="size-4" aria-hidden />}
                      {label}{e.cont ? <span className="font-normal text-muted"> {t('start.continued')}</span> : null}
                    </button>
                    <span className="text-[12px] text-muted">{t('start.groupCount', { count: list.length, selected })}</span>
                  </li>
                )
              })}
            </ul>
          )}
        <div className="border-t border-rule px-3 py-2 empty:hidden"><Pager page={pg.page} pages={pg.pages} onPage={setPage} label={t('start.pages')} /></div>
      </div>

      <fieldset className="rounded-md border border-rule bg-surface">
        <legend className="sr-only">{t('start.external')}</legend>
        <p aria-hidden className="border-b border-rule bg-sunken px-3 py-1.5 text-[12px] font-medium text-muted">{t('start.external')}</p>
        {external.length === 0 ? <p className="px-3 py-3 text-sm text-muted">{t('start.noExternal')}</p>
          : shownExt.length === 0 ? <p className="px-3 py-3 text-sm text-muted">{t('start.noExternalMatch')}</p>
            : <ul className="divide-y divide-rule">{shownExt.map((x) => <TargetRow key={x.id} t={x} checked={sel.has(x.id)} onChange={(v) => onToggle(x.id, v)} />)}</ul>}
        <p className="border-t border-rule px-3 py-2 text-[13px] text-muted">{t('start.externalHint')} <Link to="/exposure" className="text-accent underline underline-offset-4">{t('start.openExposure')}</Link></p>
      </fieldset>
    </div>
  )
}
