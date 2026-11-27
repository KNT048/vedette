import { useEffect, useState } from 'react'
import { useQueryClient } from '@tanstack/react-query'
import { Link, Navigate, useLocation, useSearchParams } from 'react-router'
import { useTranslation } from 'react-i18next'
import { toast } from 'sonner'
import { Plus, RefreshCw } from 'lucide-react'
import { Card } from '@/components/common/Card'
import { DependencyLink } from '@/components/common/DependencyLink'
import { InfoTip } from '@/components/common/InfoTip'
import { Notice, PageHeader, Section } from '@/components/common/PageHeader'
import { KpiStrip, PageTabs } from '@/components/common/PageFrame'
import { DataTable, type ColumnDef } from '@/components/common/DataTable'
import { useListParams } from '@/components/common/listParams'
import { EmptyState, QueryState, RequireModule, SampleDataNote } from '@/components/common/States'
import { Chip } from '@/components/common/StatusChip'
import { Slot } from '@/components/common/Slot'
import { Button } from '@/components/ui/button'
import { Dialog, DialogContent, DialogFooter } from '@/components/ui/dialog'
import { Field, Select } from '@/components/ui/input'
import { Segmented } from '@/components/ui/segmented'
import { ApiError } from '@/lib/api'
import { fmtDateTime, fmtNumber, fmtRelative } from '@/lib/format'
import { useModuleEnabled } from '@/lib/modules'
import { SPAN_IN_UI } from '@/lib/span'
import { useCan } from '@/lib/session'
import { fetchOlderEvents, useBadConnections, useDigest, useEvents, useSetRetention, useSources, useUnknownSenders } from './api'
import { CATALOG } from './catalog'
import { LAN_RANGE } from './places'
import { BoxCertificate, ConfigDialog, DeleteDialog, SourceFormDialog } from './SourceDialogs'
import type { IocPair, EventsResponse, EventWindow, LogEvent, LogSource, NewItem, Proto, SourcesResponse, SpikeItem } from './types'
import { ListToolbar } from '@/components/common/ListParts'

const STATE_TONE = { receiving: 'ok', silent: 'warn', never: 'off' } as const

// S-LOG-1: syslog the box dropped because its sender is not a source (or is one, declared with another protocol). Operators and admins see the
// addresses; a viewer does not get them from the API. The usual trap: on a container install, syslog from the machine that runs the
// containers arrives from the container network's gateway, not from the address the source was declared with.
// What the box keeps from a source (the form's hint): a UDP source's TCP lines too, a TCP or TLS source only its own (UDP is easy to forge).
const protoLabel = (s: { proto: Proto }) => (s.proto === 'udp' ? 'UDP and TCP' : s.proto.toUpperCase())
const PROTOS = new Intl.ListFormat('en', { type: 'conjunction' })

function UnknownSenders({ data, isAdmin, onAdd, onEdit }: { data: SourcesResponse; isAdmin: boolean; onAdd: (u: { ip: string; proto: Proto }) => void; onEdit: (s: LogSource) => void }) {
  const { t } = useTranslation('logs')
  const q = useUnknownSenders(useCan('operator'))
  // One item per address and protocol (the box keeps both when a sender uses two): one line per address, naming every protocol.
  const list: { ip: string; protos: Proto[]; count: number; last_seen: string }[] = []
  for (const u of q.data?.items ?? []) {
    const g = list.find((x) => x.ip === u.ip)
    if (!g) list.push({ ip: u.ip, protos: [u.proto], count: u.count, last_seen: u.last_seen })
    else { g.protos.push(u.proto); g.count += u.count; if (u.last_seen > g.last_seen) g.last_seen = u.last_seen }
  }
  if (!list.length) return null
  const need = isAdmin ? undefined : t('common:needRole', { role: t('common:role.admin') })
  const container = !data.box.ip && !!data.box.lan
  return (
    <section aria-labelledby="unknown-senders-title" className="mt-3">
    <Notice tone="warn" title={<span id="unknown-senders-title">{t('unknown.title')}</span>} info={<>
      <p>{t('unknown.notSourceInfo')} {t('unknown.otherProtoInfo')}</p>
      {container ? <p>{t('unknown.container')}</p> : null}
      {list.some((u) => u.protos.includes('udp')) ? <p>{t('unknown.forgedInfo')}</p> : null}
      <p>{t('unknown.memory')}</p>
    </>}>
      <ul className="grid gap-2">
        {list.map((u) => {
          const declared = data.sources.find((s) => s.sender_ip === u.ip)
          const facts = { ip: u.ip, proto: PROTOS.format(u.protos.map((p) => p.toUpperCase())), times: t('unknown.times', { count: u.count }), when: fmtRelative(u.last_seen) }
          return (
            <li key={u.ip} className="flex flex-wrap items-start justify-between gap-2">
              <span className="min-w-0 flex-1">
                {declared ? t('unknown.otherProto', { ...facts, name: declared.name, declared: declared.proto.toUpperCase() }) : t('unknown.notSource', facts)}
              </span>
              {declared
                ? <Button size="sm" disabled={!isAdmin} title={need} onClick={() => onEdit(declared)}>{t('unknown.edit', { name: declared.name })}</Button>
                : <Button size="sm" disabled={!isAdmin} title={need} onClick={() => onAdd({ ip: u.ip, proto: u.protos.includes('udp') ? 'udp' : u.protos[0]! })} aria-label={t('unknown.addFor', { ip: u.ip })}>{t('unknown.add')}</Button>}
            </li>
          )
        })}
      </ul>
      {list.some((u) => u.protos.includes('udp')) ? <p className="mt-2 text-muted">{t('unknown.forged')}</p> : null}
    </Notice>
    </section>
  )
}

function SourcesSection() {
  const { t } = useTranslation('logs')
  const q = useSources()
  const isAdmin = useCan('admin')
  // ?add=source (a "Add a log source" button on another page) opens the add dialog here at once, for someone who may add; the
  // parameter then leaves the URL so Back and a reload do not open it again
  const [params, setParams] = useSearchParams()
  const [adding, setAdding] = useState(() => isAdmin && params.get('add') === 'source')
  useEffect(() => {
    if (!params.has('add')) return
    const p = new URLSearchParams(params)
    p.delete('add')
    setParams(p, { replace: true })
  }, [params, setParams])
  const [addFrom, setAddFrom] = useState<{ ip: string; proto: Proto } | null>(null)
  const [editing, setEditing] = useState<LogSource | null>(null)
  const [deleting, setDeleting] = useState<LogSource | null>(null)
  const [guide, setGuide] = useState<LogSource | null>(null)
  const need = isAdmin ? undefined : t('common:needRole', { role: t('common:role.admin') })
  const addButton = <Button variant="primary" disabled={!isAdmin} title={need} onClick={() => setAdding(true)}><Plus />{t('sources.add')}</Button>
  const qc = useQueryClient()
  // Refresh the whole page's log data, not only this table: the headline, the digest, the event search and the AI digest panel of the
  // logs.panels slot (new lines showed here while the rest still said no line was received).
  // #930 review r1 L6: busy only for a refresh the person pressed, not for the refetch after a save or a delete elsewhere on the page
  const [refreshing, setRefreshing] = useState(false)
  const refreshAll = () => {
    setRefreshing(true)
    void Promise.allSettled([qc.invalidateQueries({ queryKey: ['logs'] }), qc.invalidateQueries({ queryKey: ['ai', 'digest'] })]).finally(() => setRefreshing(false))
  }
  const refresh = <Button onClick={refreshAll} busy={refreshing} busyLabel={t('refreshing')}><RefreshCw />{t('refresh')}</Button>
  const box = q.data?.box
  const description = !box ? t('sources.description', { ip: '' }) : box.ip ? t('sources.description', { ip: box.ip }) : box.lan ? t('sources.descriptionNoIpLan', { lan: box.lan }) : t('sources.descriptionNoIp')
  const descriptionInfo = !box || box.ip ? t('sources.descriptionInfo') : box.lan ? t('sources.descriptionNoIpLanInfo', { lan: box.lan }) : t('sources.descriptionNoIpInfo')
  return (
    <Section id="sources" title={t('sources.title')} description={description} info={descriptionInfo} stories={['S-LOG-1']} actions={<>{refresh}{addButton}</>}>
      <QueryState query={q}>
        {(d) => {
          const columns: ColumnDef<LogSource>[] = [
            { id: 'device', header: t('sources.col.device'), accessorFn: (r) => r.name, cell: ({ row: { original: r } }) => (
              <div className="grid">
                {r.asset_id ? <Link to={`/devices/${r.asset_id}`} className="font-medium text-accent underline-offset-4 hover:underline">{r.name}</Link> : <span className="font-medium">{r.name}</span>}
                <span className="text-caption text-muted">{CATALOG[r.kind].name}{r.asset_id || r.asset_matches.length ? '' : `, ${t('sources.notInInventory')}`}{r.asset_via === 'snmp_read' ? `, ${t('sources.viaSnmp')}` : ''}</span>
                {r.asset_matches.length > 0 && (
                  <span className="text-caption text-muted">
                    {t('sources.matchesSeveral')}{' '}
                    {r.asset_matches.map((m, i) => (
                      <span key={m.id}>{i > 0 && ', '}<Link to={`/devices/${m.id}`} className="text-accent underline-offset-4 hover:underline">{m.name}</Link></span>
                    ))}
                  </span>
                )}
              </div>
            ) },
            { id: 'ip', header: t('sources.col.ip'), accessorFn: (r) => r.sender_ip, cell: ({ row }) => <span className="whitespace-nowrap">{row.original.sender_ip}</span> },
            { id: 'proto', header: t('sources.col.proto'), accessorFn: (r) => r.proto, cell: ({ row }) => <span className="whitespace-nowrap">{protoLabel(row.original)} {row.original.port}</span> },
            { id: 'state', header: t('sources.col.state'), accessorFn: (r) => r.state, cell: ({ row }) => <Chip tone={STATE_TONE[row.original.state]}>{t(`sources.state.${row.original.state}`)}</Chip> },
            { id: 'last', header: t('sources.col.last'), accessorFn: (r) => r.last_received ?? '', cell: ({ row }) => (row.original.last_received ? <span title={fmtDateTime(row.original.last_received)}>{fmtRelative(row.original.last_received)}</span> : <span className="text-muted">{t('sources.never')}</span>) },
            { id: 'rate', header: t('sources.col.rate'), accessorFn: (r) => r.lines_per_hour, cell: ({ row }) => fmtNumber(row.original.lines_per_hour) },
            { id: 'actions', header: t('sources.col.actions'), enableSorting: false, cell: ({ row: { original: r } }) => (
              <div className="flex gap-1">
                <Button size="sm" onClick={() => setGuide(r)} aria-label={t('sources.guideFor', { name: r.name })}>{t('sources.guide')}</Button>
                <Button size="sm" variant="ghost" disabled={!isAdmin} title={need} onClick={() => setEditing(r)} aria-label={t('sources.editFor', { name: r.name })}>{t('sources.edit')}</Button>
                <Button size="sm" variant="ghost" disabled={!isAdmin} title={need} onClick={() => setDeleting(r)} aria-label={t('sources.deleteFor', { name: r.name })}>{t('sources.delete')}</Button>
              </div>
            ) },
          ]
          const hints = d.sources.filter((s) => s.state !== 'receiving')
          return (
            <>
              {/* docs/UI.md §0: the missing LAN range is one link away, on its field */}
              {/* /devices/setup is the administrator's: anyone else is told who can add it, not sent to a forbidden page (#875 r1) */}
              {!d.box.ip && !d.box.lan ? (isAdmin ? <DependencyLink className="mb-3" reason={t('sources.noIpReason')} to={LAN_RANGE} label={t('sources.noIpLink')} />
                : <p className="mb-3 text-meta text-muted">{t('sources.noIpReason')} {t('sources.noIpAskAdmin')}</p>) : null}
              {d.sources.length === 0 ? (
                <EmptyState title={t('sources.emptyTitle')} info={t('sources.emptyBodyInfo')} action={addButton}>{t('sources.emptyBody')}</EmptyState>
              ) : (
                <DataTable urlKey="log-sources" caption={t('sources.caption')} data={d.sources} columns={columns} rowTone={(r) => (r.state === 'silent' ? 'warn' : undefined)}
                  mobileRow={(r) => (
                    <div className="grid gap-1.5">
                      <div className="flex items-start justify-between gap-3">
                        <div className="grid">
                          {r.asset_id ? <Link to={`/devices/${r.asset_id}`} className="font-medium text-accent underline-offset-4 hover:underline">{r.name}</Link> : <span className="font-medium">{r.name}</span>}
                          <span className="text-caption text-muted">{CATALOG[r.kind].name}</span>
                        </div>
                        <Chip tone={STATE_TONE[r.state]}>{t(`sources.state.${r.state}`)}</Chip>
                      </div>
                      <p className="text-meta text-muted">{r.sender_ip}, {protoLabel(r)} {r.port}, {r.last_received ? fmtRelative(r.last_received) : t('sources.never')}</p>
                      <div className="flex flex-wrap gap-1">
                        <Button size="sm" onClick={() => setGuide(r)} aria-label={t('sources.guideFor', { name: r.name })}>{t('sources.guide')}</Button>
                        <Button size="sm" variant="ghost" disabled={!isAdmin} title={need} onClick={() => setEditing(r)} aria-label={t('sources.editFor', { name: r.name })}>{t('sources.edit')}</Button>
                        <Button size="sm" variant="ghost" disabled={!isAdmin} title={need} onClick={() => setDeleting(r)} aria-label={t('sources.deleteFor', { name: r.name })}>{t('sources.delete')}</Button>
                      </div>
                    </div>
                  )} />
              )}
              {hints.length ? (
                <ul className="mt-3 grid gap-1 text-meta text-muted">
                  {hints.map((s) => <li key={s.id}><span className="font-medium text-ink">{s.name}:</span> {s.state === 'silent' ? t('sources.silentHint', { port: s.port }) : t('sources.neverHint')}</li>)}
                </ul>
              ) : null}
              {d.box.tls ? <BoxCertificate tls={d.box.tls} /> : null}
              <UnknownSenders data={d} isAdmin={isAdmin} onAdd={(u) => { setAddFrom(u); setAdding(true) }} onEdit={setEditing} />
              {adding ? <SourceFormDialog open sender={addFrom ?? undefined} onOpenChange={(o) => { if (!o) { setAdding(false); setAddFrom(null) } }} onAdded={setGuide} /> : null}
              {editing ? <SourceFormDialog key={editing.id} open source={editing} onOpenChange={(o) => { if (!o) setEditing(null) }} /> : null}
              <DeleteDialog source={deleting} onClose={() => setDeleting(null)} />
              <ConfigDialog source={guide} boxIp={d.box.ip} lan={d.box.lan} onClose={() => setGuide(null)} />
            </>
          )
        }}
      </QueryState>
    </Section>
  )
}

const sampleLine = (s: string) => <span className="mt-0.5 block max-w-[60ch] truncate font-mono text-caption text-muted" title={s}>{s}</span>

// A link to /logs#bad (or #new, #spikes) lands on the Digest tab and scrolls to that block once the digest has loaded.
function ScrollToHash() {
  const { hash } = useLocation()
  useEffect(() => { if (hash.length > 1) document.getElementById(hash.slice(1))?.scrollIntoView() }, [hash])
  return null
}

/** The smallest time range of the Events tab that reaches back to `first` (the newest line is now or before). */
export function eventsWindowFor(first: string, now = Date.now()): EventWindow {
  const age = now - new Date(first).getTime()
  return age <= 3600e3 ? '1h' : age <= 86400e3 ? '24h' : '7d'
}

/** The Events tab with the keyword set to a destination and the range from its first hit to now: the log lines of the connection. */
export const eventsLinkFor = (r: Pick<IocPair, 'dest' | 'first_seen'>) => `?${new URLSearchParams({ tab: 'events', 'events.q': r.dest, 'events.window': eventsWindowFor(r.first_seen) })}`

/**
 * Connections to bad IPs or domains (S-LOG-2, S-LOG-4): one row per device and destination over the range, grouped, searched, ordered and
 * paged by the box (GET /logs/bad-connections), the newest last hit first or the most hits first. The destination opens the log lines
 * that show it (the Events tab, keyword and range set). Range, order, search and page are in the URL.
 */
function BadConnections({ feedsOn }: { feedsOn: boolean | undefined }) {
  const { t } = useTranslation('logs')
  const list = useListParams('bad')
  const [params, setParams] = useSearchParams()
  const win = params.get('bad.window') === '24h' ? '24h' : '7d'
  const sort = params.get('bad.sort') === 'hits' ? 'hits' : 'last'
  const setParam = (k: 'window' | 'sort', v: string, dflt: string) => setParams((prev) => {
    const p = new URLSearchParams(prev)
    if (v === dflt) p.delete(`bad.${k}`); else p.set(`bad.${k}`, v)
    p.delete('bad.page')
    return p
  }, { replace: true, preventScrollReset: true })
  const size = list.size ?? 25
  const q = useBadConnections({ window: win, q: list.q, sort, offset: list.page * size, limit: size })
  const via = (v: string) => (v.startsWith('syslog:') ? t('digest.bad.via.syslog', { name: v.slice(7) }) : t(`digest.bad.via.${v}`, { defaultValue: v }))
  const clear = () => list.set({ q: '', page: 0 })
  const columns: ColumnDef<IocPair>[] = [
    { id: 'device', header: t('digest.bad.col.device'), cell: ({ row: { original: r } }) => (
      <div className="grid">
        {r.asset_id ? <Link to={`/devices/${r.asset_id}`} className="font-medium text-accent underline-offset-4 hover:underline">{r.asset_name}</Link> : <span className="font-medium">{r.src_ip}</span>}
        <span className="text-caption text-muted">{r.asset_id ? r.src_ip : t('sources.notInInventory')}</span>
      </div>
    ) },
    { id: 'dst', header: t('digest.bad.col.dst'), cell: ({ row: { original: r } }) => (
      <div className="grid gap-0.5">
        <Link to={eventsLinkFor(r)} className="font-medium text-accent underline-offset-4 [overflow-wrap:anywhere] hover:underline" aria-label={t('digest.bad.showLogs', { dst: r.dest })} title={t('digest.bad.showLogs', { dst: r.dest })}>{r.dest}</Link>
        {r.listed_as ? <span className="flex items-center gap-1 text-caption text-muted">{t('digest.bad.listedAs', { name: r.listed_as })}<InfoTip topic={t('digest.bad.listedAs', { name: r.listed_as })}>{t('digest.bad.listedAsHint')}</InfoTip></span> : null}
        {r.other_devices > 0 ? <span className="text-caption text-muted">{t('digest.bad.otherDevices', { count: r.other_devices })}</span> : null}
        {r.blocked > 0 ? <span className="flex items-center gap-1"><Chip tone="warn">{r.blocked === r.hits ? t('digest.bad.blocked') : t('digest.bad.blockedSome', { count: r.blocked, hits: r.hits })}</Chip><InfoTip topic={t('digest.bad.blocked')}>{t('digest.bad.blockedHint')}</InfoTip></span> : null}
      </div>
    ) },
    { id: 'hits', header: t('digest.bad.col.hits'), cell: ({ row }) => <span className="tabular-nums">{fmtNumber(row.original.hits)}</span> },
    { id: 'seen', header: t('digest.bad.col.seen'), cell: ({ row: { original: r } }) => (
      <span className="grid whitespace-nowrap text-meta"><span>{fmtDateTime(r.last_seen)}</span>{r.hits > 1 ? <span className="text-caption text-muted">{t('digest.bad.firstSeen', { time: fmtDateTime(r.first_seen) })}</span> : null}</span>
    ) },
    { id: 'via', header: t('digest.bad.col.via'), cell: ({ row }) => <span className="grid text-meta">{row.original.seen_via.map((v) => <span key={v}>{via(v)}</span>)}</span> },
    { id: 'feed', header: t('digest.bad.col.feed'), cell: ({ row }) => <span className="text-meta text-muted">{row.original.feeds.join(', ')}</span> },
    { id: 'confidence', header: t('digest.bad.col.confidence'), cell: ({ row }) => <span className="tabular-nums">{Math.round(row.original.confidence * 100)}%</span> },
  ]
  return (
    <div className="grid gap-3">
      <ListToolbar search={{ value: list.q, onChange: (v) => list.set({ q: v, page: 0 }), label: t('digest.bad.search') }}>
        <Segmented label={t('events.window')} value={win} onChange={(v) => setParam('window', v, '7d')} options={[{ value: '24h', label: t('events.w24h') }, { value: '7d', label: t('events.w7d') }]} />
        <Select className="w-full sm:w-auto" aria-label={t('digest.bad.sortLabel')} value={sort} onChange={(e) => setParam('sort', e.target.value, 'last')}>
          <option value="last">{t('digest.bad.sortLast')}</option>
          <option value="hits">{t('digest.bad.sortHits')}</option>
        </Select>
      </ListToolbar>
      <QueryState query={q}>
        {(d) => d.total === 0 && !list.q ? (
          feedsOn === false ? <EmptyState title={t('digest.bad.emptyFeedsOff')}><DependencyLink reason={t('digest.bad.feedsOffReason')} to="/settings/modules#module-feeds" label={t('digest.bad.openModules')} /></EmptyState>
            : d.ioc_matching ? <EmptyState title={t(win === '24h' ? 'digest.bad.empty' : 'digest.bad.empty7d')} />
              : <EmptyState title={t('digest.bad.emptyNoIoc')}><DependencyLink reason={t('digest.bad.emptyNoIocAction')} to="/settings/feeds#feeds-builtin" label={t('digest.bad.openFeeds')} /></EmptyState>
        ) : (
          <DataTable caption={t('digest.bad.caption')} data={d.items} columns={columns} rowTone={() => 'danger'} pageSize={25} urlKey="bad"
            server={{ total: d.total, list }} filtered={!!list.q} onClearFilters={clear}
            mobileRow={(r) => (
              <div className="grid gap-1">
                <Link to={eventsLinkFor(r)} className="font-medium text-accent underline-offset-4 [overflow-wrap:anywhere] hover:underline" aria-label={t('digest.bad.showLogs', { dst: r.dest })}>{r.dest}</Link>
                <span className="text-meta">{r.asset_name ?? r.src_ip}{r.asset_name ? ` (${r.src_ip})` : ''}</span>
                <span className="text-caption text-muted">{t('digest.bad.mobileLine', { count: r.hits, time: fmtDateTime(r.last_seen), confidence: Math.round(r.confidence * 100) })}</span>
                {r.other_devices > 0 ? <span className="text-caption text-muted">{t('digest.bad.otherDevices', { count: r.other_devices })}</span> : null}
              </div>
            )} />
        )}
      </QueryState>
    </div>
  )
}

function DigestSections() {
  const { t } = useTranslation('logs')
  const q = useDigest()
  const feedsOn = useModuleEnabled('feeds')
  return (
    <QueryState query={q}>
      {(d) => {
        const days = d.baseline_days
        const learning = d.history_days < days
        const fresh: ColumnDef<NewItem>[] = [
          { id: 'signature', header: t('digest.new.col.signature'), accessorFn: (r) => r.signature, cell: ({ row: { original: r } }) => <div><span className="font-medium">{r.signature}</span>{sampleLine(r.sample)}</div> },
          { id: 'source', header: t('digest.new.col.source'), accessorFn: (r) => r.source_name },
          { id: 'count', header: t('digest.new.col.count'), accessorFn: (r) => r.count },
          { id: 'first', header: t('digest.new.col.first'), accessorFn: (r) => r.first_seen, cell: ({ row }) => <span className="whitespace-nowrap">{fmtDateTime(row.original.first_seen)}</span> },
        ]
        const spanRows = SPAN_IN_UI || d.bad_connections.some((h) => h.seen_via.startsWith('span_'))
        const spikes: ColumnDef<SpikeItem>[] = [
          { id: 'signature', header: t('digest.spikes.col.signature'), accessorFn: (r) => r.signature, cell: ({ row: { original: r } }) => <div><span className="font-medium">{r.signature}</span>{sampleLine(r.sample)}</div> },
          { id: 'source', header: t('digest.spikes.col.source'), accessorFn: (r) => r.source_name },
          { id: 'count', header: t('digest.spikes.col.count'), accessorFn: (r) => r.count, cell: ({ row }) => fmtNumber(row.original.count) },
          { id: 'baseline', header: t('digest.spikes.col.baseline'), accessorFn: (r) => r.baseline_per_day },
          { id: 'ratio', header: t('digest.spikes.col.ratio'), accessorFn: (r) => r.count / Math.max(r.baseline_per_day, 1), cell: ({ row }) => <span className="font-medium text-warn">{t('digest.spikes.ratio', { x: Math.round(row.original.count / Math.max(row.original.baseline_per_day, 1)) })}</span> },
        ]
        return (
          <>
            <ScrollToHash />
            <Section id="bad" title={t('digest.bad.title')} description={t(spanRows ? 'digest.bad.description' : 'digest.bad.descriptionNoSpan')}
              info={<><p>{t(spanRows ? 'digest.bad.descriptionInfo' : 'digest.bad.descriptionNoSpanInfo')}</p>{SPAN_IN_UI ? <p>{t('digest.bad.note')}</p> : spanRows ? <p>{t('digest.bad.noteKept')}</p> : null}</>} stories={['S-LOG-2', 'S-LOG-4']}>
              <BadConnections feedsOn={feedsOn} />
            </Section>
            <Section id="new" title={learning ? t('digest.new.titleLearning') : t('digest.new.title', { days })} description={t('digest.new.description')} info={t('digest.new.descriptionInfo')} stories={['S-LOG-1']}>
              {d.new.length ? <DataTable urlKey="digest-new" caption={t('digest.new.caption')} data={d.new} columns={fresh} /> : <EmptyState title={learning ? t('digest.new.emptyLearning', { n: d.history_days, days }) : t('digest.new.empty', { days })} />}
            </Section>
            <Section id="spikes" title={t('digest.spikes.title')} description={t('digest.spikes.description', { days })}>
              {d.spikes.length ? <DataTable urlKey="digest-spikes" caption={t('digest.spikes.caption')} data={d.spikes} columns={spikes} /> : <EmptyState title={t('digest.spikes.empty')} />}
            </Section>
          </>
        )
      }}
    </QueryState>
  )
}

function EventsSection({ sources }: { sources: LogSource[] }) {
  const { t } = useTranslation('logs')
  // Range, source and keyword are in the URL (events.window, events.source, events.q): a link from a bad connection opens the lines
  // of its destination, and reload or back keeps them
  const [params, setParams] = useSearchParams()
  const win: EventWindow = (['1h', '24h', '7d'] as const).find((w) => w === params.get('events.window')) ?? '24h'
  const source = params.get('events.source') ?? ''
  const setUrl = (k: 'window' | 'source', v: string, dflt: string) => setParams((prev) => {
    const p = new URLSearchParams(prev)
    if (v === dflt) p.delete(`events.${k}`); else p.set(`events.${k}`, v)
    return p
  }, { replace: true, preventScrollReset: true })
  const setWin = (w: EventWindow) => setUrl('window', w, '24h')
  const setSource = (v: string) => setUrl('source', v, '')
  // The keyword is searched by the box over the whole window (q), not in the lines already shown; it is in the URL like a list's search
  const list = useListParams('events')
  const kw = list.q
  const q = useEvents({ window: win, source, q: kw })
  // The keyword search can stop before the start of the window: "Search older lines" appends the next step below what is shown.
  const [older, setOlder] = useState<{ key: string; fetched: boolean; events: LogEvent[]; next?: string; back?: string; busy: boolean; failed: boolean }>({ key: '', fetched: false, events: [], busy: false, failed: false })
  const key = `${win}|${source}|${kw}|${q.dataUpdatedAt}`
  const extra = older.key === key ? older : { key, fetched: false, events: [] as LogEvent[], next: undefined, back: undefined, busy: false, failed: false }
  const searchOlder = (d: EventsResponse) => {
    const before = extra.fetched ? extra.next : d.next_cursor
    if (!before) return
    setOlder({ ...extra, busy: true, failed: false })
    fetchOlderEvents({ window: win, source, q: kw }, before).then(
      (r) => setOlder({ key, fetched: true, events: [...extra.events, ...r.events], next: r.next_cursor ?? undefined, back: r.searched_back_to, busy: false, failed: false }),
      () => setOlder({ ...extra, busy: false, failed: true }),
    )
  }
  const filtered = !!kw.trim() || !!source
  // One URL change for both (two in a row would each start from the same URL and the second would undo the first)
  const clearFilters = () => setParams((prev) => { const p = new URLSearchParams(prev); for (const k of ['events.q', 'events.page', 'events.source']) p.delete(k); return p }, { replace: true, preventScrollReset: true })
  const columns: ColumnDef<LogEvent>[] = [
    { id: 'time', header: t('events.col.time'), accessorFn: (r) => r.ts, cell: ({ row }) => <span className="whitespace-nowrap">{fmtDateTime(row.original.ts)}</span> },
    { id: 'source', header: t('events.col.source'), accessorFn: (r) => r.source_name, cell: ({ row }) => <span className="grid">{row.original.source_name}{row.original.host && row.original.host !== row.original.source_name ? <span className="text-caption text-muted">{row.original.host}</span> : null}</span> },
    { id: 'line', header: t('events.col.message'), accessorFn: (r) => r.message, enableSorting: false, cell: ({ row }) => <Message e={row.original} /> },
  ]
  return (
    <Section id="events" title={t('events.title')} description={t('events.description')}>
      <ListToolbar className="mb-3" search={{ value: kw, onChange: (v) => list.set({ q: v, page: 0 }), label: t('events.q'), placeholder: t('events.qPlaceholder') }}>
        <Segmented label={t('events.window')} value={win} onChange={setWin} options={[{ value: '1h', label: t('events.w1h') }, { value: '24h', label: t('events.w24h') }, { value: '7d', label: t('events.w7d') }]} />
        <Select className="w-full sm:w-auto" aria-label={t('events.source')} value={source} onChange={(e) => setSource(e.target.value)}><option value="">{t('events.allSources')}</option>{sources.map((s) => <option key={s.id} value={s.id}>{s.name}</option>)}</Select>
      </ListToolbar>
      <QueryState query={q}>
        {(d) => {
          const rows = [...d.events, ...extra.events]
          const next = extra.fetched ? extra.next : d.next_cursor ?? undefined
          const back = extra.fetched ? extra.back : d.searched_back_to
          return (
          <>
            {next ? (
              <div className="mb-2 flex flex-wrap items-center gap-3 text-meta text-muted">
                <p aria-live="polite">{t('events.partial', { count: rows.length, time: back ? fmtDateTime(back) : '' })}</p>
                <Button disabled={q.isPlaceholderData} busy={extra.busy} busyLabel={t('events.searchingOlder')} onClick={() => searchOlder(d)}>{t('events.searchOlder')}</Button>
                {extra.failed ? <span role="alert" className="text-danger">{t('events.searchOlderFailed')}</span> : null}
              </div>
            ) : (
              <p className="mb-2 text-meta text-muted">{kw.trim() ? t('events.found', { count: rows.length }) : t('events.count', { shown: d.events.length, total: d.total })} {!kw.trim() && d.total > d.events.length ? t('events.capped') : ''}</p>
            )}
            <DataTable caption={t('events.caption')} data={rows} columns={columns} pageSize={25} search={false} urlKey="events" resetPageOn={`${win}-${source}`} mobileRow={(r) => (
              <div className="grid gap-1"><p className="text-caption text-muted">{fmtDateTime(r.ts)}, {r.source_name}{r.host && r.host !== r.source_name ? ` (${r.host})` : ''}</p><Message e={r} /></div>
            )} empty={<span className="inline-flex items-center gap-1">{t('events.emptyNone')}<InfoTip topic={t('events.title')}>{t('events.emptyNoneInfo')}</InfoTip></span>}
              filtered={filtered} onClearFilters={clearFilters}
              emptyFiltered={<span className="inline-flex flex-wrap items-center justify-center gap-x-2 gap-y-1">{t('events.empty')}<Button size="sm" variant="link" onClick={clearFilters}>{t('common:table.clearFilters')}</Button></span>} />
          </>
          )
        }}
      </QueryState>
    </Section>
  )
}

/** The line without its syslog header: the program, then the message; the stored line is the tooltip. */
function Message({ e }: { e: LogEvent }) {
  return <span className="break-all font-mono text-caption" title={e.line}>{e.app ? <span className="text-muted">{e.app}: </span> : null}{e.message}</span>
}

/** Bytes as the page says them: decimal units, one decimal from MB up. */
function sizeText(n: number) {
  if (n >= 1e12) return `${(n / 1e12).toFixed(1)} TB`
  if (n >= 1e9) return `${(n / 1e9).toFixed(1)} GB`
  if (n >= 1e6) return `${(n / 1e6).toFixed(1)} MB`
  if (n >= 1e3) return `${Math.round(n / 1e3)} kB`
  return `${n} B`
}

function RetentionSection({ days, linesPerHour, logsBytes, freeBytes }: { days: number; linesPerHour: number; logsBytes: number | null; freeBytes: number | null }) {
  const { t } = useTranslation('logs')
  const set = useSetRetention()
  const isAdmin = useCan('admin')
  const mb = fmtNumber(Math.max(1, Math.round((linesPerHour * 24 * days * 220) / 1e6)))
  const [pending, setPending] = useState<number | null>(null)
  const save = (n: number) => set.mutate(n, { onSuccess: () => toast.success(t('retention.saved')), onError: (er) => toast.error(er instanceof ApiError ? er.message : String(er)), onSettled: () => setPending(null) })
  return (
    <Section id="retention" title={t('retention.title')} description={linesPerHour > 0 ? t('retention.description', { days, mb }) : t('retention.descriptionNone')}>
      <Card className="max-w-xl">
      <Field label={t('retention.label')} htmlFor="ret-days" className="max-w-xs">
        <Select id="ret-days" value={days} disabled={!isAdmin || set.isPending} title={isAdmin ? undefined : t('common:needRole', { role: t('common:role.admin') })}
          onChange={(e) => { const n = Number(e.target.value); if (n < days) setPending(n); else save(n) }}>
          {[7, 30, 90, 180].map((n) => <option key={n} value={n}>{t('retention.option', { n })}</option>)}
        </Select>
      </Field>
      <dl className="mt-4 grid max-w-xs grid-cols-[auto_1fr] gap-x-6 gap-y-1 text-sm">
        <dt className="text-muted">{t('retention.usedLabel')}</dt><dd className="text-right">{logsBytes === null ? t('retention.unknown') : sizeText(logsBytes)}</dd>
        <dt className="text-muted">{t('retention.freeLabel')}</dt><dd className="text-right">{freeBytes === null ? t('retention.unknown') : sizeText(freeBytes)}</dd>
      </dl>
      </Card>
      <Dialog open={pending !== null} onOpenChange={(o) => { if (!o && !set.isPending) setPending(null) }}>
        {pending !== null ? (
          <DialogContent title={t('retention.shortenTitle', { n: pending })} description={t('retention.shortenBody', { n: pending })}>
            <DialogFooter>
              <Button disabled={set.isPending} onClick={() => setPending(null)}>{t('common:cancel')}</Button>
              <Button variant="danger" busy={set.isPending} busyLabel={t('common:busy.saving')} onClick={() => save(pending)}>{t('retention.shortenConfirm')}</Button>
            </DialogFooter>
          </DialogContent>
        ) : null}
      </Dialog>
    </Section>
  )
}

// Old #anchor → tab (before the tabs these were the six blocks of one page).
const ANCHOR_TAB: Record<string, string> = { sources: 'sources', bad: 'digest', new: 'digest', spikes: 'digest', events: 'events', retention: 'retention' }

function Content() {
  const { t } = useTranslation('logs')
  const sources = useSources()
  const digest = useDigest()
  const feedsOn = useModuleEnabled('feeds')
  let title = t('titleLoading')
  const noSources = sources.data?.sources.length === 0
  const noLogs = !noSources && digest.data !== undefined && digest.data.lines_24h === 0
  const learning = digest.data !== undefined && digest.data.history_days < digest.data.baseline_days
  if (noSources) title = t('titleNoSources')
  else if (noLogs) title = t('titleNoLogs')
  else if (digest.data) {
    const { bad_connections: b, new: n, spikes: s } = digest.data
    // No count of bad connections when none can be matched (Feeds off, or no IOC feed lists anything): "0" would read as "none happened".
    const unmatched = b.length === 0 && (feedsOn === false || !digest.data.ioc_matching)
    if (b.length + n.length + s.length === 0) title = learning ? t('titleLearning', { n: digest.data.history_days, days: digest.data.baseline_days }) : t('titleQuiet')
    else {
      // A hit the logging device blocked is an attempt, counted apart from the connections that went through.
      const attempts = b.filter((h) => h.blocked).length
      const connections = b.length - attempts
      const bad = connections && attempts
        ? t('headline.badBoth', { connections: t('headline.connections', { count: connections }), attempts: t('headline.attempts', { count: attempts }) })
        : t('headline.bad', { what: attempts ? t('headline.attempts', { count: attempts }) : t('headline.connections', { count: connections }) })
      const rest = { fresh: t('headline.fresh', { count: n.length }), spikes: t('headline.spikes', { count: s.length }) }
      title = unmatched ? t('titleNoIoc', rest) : t('title', { bad, ...rest })
    }
  }
  const sourceList = sources.data?.sources ?? []
  const { hash, search } = useLocation()
  // Links from before the tabs (/logs#sources, #bad, #new, #spikes, #events, #retention) land on the right tab; the Digest blocks keep their
  // hash so the page scrolls to them. Any other hash (the skip link's #main) stays as it is.
  const anchorTab = ANCHOR_TAB[hash.slice(1)]
  if (anchorTab && new URLSearchParams(search).get('tab') !== anchorTab) {
    const p = new URLSearchParams(search)
    p.set('tab', anchorTab)
    return <Navigate replace to={{ search: `?${p}`, hash: anchorTab === 'digest' ? hash : '' }} />
  }
  const d = digest.data
  const receiving = sourceList.filter((x) => x.state === 'receiving').length
  const bad = d?.bad_connections ?? []
  // No count of bad connections when none can be matched (Feeds off, or no IOC feed lists anything): "0" would read as "none happened".
  const matchable = bad.length > 0 || (feedsOn !== false && !!d?.ioc_matching)
  const kpis = sources.data && d && !noSources ? [
    { value: matchable ? fmtNumber(bad.length) : '–', label: t('kpi.bad'), to: '?tab=digest' },
    { value: fmtNumber(d.new.length), label: t('kpi.new'), to: '?tab=digest' },
    { value: `${receiving} / ${sourceList.length}`, label: t('kpi.sources'), to: '?tab=sources' },
    { value: fmtNumber(sourceList.reduce((n, x) => n + x.lines_per_hour, 0)), label: t('kpi.lines'), to: '?tab=events' },
  ] : []
  const retention = sources.data ? [{ id: 'retention', label: t('tabs.retention'), panel: <RetentionSection days={sources.data.retention_days} linesPerHour={sourceList.reduce((n, x) => n + x.lines_per_hour, 0)} logsBytes={sources.data.logs_bytes ?? null} freeBytes={sources.data.disk_free_bytes ?? null} /> }] : []
  const sourcesTab = { id: 'sources', label: t('tabs.sources'), panel: <SourcesSection /> }
  return (
    <>
      <PageHeader title={title} info={t('pageInfo')} stories={['S-LOG-1', 'S-LOG-2', 'S-LOG-4']}
        meta={digest.data && !noSources && !noLogs ? <span className="inline-flex flex-wrap items-center gap-2">{t(learning ? 'metaLearning' : 'meta', { lines: fmtNumber(digest.data.lines_24h), days: digest.data.baseline_days, time: fmtDateTime(digest.data.generated_at) })}<SampleDataNote /></span> : null} />
      {kpis.length ? <KpiStrip label={t('kpi.label')} items={kpis} /> : null}
      <PageTabs label={t('tabs.label')} tabs={noSources ? [sourcesTab, ...retention] : [
        { id: 'digest', label: t('tabs.digest'), panel: <>
          {noLogs ? <EmptyState title={t('digest.none.title')} info={t('digest.none.bodyInfo')}>{t('digest.none.body')}</EmptyState> : <DigestSections />}
          <Slot name="logs.panels" props={{}} />
        </> },
        { id: 'events', label: t('tabs.events'), panel: <EventsSection sources={sourceList} /> },
        sourcesTab,
        ...retention,
      ]} />
    </>
  )
}

export default function LogsPage() {
  return <RequireModule module="logs" page><Content /></RequireModule>
}
