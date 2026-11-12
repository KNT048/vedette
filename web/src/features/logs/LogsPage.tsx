import { useDeferredValue, useState } from 'react'
import { Link } from 'react-router'
import { useTranslation } from 'react-i18next'
import { toast } from 'sonner'
import { Plus, RefreshCw } from 'lucide-react'
import { PageHeader, Section } from '@/components/common/PageHeader'
import { DataTable, type ColumnDef } from '@/components/common/DataTable'
import { EmptyState, QueryState, RequireModule, SampleDataNote } from '@/components/common/States'
import { Chip } from '@/components/common/StatusChip'
import { Slot } from '@/components/common/Slot'
import { Button } from '@/components/ui/button'
import { Dialog, DialogContent, DialogFooter } from '@/components/ui/dialog'
import { Field, Input, Select } from '@/components/ui/input'
import { Segmented } from '@/components/ui/segmented'
import { ApiError } from '@/lib/api'
import { fmtDateTime, fmtNumber, fmtRelative } from '@/lib/format'
import { useModuleEnabled } from '@/lib/modules'
import { useCan } from '@/lib/session'
import { useDigest, useEvents, useSetRetention, useSources } from './api'
import { CATALOG } from './catalog'
import { ConfigDialog, DeleteDialog, SourceFormDialog } from './SourceDialogs'
import type { IocHit, EventWindow, LogEvent, LogSource, NewItem, SpikeItem } from './types'

const STATE_TONE = { receiving: 'ok', silent: 'warn', never: 'off' } as const

function SourcesSection() {
  const { t } = useTranslation('logs')
  const q = useSources()
  const isAdmin = useCan('admin')
  const [adding, setAdding] = useState(false)
  const [editing, setEditing] = useState<LogSource | null>(null)
  const [deleting, setDeleting] = useState<LogSource | null>(null)
  const [guide, setGuide] = useState<LogSource | null>(null)
  const need = isAdmin ? undefined : t('common:needRole', { role: t('common:role.admin') })
  const addButton = <Button variant="primary" disabled={!isAdmin} title={need} onClick={() => setAdding(true)}><Plus />{t('sources.add')}</Button>
  const refresh = <Button onClick={() => void q.refetch()} disabled={q.isFetching}><RefreshCw />{t('refresh')}</Button>
  return (
    <Section id="sources" title={t('sources.title')} description={q.data && !q.data.box.ip ? t('sources.descriptionNoIp') : t('sources.description', { ip: q.data?.box.ip ?? '' })} stories={['S-LOG-1']} actions={<>{refresh}{addButton}</>}>
      <QueryState query={q}>
        {(d) => {
          const columns: ColumnDef<LogSource>[] = [
            { id: 'device', header: t('sources.col.device'), accessorFn: (r) => r.name, cell: ({ row: { original: r } }) => (
              <div className="grid">
                {r.asset_id ? <Link to={`/devices/${r.asset_id}`} className="font-medium text-accent underline-offset-4 hover:underline">{r.name}</Link> : <span className="font-medium">{r.name}</span>}
                <span className="text-[12px] text-muted">{CATALOG[r.kind].name}{r.asset_id ? '' : `, ${t('sources.notInInventory')}`}</span>
              </div>
            ) },
            { id: 'ip', header: t('sources.col.ip'), accessorFn: (r) => r.sender_ip, cell: ({ row }) => <span className="whitespace-nowrap">{row.original.sender_ip}</span> },
            { id: 'proto', header: t('sources.col.proto'), accessorFn: (r) => r.proto, cell: ({ row }) => <span className="whitespace-nowrap">{row.original.proto.toUpperCase()} {row.original.port}</span> },
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
              {d.sources.length === 0 ? (
                <EmptyState title={t('sources.emptyTitle')} action={addButton}>{t('sources.emptyBody')}</EmptyState>
              ) : (
                <DataTable caption={t('sources.caption')} data={d.sources} columns={columns} rowTone={(r) => (r.state === 'silent' ? 'warn' : undefined)}
                  mobileRow={(r) => (
                    <div className="grid gap-1.5">
                      <div className="flex items-start justify-between gap-3">
                        <div className="grid">
                          {r.asset_id ? <Link to={`/devices/${r.asset_id}`} className="font-medium text-accent underline-offset-4 hover:underline">{r.name}</Link> : <span className="font-medium">{r.name}</span>}
                          <span className="text-[12px] text-muted">{CATALOG[r.kind].name}</span>
                        </div>
                        <Chip tone={STATE_TONE[r.state]}>{t(`sources.state.${r.state}`)}</Chip>
                      </div>
                      <p className="text-[13px] text-muted">{r.sender_ip}, {r.proto.toUpperCase()} {r.port}, {r.last_received ? fmtRelative(r.last_received) : t('sources.never')}</p>
                      <div className="flex flex-wrap gap-1">
                        <Button size="sm" onClick={() => setGuide(r)} aria-label={t('sources.guideFor', { name: r.name })}>{t('sources.guide')}</Button>
                        <Button size="sm" variant="ghost" disabled={!isAdmin} title={need} onClick={() => setEditing(r)} aria-label={t('sources.editFor', { name: r.name })}>{t('sources.edit')}</Button>
                        <Button size="sm" variant="ghost" disabled={!isAdmin} title={need} onClick={() => setDeleting(r)} aria-label={t('sources.deleteFor', { name: r.name })}>{t('sources.delete')}</Button>
                      </div>
                    </div>
                  )} />
              )}
              {hints.length ? (
                <ul className="mt-3 grid gap-1 text-[13px] text-muted">
                  {hints.map((s) => <li key={s.id}><span className="font-medium text-ink">{s.name}:</span> {s.state === 'silent' ? t('sources.silentHint', { port: s.port }) : t('sources.neverHint')}</li>)}
                </ul>
              ) : null}
              {adding ? <SourceFormDialog open onOpenChange={(o) => { if (!o) setAdding(false) }} onAdded={setGuide} /> : null}
              {editing ? <SourceFormDialog key={editing.id} open source={editing} onOpenChange={(o) => { if (!o) setEditing(null) }} /> : null}
              <DeleteDialog source={deleting} onClose={() => setDeleting(null)} />
              <ConfigDialog source={guide} boxIp={d.box.ip} onClose={() => setGuide(null)} />
            </>
          )
        }}
      </QueryState>
    </Section>
  )
}

const sampleLine = (s: string) => <span className="mt-0.5 block max-w-[60ch] truncate font-mono text-[12px] text-muted" title={s}>{s}</span>

function DigestSections() {
  const { t } = useTranslation('logs')
  const q = useDigest()
  const feedsOn = useModuleEnabled('feeds')
  return (
    <QueryState query={q}>
      {(d) => {
        const days = d.baseline_days
        const via = (v: string) => (v.startsWith('syslog:') ? t('digest.bad.via.syslog', { name: v.slice(7) }) : t(`digest.bad.via.${v}`, { defaultValue: v }))
        const bad: ColumnDef<IocHit>[] = [
          { id: 'last', header: t('digest.bad.col.last'), accessorFn: (r) => r.ts, cell: ({ row }) => <span className="whitespace-nowrap">{fmtDateTime(row.original.ts)}</span> },
          { id: 'device', header: t('digest.bad.col.device'), accessorFn: (r) => r.asset_name ?? r.src_ip, cell: ({ row: { original: r } }) => (
            <div className="grid">
              {r.asset_id ? <Link to={`/devices/${r.asset_id}`} className="font-medium text-accent underline-offset-4 hover:underline">{r.asset_name}</Link> : <span className="font-medium">{r.src_ip}</span>}
              <span className="text-[12px] text-muted">{r.asset_id ? r.src_ip : t('sources.notInInventory')}</span>
            </div>
          ) },
          { id: 'dst', header: t('digest.bad.col.dst'), accessorFn: (r) => r.dest, cell: ({ row: { original: r } }) => (
            <div className="grid"><span className="font-medium">{r.dest}</span><Link to={`/lookup?q=${encodeURIComponent(r.dest)}`} className="text-[12px] text-accent underline-offset-4 hover:underline">{t('digest.bad.lookup', { dst: r.dest })}</Link></div>
          ) },
          { id: 'via', header: t('digest.bad.col.via'), accessorFn: (r) => via(r.seen_via), cell: ({ row }) => <span className="text-[13px]">{via(row.original.seen_via)}</span> },
          { id: 'feed', header: t('digest.bad.col.feed'), accessorFn: (r) => r.feeds.join(', '), cell: ({ row }) => <span className="text-[13px] text-muted">{row.original.feeds.join(', ')}</span> },
          { id: 'confidence', header: t('digest.bad.col.confidence'), accessorFn: (r) => r.confidence, cell: ({ row }) => <span className="tabular-nums">{Math.round(row.original.confidence * 100)}%</span> },
        ]
        const fresh: ColumnDef<NewItem>[] = [
          { id: 'signature', header: t('digest.new.col.signature'), accessorFn: (r) => r.signature, cell: ({ row: { original: r } }) => <div><span className="font-medium">{r.signature}</span>{sampleLine(r.sample)}</div> },
          { id: 'source', header: t('digest.new.col.source'), accessorFn: (r) => r.source_name },
          { id: 'count', header: t('digest.new.col.count'), accessorFn: (r) => r.count },
          { id: 'first', header: t('digest.new.col.first'), accessorFn: (r) => r.first_seen, cell: ({ row }) => <span className="whitespace-nowrap">{fmtDateTime(row.original.first_seen)}</span> },
        ]
        const spikes: ColumnDef<SpikeItem>[] = [
          { id: 'signature', header: t('digest.spikes.col.signature'), accessorFn: (r) => r.signature, cell: ({ row: { original: r } }) => <div><span className="font-medium">{r.signature}</span>{sampleLine(r.sample)}</div> },
          { id: 'source', header: t('digest.spikes.col.source'), accessorFn: (r) => r.source_name },
          { id: 'count', header: t('digest.spikes.col.count'), accessorFn: (r) => r.count, cell: ({ row }) => fmtNumber(row.original.count) },
          { id: 'baseline', header: t('digest.spikes.col.baseline'), accessorFn: (r) => r.baseline_per_day },
          { id: 'ratio', header: t('digest.spikes.col.ratio'), accessorFn: (r) => r.count / Math.max(r.baseline_per_day, 1), cell: ({ row }) => <span className="font-medium text-warn">{t('digest.spikes.ratio', { x: Math.round(row.original.count / Math.max(row.original.baseline_per_day, 1)) })}</span> },
        ]
        return (
          <>
            <Section id="bad" title={t('digest.bad.title')} description={t('digest.bad.description')} stories={['S-LOG-2', 'S-LOG-4']}>
              {d.bad_connections.length ? <><DataTable caption={t('digest.bad.caption')} data={d.bad_connections} columns={bad} rowTone={() => 'danger'} /><p className="mt-2 text-[13px] text-muted">{t('digest.bad.note')}</p></> : <EmptyState title={t('digest.bad.empty')}>{feedsOn === undefined ? null : feedsOn ? t('digest.bad.emptyWhy') : t('digest.bad.emptyFeedsOff')}</EmptyState>}
            </Section>
            <Section id="new" title={t('digest.new.title', { days })} description={t('digest.new.description')} stories={['S-LOG-1']}>
              {d.new.length ? <DataTable caption={t('digest.new.caption')} data={d.new} columns={fresh} /> : <EmptyState title={t('digest.new.empty', { days })} />}
            </Section>
            <Section id="spikes" title={t('digest.spikes.title')} description={t('digest.spikes.description', { days })}>
              {d.spikes.length ? <DataTable caption={t('digest.spikes.caption')} data={d.spikes} columns={spikes} /> : <EmptyState title={t('digest.spikes.empty')} />}
            </Section>
          </>
        )
      }}
    </QueryState>
  )
}

function EventsSection({ sources }: { sources: LogSource[] }) {
  const { t } = useTranslation('logs')
  const [win, setWin] = useState<EventWindow>('24h')
  const [source, setSource] = useState('')
  const [text, setText] = useState('')
  const q = useEvents({ window: win, source, q: useDeferredValue(text) })
  const columns: ColumnDef<LogEvent>[] = [
    { id: 'time', header: t('events.col.time'), accessorFn: (r) => r.ts, cell: ({ row }) => <span className="whitespace-nowrap">{fmtDateTime(row.original.ts)}</span> },
    { id: 'source', header: t('events.col.source'), accessorFn: (r) => r.source_name },
    { id: 'line', header: t('events.col.line'), accessorFn: (r) => r.line, enableSorting: false, cell: ({ row }) => <span className="break-all font-mono text-[12px]">{row.original.line}</span> },
  ]
  return (
    <Section id="events" title={t('events.title')} description={t('events.description')}>
      <div className="mb-3 flex flex-wrap items-end gap-3">
        <Segmented label={t('events.window')} value={win} onChange={setWin} options={[{ value: '1h', label: t('events.w1h') }, { value: '24h', label: t('events.w24h') }, { value: '7d', label: t('events.w7d') }]} />
        <Field label={t('events.source')} htmlFor="ev-source"><Select id="ev-source" className="h-8 w-44" value={source} onChange={(e) => setSource(e.target.value)}><option value="">{t('events.allSources')}</option>{sources.map((s) => <option key={s.id} value={s.id}>{s.name}</option>)}</Select></Field>
        <Field label={t('events.q')} htmlFor="ev-q"><Input id="ev-q" className="h-8 w-56" value={text} onChange={(e) => setText(e.target.value)} placeholder={t('events.qPlaceholder')} autoComplete="off" /></Field>
      </div>
      <QueryState query={q}>
        {(d) => (
          <>
            <p className="mb-2 text-[13px] text-muted">{t('events.count', { shown: d.events.length, total: d.total })} {d.total > d.events.length ? t('events.capped') : ''}</p>
            <DataTable key={`${win}-${source}-${text}`} caption={t('events.caption')} data={d.events} columns={columns} pageSize={25} mobileRow={(r) => (
              <div className="grid gap-1"><p className="text-[12px] text-muted">{fmtDateTime(r.ts)}, {r.source_name}</p><p className="break-all font-mono text-[12px]">{r.line}</p></div>
            )} empty={!text.trim() && !source ? t('events.emptyNone') : t('events.empty')} />
          </>
        )}
      </QueryState>
    </Section>
  )
}

function RetentionSection({ days, linesPerHour }: { days: number; linesPerHour: number }) {
  const { t } = useTranslation('logs')
  const set = useSetRetention()
  const isAdmin = useCan('admin')
  const mb = fmtNumber(Math.max(1, Math.round((linesPerHour * 24 * days * 220) / 1e6)))
  const [pending, setPending] = useState<number | null>(null)
  const save = (n: number) => set.mutate(n, { onSuccess: () => toast.success(t('retention.saved')), onError: (er) => toast.error(er instanceof ApiError ? er.message : String(er)), onSettled: () => setPending(null) })
  return (
    <Section id="retention" title={t('retention.title')} description={t('retention.description', { days, mb })}>
      <Field label={t('retention.label')} htmlFor="ret-days" className="max-w-xs">
        <Select id="ret-days" value={days} disabled={!isAdmin || set.isPending} title={isAdmin ? undefined : t('common:needRole', { role: t('common:role.admin') })}
          onChange={(e) => { const n = Number(e.target.value); if (n < days) setPending(n); else save(n) }}>
          {[7, 30, 90, 180].map((n) => <option key={n} value={n}>{t('retention.option', { n })}</option>)}
        </Select>
      </Field>
      <Dialog open={pending !== null} onOpenChange={(o) => { if (!o) setPending(null) }}>
        {pending !== null ? (
          <DialogContent title={t('retention.shortenTitle', { n: pending })} description={t('retention.shortenBody', { n: pending })}>
            <DialogFooter>
              <Button onClick={() => setPending(null)}>{t('common:cancel')}</Button>
              <Button variant="danger" disabled={set.isPending} onClick={() => save(pending)}>{t('retention.shortenConfirm')}</Button>
            </DialogFooter>
          </DialogContent>
        ) : null}
      </Dialog>
    </Section>
  )
}

function Content() {
  const { t } = useTranslation('logs')
  const sources = useSources()
  const digest = useDigest()
  let title = t('titleLoading')
  const noSources = sources.data?.sources.length === 0
  const noLogs = !noSources && digest.data !== undefined && digest.data.lines_24h === 0
  if (noSources) title = t('titleNoSources')
  else if (noLogs) title = t('titleNoLogs')
  else if (digest.data) {
    const { bad_connections: b, new: n, spikes: s } = digest.data
    title = b.length + n.length + s.length === 0 ? t('titleQuiet') : t('title', { bad: b.length, fresh: n.length, spikes: s.length })
  }
  const sourceList = sources.data?.sources ?? []
  return (
    <>
      <PageHeader title={title} stories={['S-LOG-1', 'S-LOG-2', 'S-LOG-4']}
        meta={digest.data && !noSources && !noLogs ? <span className="inline-flex flex-wrap items-center gap-2">{t('meta', { lines: fmtNumber(digest.data.lines_24h), days: digest.data.baseline_days, time: fmtDateTime(digest.data.generated_at) })}<SampleDataNote /></span> : null} />
      <SourcesSection />
      {noSources ? null : noLogs ? <EmptyState title={t('digest.none.title')}>{t('digest.none.body')}</EmptyState> : <DigestSections />}
      {noSources ? null : <Slot name="logs.panels" props={{}} />}
      {noSources ? null : <EventsSection sources={sourceList} />}
      {sources.data ? <RetentionSection days={sources.data.retention_days} linesPerHour={sourceList.reduce((n, s) => n + s.lines_per_hour, 0)} /> : null}
    </>
  )
}

export default function LogsPage() {
  return <RequireModule module="logs"><Content /></RequireModule>
}
