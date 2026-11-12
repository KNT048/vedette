import { useState } from 'react'
import { useTranslation } from 'react-i18next'
import { toast } from 'sonner'
import { PageHeader, Section } from '@/components/common/PageHeader'
import { DataTable } from '@/components/common/DataTable'
import { EmptyState, QueryState } from '@/components/common/States'
import { Chip } from '@/components/common/StatusChip'
import { Button } from '@/components/ui/button'
import { Switch } from '@/components/ui/switch'
import { fmtNumber, fmtRelative } from '@/lib/format'
import { useCan } from '@/lib/session'
import { useFeedSources, useFetchFeed, usePatchFeed } from './api'
import { BuiltinDialog, CustomDialog, DeleteDialog } from './FeedDialogs'
import type { Feed } from './types'

/** Settings → Feeds (S-FEED-4, D-36, D-37): built-in feeds (switch, schedule, mirror) and your own feeds with parsing rules. Admin edits; others read. */
export default function FeedsSettings() {
  const { t } = useTranslation('feeds')
  const sources = useFeedSources()
  return (
    <div className="grid max-w-5xl gap-2">
      <PageHeader title={t('settings.title')} meta={t('settings.direct')} stories={['S-FEED-4', 'S-FEED-5']} />
      <QueryState query={sources}>{(d) => <Tables items={d.items} />}</QueryState>
    </div>
  )
}

function Tables({ items }: { items: Feed[] }) {
  const { t } = useTranslation('feeds')
  const admin = useCan('admin')
  const patch = usePatchFeed()
  const fetchNow = useFetchFeed()
  const [builtin, setBuiltin] = useState<Feed | null>(null)
  const [custom, setCustom] = useState<Feed | 'new' | null>(null)
  const [del, setDel] = useState<Feed | null>(null)
  const reason = admin ? undefined : t('common:needRole', { role: t('common:role.admin') })
  const builtins = items.filter((f) => f.builtin)
  const customs = items.filter((f) => !f.builtin)

  function runFetch(f: Feed) {
    fetchNow.mutate(f.id, {
      onSuccess: (r) => (r.status === 'ok' ? toast.success(t('row.fetched', { name: r.name, count: r.records ?? 0 })) : toast.error(`${r.name}: ${r.error ?? t('row.failed')}`)),
      onError: (e) => toast.error(e instanceof Error ? e.message : String(e)),
    })
  }
  const status = (f: Feed) => (
    <span className="grid gap-0.5">
      <span><Chip tone={f.status === 'ok' ? 'ok' : f.status === 'error' ? 'danger' : 'off'}>{t(`status.${f.status}`)}</Chip></span>
      {f.answered_by ? <span className="text-[12px] text-muted">{t('row.answeredBy', { source: f.answered_by })}</span> : null}
      {f.error ? <span className="max-w-64 text-[12px] text-muted">{f.error}</span> : null}
    </span>
  )
  const toggle = (f: Feed) => (
    <Switch checked={f.enabled} disabled={!admin || patch.isPending} title={reason} aria-label={t('row.enable', { name: f.name })}
      onCheckedChange={(v) => patch.mutate({ id: f.id, enabled: v }, { onSuccess: () => toast.success(v ? t('row.nowOn', { name: f.name }) : t('row.nowOff', { name: f.name })) })} />
  )
  const last = (f: Feed) => (f.last_fetch ? <span title={f.last_fetch}>{fmtRelative(f.last_fetch)}</span> : <span className="text-muted">{t('row.never')}</span>)
  const fetchBtn = (f: Feed) => (
    <Button size="sm" disabled={!admin || !f.enabled || (fetchNow.isPending && fetchNow.variables === f.id)} title={reason ?? (f.enabled ? undefined : t('row.turnOnFirst'))} aria-label={t('row.fetchNamed', { name: f.name })} onClick={() => runFetch(f)}>
      {fetchNow.isPending && fetchNow.variables === f.id ? t('row.fetching') : t('row.fetchNow')}
    </Button>
  )
  type R = { row: { original: Feed } }
  const common = {
    on: { id: 'on', header: t('col.on'), enableSorting: false, accessorKey: 'enabled', cell: ({ row }: R) => toggle(row.original) },
    schedule: { id: 'schedule', header: t('col.schedule'), accessorKey: 'interval_hours', cell: ({ row }: R) => <span className="whitespace-nowrap">{t('row.every', { count: row.original.interval_hours })}</span> },
    last: { id: 'last', header: t('col.last'), accessorKey: 'last_fetch', cell: ({ row }: R) => last(row.original) },
    records: { id: 'records', header: t('col.records'), accessorKey: 'records', cell: ({ row }: R) => (row.original.records === null ? <span className="text-muted">-</span> : fmtNumber(row.original.records)) },
    status: { id: 'status', header: t('col.status'), accessorKey: 'status', cell: ({ row }: R) => status(row.original) },
  }
  const name = (f: Feed) => (
    <span className="grid"><span className="font-medium">{f.name}</span><span className="text-[12px] text-muted">{t(`kind.${f.kind}`)}{f.builtin && f.license ? `, ${f.license}` : `, ${t(`parser.formats.${f.format}`)}`}</span></span>
  )
  const mobile = (f: Feed, actions: React.ReactNode) => (
    <div className="grid gap-1.5 text-sm">
      <p className="flex flex-wrap items-center gap-3 font-medium">{f.name} {toggle(f)}</p>
      <p className="text-muted">{t(`kind.${f.kind}`)}, {t('row.every', { count: f.interval_hours })}, {f.last_fetch ? fmtRelative(f.last_fetch) : t('row.never')}, {f.records === null ? '-' : t('row.records', { count: f.records, n: fmtNumber(f.records) })}</p>
      {status(f)}
      <span className="flex flex-wrap gap-2">{actions}</span>
    </div>
  )
  const builtinActions = (f: Feed) => (
    <>
      <Button size="sm" disabled={!admin} title={reason} aria-label={t('row.settingsNamed', { name: f.name })} onClick={() => setBuiltin(f)}>{t('row.settings')}</Button>
      {fetchBtn(f)}
    </>
  )
  const customActions = (f: Feed) => (
    <>
      <Button size="sm" disabled={!admin} title={reason} aria-label={t('row.editNamed', { name: f.name })} onClick={() => setCustom(f)}>{t('row.edit')}</Button>
      {fetchBtn(f)}
      <Button size="sm" disabled={!admin} title={reason} aria-label={t('row.deleteNamed', { name: f.name })} onClick={() => setDel(f)}>{t('common:delete')}</Button>
    </>
  )
  const addBtn = <Button variant="primary" disabled={!admin} title={reason} onClick={() => setCustom('new')}>{t('custom.add')}</Button>

  return (
    <>
      <Section id="feeds-builtin" title={t('builtin.title')} description={t('builtin.description')} stories={['S-FEED-4']}>
        <DataTable<Feed> caption={t('builtin.caption')} data={builtins} mobileRow={(f) => mobile(f, builtinActions(f))}
          columns={[
            { id: 'name', header: t('col.feed'), accessorKey: 'name', cell: ({ row }: R) => name(row.original) },
            common.on, common.schedule, common.last, common.records, common.status,
            { id: 'actions', header: t('col.actions'), enableSorting: false, cell: ({ row }: R) => <span className="flex flex-wrap gap-2">{builtinActions(row.original)}</span> },
          ]} />
      </Section>
      <Section id="feeds-custom" title={t('custom.title')} description={t('custom.description')} actions={customs.length ? addBtn : undefined} stories={['S-FEED-4', 'S-FEED-5']}>
        {customs.length === 0 ? (
          <EmptyState title={t('custom.empty')} action={addBtn}>{t('custom.emptyBody')}</EmptyState>
        ) : (
          <>
          {customs.some((f) => f.kind === 'vulnerabilities') ? <p className="mb-2 max-w-3xl text-[13px] text-muted">{t('custom.vulnNote')}</p> : null}
          <DataTable<Feed> caption={t('custom.caption')} data={customs} mobileRow={(f) => mobile(f, customActions(f))}
            columns={[
              { id: 'name', header: t('col.feed'), accessorKey: 'name', cell: ({ row }: R) => name(row.original) },
              common.on, common.schedule, common.last, common.records, common.status,
              { id: 'actions', header: t('col.actions'), enableSorting: false, cell: ({ row }: R) => <span className="flex flex-wrap gap-2">{customActions(row.original)}</span> },
            ]} />
          </>
        )}
      </Section>
      {builtin ? <BuiltinDialog key={builtin.id} feed={builtin} onClose={() => setBuiltin(null)} /> : null}
      {custom ? <CustomDialog key={typeof custom === 'string' ? 'new' : custom.id} feed={custom === 'new' ? null : custom} onClose={() => setCustom(null)} /> : null}
      {del ? <DeleteDialog feed={del} onClose={() => setDel(null)} /> : null}
    </>
  )
}
