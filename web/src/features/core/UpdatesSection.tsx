import { memo, useRef, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { toast } from 'sonner'
import { Download, RefreshCw, Upload } from 'lucide-react'
import { Link } from 'react-router'
import { PageHeader, Section } from '@/components/common/PageHeader'
import { DataTable, type ColumnDef } from '@/components/common/DataTable'
import { Chip } from '@/components/common/StatusChip'
import { QueryState } from '@/components/common/States'
import { Button } from '@/components/ui/button'
import { Dialog, DialogContent, DialogFooter } from '@/components/ui/dialog'
import { Segmented } from '@/components/ui/segmented'
import { download } from '@/lib/api'
import { fmtDate, fmtDateTime, fmtRelative } from '@/lib/format'
import { useOsState, useUpdateMutations, useUpdates } from './api'
import { OsBlock } from './OsUpdates'
import { Band, errMsg, ReadOnlyNote, useGate } from './parts'
import { MAX_UPLOAD, sha256Hex, toBase64 } from './util'
import type { ManagedPackage, UpdateAvailable, UpdateComponent, UpdateHistory, UpdatesState } from './types'

/** memo: the page title also reads the OS query; without it every OS refresh re-renders this body and the table cells remount under the user's click. */
const Body = memo(function Body({ s }: { s: UpdatesState }) {
  const { t } = useTranslation('core')
  const admin = useGate('admin')
  const operator = useGate('operator')
  const m = useUpdateMutations()
  const [rollback, setRollback] = useState<UpdateComponent | null>(null)
  const file = useRef<HTMLInputElement>(null)
  const comp = (id: string) => t(`updates.comp.${id}`, { defaultValue: id })
  const availableOf = (id: string): UpdateAvailable | undefined => s.available.find((a) => a.component === id)

  async function check() {
    try {
      const r = await m.check.mutateAsync()
      toast.success(r.applied ? t('updates.checkedApplied', { count: r.applied }) : r.available.length ? t('updates.checkedNew', { count: r.available.length }) : t('updates.checkedNone'))
    } catch (e) { toast.error(errMsg(e, t)) }
  }
  async function apply(id: string) {
    try { await m.apply.mutateAsync(id); toast.success(t(id === 'software' ? 'updates.appliedSoftware' : 'updates.applied', { name: comp(id) })) } catch (e) { toast.error(errMsg(e, t)) }
  }
  async function doRollback(c: UpdateComponent) {
    try { await m.rollback.mutateAsync(c.id); toast.success(t('updates.rolledBack', { name: comp(c.id) })) } catch (e) { toast.error(errMsg(e, t)) }
    setRollback(null)
  }
  async function importBundle(f: File | undefined) {
    if (!f) return
    if (f.size > MAX_UPLOAD) { toast.error(t('updates.bundle.tooLarge')); return }
    try {
      const buf = await f.arrayBuffer()
      const r = await m.importBundle.mutateAsync({ name: f.name, size: f.size, sha256: await sha256Hex(buf), content: toBase64(new TextDecoder().decode(buf)) })
      toast.success(t('updates.bundle.done', { count: r.applied }))
    } catch (e) { toast.error(errMsg(e, t)) }
    if (file.current) file.current.value = ''
  }

  const columns: ColumnDef<UpdateComponent>[] = [
    { id: 'name', header: t('updates.col.component'), accessorFn: (c) => comp(c.id), cell: ({ row }) => <div className="grid"><span className="font-medium">{comp(row.original.id)}</span><span className="text-[12px] text-muted">{t(`updates.kind.${row.original.kind}`)}</span></div> },
    { id: 'version', header: t('updates.col.version'), accessorFn: (c) => c.version, cell: ({ row }) => <div className="grid"><span className="font-mono text-[12.5px]">{row.original.version}</span><span className="text-[12px] text-muted">{fmtDateTime(row.original.installed_at)}</span></div> },
    { id: 'sig', header: t('updates.col.signature'), accessorFn: (c) => c.signature, cell: ({ row }) => (row.original.signature === 'valid' ? <Chip tone="ok">{t('updates.sig.valid')}</Chip> : <Chip tone="danger">{t(`updates.sig.${row.original.signature}`)}</Chip>) },
    { id: 'available', header: t('updates.col.available'), enableSorting: false, accessorFn: (c) => availableOf(c.id)?.version ?? '', cell: ({ row }) => {
      const a = availableOf(row.original.id)
      if (!a) return <span className="text-muted">{t('updates.latest')}</span>
      return (
        <div className="flex flex-wrap items-center gap-2">
          <div className="grid"><span className="font-mono text-[12.5px]">{a.version}</span><span className="max-w-xs text-[12px] text-muted">{a.note}</span></div>
          <Button size="sm" variant="primary" disabled={admin.disabled || m.apply.isPending} title={admin.title} onClick={() => void apply(a.component)}>{t('updates.apply')} <span className="sr-only">{comp(a.component)}</span></Button>
        </div>
      )
    } },
    { id: 'rollback', header: t('updates.col.rollback'), enableSorting: false, accessorFn: () => '', cell: ({ row }) => (row.original.previous
      ? <Button size="sm" disabled={admin.disabled} title={admin.title} onClick={() => setRollback(row.original)}>{t('updates.rollbackTo', { version: row.original.previous })} <span className="sr-only">{comp(row.original.id)}</span></Button>
      : <span className="text-muted">{t('updates.noPrevious')}</span>) },
  ]
  const hist: ColumnDef<UpdateHistory>[] = [
    { id: 'ts', header: t('updates.hist.time'), accessorFn: (h) => h.ts, cell: ({ row }) => <span className="whitespace-nowrap">{fmtDateTime(row.original.ts)}</span> },
    { id: 'c', header: t('updates.col.component'), accessorFn: (h) => comp(h.component) },
    { id: 'act', header: t('updates.hist.action'), accessorFn: (h) => h.action, cell: ({ row }) => t(`updates.act.${row.original.action}`) },
    { id: 'ver', header: t('updates.hist.change'), accessorFn: (h) => h.to, cell: ({ row }) => <span className="font-mono text-[12.5px]">{row.original.from ?? '–'} {'>'} {row.original.to}</span> },
    { id: 'u', header: t('updates.hist.by'), accessorFn: (h) => h.user, cell: ({ row }) => (row.original.user === 'system' ? t('updates.hist.system') : row.original.user) },
  ]
  const managedCols: ColumnDef<ManagedPackage>[] = [
    { id: 'name', header: t('updates.managed.col.package'), accessorFn: (p) => p.name, cell: ({ row }) => <span className="font-medium">{row.original.name}</span> },
    { id: 'version', header: t('updates.managed.col.version'), accessorFn: (p) => p.version, cell: ({ row }) => <span className="font-mono text-[12.5px]">{row.original.version}</span> },
    { id: 'status', header: t('updates.managed.col.status'), accessorFn: (p) => p.status, cell: ({ row }) => (row.original.status === 'ok' ? <Chip tone="ok">{t('updates.managed.pinned')}</Chip> : <Chip tone="warn">{t('updates.managed.pending')}</Chip>) },
    { id: 'how', header: t('updates.managed.col.how'), enableSorting: false, accessorFn: () => '', cell: () => <span className="text-[13px] text-muted">{t('updates.managed.how')}</span> },
  ]
  const affected = s.advisories.filter((a) => a.status === 'affected')

  return (
    <>
      <section id="managed" aria-labelledby="managed-band" className="mt-12">
        <Band id="managed-band" n="2" title={t('updates.managed.title')} desc={t('updates.managed.desc')} />
        <DataTable data={s.managed} columns={managedCols} caption={t('updates.managed.title')} pageSize={20}
          mobileRow={(p) => <div className="flex flex-wrap items-center justify-between gap-2"><div className="grid"><span className="font-medium">{p.name}</span><span className="font-mono text-[12px] text-muted">{p.version}</span></div>{p.status === 'ok' ? <Chip tone="ok">{t('updates.managed.pinned')}</Chip> : <Chip tone="warn">{t('updates.managed.pending')}</Chip>}</div>} />
      </section>

      <section id="vedette" aria-labelledby="vedette-band" className="mt-12">
        <Band id="vedette-band" n="3" title={t('updates.vedette.title')} desc={t('updates.vedette.desc')} />
      {affected.length ? (
        <div role="alert" className="mb-6 rounded-md border border-danger/40 bg-danger-soft px-4 py-3 text-sm">
          <p className="font-medium text-danger">{t('updates.advisoryBanner', { count: affected.length })}</p>
          <p className="mt-1">{t('updates.advisoryFix', { id: affected[0]?.id, version: affected[0]?.fixed_in })}</p>
        </div>
      ) : null}

      <Section title={t('updates.settings')} actions={<Button onClick={() => void check()} disabled={operator.disabled || m.check.isPending} title={operator.title}><RefreshCw />{t('updates.check')}</Button>}>
        <fieldset disabled={!admin.ok} title={admin.title} className="m-0 grid min-w-0 gap-4 border-0 p-0 sm:grid-cols-2">
          <div className="grid gap-1.5">
            <span className="text-sm font-medium">{t('updates.channel')}</span>
            <Segmented label={t('updates.channel')} value={s.channel} onChange={(v) => admin.ok && void m.settings.mutateAsync({ channel: v }).catch((e) => toast.error(errMsg(e, t)))} options={[{ value: 'stable', label: t('updates.stable') }, { value: 'beta', label: t('updates.beta') }]} />
            <p className="text-[13px] text-muted">{t(`updates.channelHint.${s.channel}`)}</p>
          </div>
          <div className="grid gap-1.5">
            <span className="text-sm font-medium">{t('updates.mode')}</span>
            <Segmented label={t('updates.mode')} value={s.mode} onChange={(v) => admin.ok && void m.settings.mutateAsync({ mode: v }).catch((e) => toast.error(errMsg(e, t)))} options={[{ value: 'manual', label: t('updates.manual') }, { value: 'auto', label: t('updates.auto') }]} />
            <p className="text-[13px] text-muted">{t(`updates.modeHint.${s.mode}`)}</p>
          </div>
        </fieldset>
        <p className="mt-3 text-[13px] text-muted">{t('updates.lastCheck', { time: fmtRelative(s.last_check) })} {s.check_enabled ? '' : t('updates.checkOff')}</p>
      </Section>

      <Section title={t('updates.sources.title')}>
        <p className="max-w-3xl text-sm">{t('updates.sources.body')} <Link className="text-accent underline-offset-4 hover:underline" to="/settings/feeds">{t('updates.sources.link')}</Link></p>
      </Section>

      <Section title={t('updates.components')} description={t('updates.componentsDesc')}>
        <DataTable data={s.components} columns={columns} caption={t('updates.components')} pageSize={20}
          mobileRow={(c) => {
            const a = availableOf(c.id)
            return (
              <div className="grid gap-1.5">
                <div className="flex flex-wrap items-center justify-between gap-2"><span className="font-medium">{comp(c.id)}</span>{c.signature === 'valid' ? <Chip tone="ok">{t('updates.sig.valid')}</Chip> : <Chip tone="danger">{t(`updates.sig.${c.signature}`)}</Chip>}</div>
                <span className="font-mono text-[12.5px]">{c.version} <span className="font-sans text-[12px] text-muted">{fmtDateTime(c.installed_at)}</span></span>
                {a ? <div className="flex flex-wrap items-center gap-2"><span className="text-[13px]">{t('updates.col.available')}: <span className="font-mono">{a.version}</span></span><Button size="sm" variant="primary" disabled={admin.disabled || m.apply.isPending} title={admin.title} onClick={() => void apply(a.component)}>{t('updates.apply')} <span className="sr-only">{comp(a.component)}</span></Button></div> : <span className="text-[13px] text-muted">{t('updates.latest')}</span>}
                {c.previous ? <div><Button size="sm" disabled={admin.disabled} title={admin.title} onClick={() => setRollback(c)}>{t('updates.rollbackTo', { version: c.previous })} <span className="sr-only">{comp(c.id)}</span></Button></div> : null}
              </div>
            )
          }} />
      </Section>

      <Section title={t('updates.advisories')} description={t('updates.advisoriesDesc')}>
        <ul className="grid gap-2">
          {s.advisories.map((a) => (
            <li key={a.id} className="rounded-md border border-rule bg-surface px-4 py-3 text-sm">
              <div className="flex flex-wrap items-center gap-2">
                <span className="font-medium">{a.title}</span>
                {a.status === 'affected' ? <Chip tone="danger">{t('updates.advisoryAffected')}</Chip> : <Chip tone="ok">{t('updates.advisoryFixed')}</Chip>}
              </div>
              <p className="mt-1 text-[13px] text-muted">{a.id}, {fmtDate(a.published)}. {t('updates.fixedIn', { version: a.fixed_in })}</p>
              <p className="mt-1">{a.summary}</p>
            </li>
          ))}
        </ul>
      </Section>

      <Section title={t('updates.bundle.title')} description={t('updates.bundle.desc')}>
        <div className="flex flex-wrap items-center gap-2">
          <Button disabled={operator.disabled} title={operator.title} onClick={() => void download('/core/updates/bundle', 'vedette-bundle.json').catch((e) => toast.error(errMsg(e, t)))}><Download />{t('updates.bundle.export')}</Button>
          <input ref={file} type="file" hidden tabIndex={-1} aria-label={t('updates.bundle.file')} accept=".json,application/json" onChange={(e) => void importBundle(e.target.files?.[0])} />
          <Button disabled={admin.disabled || m.importBundle.isPending} title={admin.title} onClick={() => file.current?.click()}><Upload />{t('updates.bundle.import')}</Button>
        </div>
      </Section>

      <Section title={t('updates.history')} description={t('updates.historyDesc')}>
        <DataTable data={s.history} columns={hist} caption={t('updates.history')} pageSize={20} empty={t('updates.historyEmpty')}
          mobileRow={(h) => <div className="grid gap-0.5"><span className="font-medium">{comp(h.component)}, {t(`updates.act.${h.action}`)}</span><span className="font-mono text-[12px] [overflow-wrap:anywhere]">{h.from ?? '–'} {'>'} {h.to}</span><span className="text-[12px] text-muted">{fmtDateTime(h.ts)}, {h.user === 'system' ? t('updates.hist.system') : h.user}</span></div>} />
      </Section>

      <Dialog open={!!rollback} onOpenChange={(o) => !o && setRollback(null)}>
        <DialogContent title={t('updates.rollbackAsk.title', { name: rollback ? comp(rollback.id) : '' })} description={rollback ? t('updates.rollbackAsk.body', { from: rollback.version, to: rollback.previous ?? '' }) : undefined}>
          <p className="text-sm text-muted">{t('updates.rollbackAsk.manual')}</p>
          <DialogFooter><Button onClick={() => setRollback(null)}>{t('common:cancel')}</Button><Button variant="danger" disabled={m.rollback.isPending} onClick={() => rollback && void doRollback(rollback)}>{t('updates.rollbackAsk.confirm')}</Button></DialogFooter>
        </DialogContent>
      </Dialog>
      </section>
    </>
  )
})

export default function UpdatesSection() {
  const { t } = useTranslation('core')
  const q = useUpdates()
  const os = useOsState()
  const sec = os.data?.pending.filter((p) => p.security).length ?? 0
  const title = !os.data ? t('settings.updates') : sec ? t('updates.titleOs', { name: os.data.os.name, count: sec }) : t('updates.titleOsClean', { name: os.data.os.name })
  return (
    <>
      <PageHeader title={title} meta={t('updates.meta')} stories={['S-CORE-2', 'S-CORE-7']} />
      <ReadOnlyNote role="admin" />
      <OsBlock />
      {/* The software part has its own query: when it fails or is not built yet (501), the operating system part above still shows (issue #230). */}
      <QueryState query={q}>{(s) => <Body s={s} />}</QueryState>
    </>
  )
}
