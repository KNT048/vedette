import { memo, useEffect, useRef, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { toast } from 'sonner'
import { Download, RefreshCw, Upload } from 'lucide-react'
import { Link } from 'react-router'
import { PageHeader, Section } from '@/components/common/PageHeader'
import { DataTable, type ColumnDef } from '@/components/common/DataTable'
import { Chip } from '@/components/common/StatusChip'
import { QueryState } from '@/components/common/States'
import { Button } from '@/components/ui/button'
import { Checkbox } from '@/components/ui/checkbox'
import { Dialog, DialogContent, DialogFooter } from '@/components/ui/dialog'
import { Segmented } from '@/components/ui/segmented'
import { download } from '@/lib/api'
import { fmtDate, fmtDateTime, fmtRelative } from '@/lib/format'
import { useOsState, useUpdateMutations, useUpdates } from './api'
import { OsBlock } from './OsUpdates'
import { Band, errMsg, ReadOnlyNote, useGate } from './parts'
import { MAX_UPLOAD, sha256Hex, toBase64 } from './util'
import type { ManagedPackage, UpdateAvailable, UpdateComponent, UpdateHistory, UpdateRun, UpdatesState } from './types'

/** The software install or rollback (D-340): its step while it runs, its end in words, and one toast when a run this page saw running ends. */
function RunPanel({ run, name, reconnecting }: { run: UpdateRun; name: string; reconnecting: boolean }) {
  const { t } = useTranslation('core')
  const seen = useRef<string | null>(null)
  useEffect(() => {
    if (run.status === 'running') { seen.current = `${run.id}:running`; return }
    if (seen.current === `${run.id}:running`) {
      if (run.status === 'done') toast.success(t(run.action === 'update' ? 'updates.appliedSoftware' : 'updates.rolledBack', { name }))
      else toast.error(run.error ?? t(`updates.run.${run.status}Toast`))
    }
    seen.current = `${run.id}:end`
  }, [run.id, run.status, run.action, run.error, name, t])
  const steps = run.action === 'update' ? (['download', 'start', 'restart'] as const) : (['start', 'restart'] as const)
  const at = run.step ? steps.indexOf(run.step as never) : -1
  const tone = run.status === 'running' ? 'accent' : run.status === 'done' ? 'ok' : 'danger'
  return (
    <div className="mb-6 grid gap-3 rounded-md border border-rule bg-surface px-4 py-3" aria-live="polite">
      <div className="flex flex-wrap items-center gap-2">
        <h3 className="text-sm font-semibold">{t(`updates.run.title.${run.action}`, { name, version: run.to })}</h3>
        <Chip tone={tone}>{t(`updates.run.status.${run.status}`)}</Chip>
        <span className="text-[13px] text-muted">{fmtDateTime(run.started_at)}, {run.user === 'system' ? t('updates.hist.system') : run.user}</span>
      </div>
      {run.status === 'running' ? (
        <ol className="grid gap-1 text-sm">
          {steps.map((st, i) => (
            <li key={st} className={i === at ? 'font-medium' : 'text-muted'} aria-current={i === at ? 'step' : undefined}>
              {t('updates.run.stepOf', { n: i + 1, total: steps.length })} {t(`updates.run.step.${st}`)}{i < at ? ` ${t('updates.run.stepDone')}` : ''}
            </li>
          ))}
        </ol>
      ) : null}
      {run.status === 'running' && run.step === 'restart' ? <p className="text-[13px] text-muted">{t('updates.run.restartNote')}</p> : null}
      {reconnecting ? <p role="status" className="text-[13px] text-muted">{t('updates.run.reconnecting')}</p> : null}
      {run.status === 'failed' || run.status === 'reverted' ? <p role="alert" className="text-sm text-danger">{run.error ?? t(`updates.run.${run.status}Toast`)}</p> : null}
    </div>
  )
}

/** memo: the page title also reads the OS query; without it every OS refresh re-renders this body and the table cells remount under the user's click. */
const Body = memo(function Body({ s, reconnecting = false }: { s: UpdatesState; reconnecting?: boolean }) {
  const { t } = useTranslation('core')
  const admin = useGate('admin')
  const operator = useGate('operator')
  const m = useUpdateMutations()
  const [rollback, setRollback] = useState<UpdateComponent | null>(null)
  const [dataLossOk, setDataLossOk] = useState(false)
  const running = s.run?.status === 'running'
  const askRollback = (c: UpdateComponent) => { setDataLossOk(false); setRollback(c) }
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
    try {
      await m.apply.mutateAsync(id)
      if (id !== 'software') toast.success(t('updates.applied', { name: comp(id) })) // the software reports at the end of its run (RunPanel)
    } catch (e) { toast.error(errMsg(e, t)) }
  }
  async function doRollback(c: UpdateComponent) {
    try {
      await m.rollback.mutateAsync(c.rollback_restores_data ? { component: c.id, confirm_data_loss: true } : { component: c.id })
      if (c.id !== 'software') toast.success(t('updates.rolledBack', { name: comp(c.id) }))
    } catch (e) { toast.error(errMsg(e, t)) }
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
          <Button size="sm" variant="primary" disabled={admin.disabled || m.apply.isPending || running} title={admin.title} onClick={() => void apply(a.component)}>{t('updates.apply')} <span className="sr-only">{comp(a.component)}</span></Button>
        </div>
      )
    } },
    { id: 'rollback', header: t('updates.col.rollback'), enableSorting: false, accessorFn: () => '', cell: ({ row }) => (row.original.previous
      ? <Button size="sm" disabled={admin.disabled || running} title={admin.title} onClick={() => askRollback(row.original)}>{t('updates.rollbackTo', { version: row.original.previous })} <span className="sr-only">{comp(row.original.id)}</span></Button>
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
      {s.run ? <RunPanel run={s.run} name={comp(s.run.component)} reconnecting={reconnecting} /> : null}
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
                {a ? <div className="flex flex-wrap items-center gap-2"><span className="text-[13px]">{t('updates.col.available')}: <span className="font-mono">{a.version}</span></span><Button size="sm" variant="primary" disabled={admin.disabled || m.apply.isPending || running} title={admin.title} onClick={() => void apply(a.component)}>{t('updates.apply')} <span className="sr-only">{comp(a.component)}</span></Button></div> : <span className="text-[13px] text-muted">{t('updates.latest')}</span>}
                {c.previous ? <div><Button size="sm" disabled={admin.disabled || running} title={admin.title} onClick={() => askRollback(c)}>{t('updates.rollbackTo', { version: c.previous })} <span className="sr-only">{comp(c.id)}</span></Button></div> : null}
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
          {rollback?.rollback_restores_data ? (
            <div className="grid gap-2 rounded-md border border-danger/40 bg-danger-soft px-3 py-2 text-sm">
              <p className="font-medium text-danger">{t('updates.rollbackAsk.dataLoss')}</p>
              <p>{t('updates.rollbackAsk.dataLossWhy')}</p>
              <label className="flex items-start gap-2"><Checkbox checked={dataLossOk} onCheckedChange={(v) => setDataLossOk(v === true)} className="mt-0.5" />{t('updates.rollbackAsk.dataLossOk')}</label>
            </div>
          ) : null}
          <p className="text-sm text-muted">{t('updates.rollbackAsk.manual')}</p>
          <DialogFooter><Button onClick={() => setRollback(null)}>{t('common:cancel')}</Button><Button variant="danger" disabled={m.rollback.isPending || (!!rollback?.rollback_restores_data && !dataLossOk)} onClick={() => rollback && void doRollback(rollback)}>{t('updates.rollbackAsk.confirm')}</Button></DialogFooter>
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
      {/* While the software updates, Vedette restarts and a read fails for a moment: keep the page and say it reconnects (D-340). */}
      {/* One branch for every answer with data, so the run panel is not remounted when the run ends (its toast would be lost). */}
      {q.data && (!q.error || q.data.run?.status === 'running') ? <Body s={q.data} reconnecting={!!q.error} /> : <QueryState query={q}>{(s) => <Body s={s} />}</QueryState>}
    </>
  )
}
