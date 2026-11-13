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
import { ApiError, download } from '@/lib/api'
import { fmtDate, fmtDateTime, fmtRelative, isNever } from '@/lib/format'
import { useOsState, useUpdateMutations, useUpdates } from './api'
import { OsBlock } from './OsUpdates'
import { ContainerUpdates, InstallPending } from './ContainerOnly'
import { UpdateNotices } from './UpdateSignals'
import { useInstallKind } from '@/lib/modules'
import { BUNDLE_IN_UI } from '@/lib/bundle'
import { Band, errMsg, ReadOnlyNote, useGate } from './parts'
import { MAX_UPLOAD, sha256Hex, toBase64 } from './util'
import type { ManagedPackage, UpdateAvailable, UpdateComponent, UpdateHistory, UpdateRun, UpdatesState } from './types'

/**
 * The software install or rollback (D-340): its steps while it runs, its end in words, and one toast (with Reload: the page now runs the old code) when a run this page saw running ends.
 * `after`: the run on screen when this page last pressed Apply on the software; a different run is one Apply started, announced even when it ended at once (D-316 (h), host_too_old).
 */
function RunPanel({ run, name, reconnecting, after }: { run: UpdateRun; name: string; reconnecting: boolean; after?: string | null }) {
  const { t } = useTranslation('core')
  const seen = useRef<string | null>(null)
  // The run this page watched while it ran: only its end is announced and offers Reload (an old end is not news).
  const [watched, setWatched] = useState<string | null>(null)
  const started = after !== undefined && run.id !== after
  if ((run.status === 'running' || started) && watched !== run.id) setWatched(run.id)
  const sawEnd = watched === run.id && run.status !== 'running'
  useEffect(() => {
    if (run.status === 'running') { seen.current = `${run.id}:running`; return }
    if (seen.current === `${run.id}:end`) return
    if (seen.current === `${run.id}:running` || started) {
      const reload = { action: { label: t('updates.run.reload'), onClick: () => window.location.reload() } }
      if (run.status === 'done') toast.success(t(run.action === 'update' ? 'updates.appliedSoftware' : 'updates.rolledBack', { name }), reload)
      else if (run.status === 'reverted') toast.error(run.error ?? t(`updates.run.revertedToast.${run.action}`, { from: run.from ?? '' }))
      else toast.error(run.error ?? t(`updates.run.failedToast.${run.action}`))
    }
    seen.current = `${run.id}:end`
  }, [run.id, run.status, run.action, run.error, run.from, name, t, started])
  const at = run.step ? run.steps.indexOf(run.step) : -1
  const tone = run.status === 'running' ? 'accent' : run.status === 'done' ? 'ok' : 'danger'
  const why = run.status === 'failed' || run.status === 'reverted' ? (run.error ?? t(`updates.run.${run.status}Toast.${run.action}`, { from: run.from ?? '' })) : null
  return (
    <div className="mb-6 grid gap-3 rounded-md border border-rule bg-surface px-4 py-3">
      <div className="flex flex-wrap items-center gap-2">
        <h3 className="text-sm font-semibold">{t(`updates.run.title.${run.action}.${run.status}`, { name, version: run.to, from: run.from ?? '' })}</h3>
        <Chip tone={tone}>{t(`updates.run.status.${run.status}`)}</Chip>
        <span className="text-[13px] text-muted">{fmtDateTime(run.started_at)}, {run.user === 'system' ? t('updates.hist.system') : run.user}</span>
      </div>
      {run.status === 'running' ? (
        <div className="grid gap-3" aria-live="polite">
          <ol className="grid gap-1 text-sm">
            {run.steps.map((st, i) => (
              <li key={st} className={i === at ? 'font-medium' : 'text-muted'} aria-current={i === at ? 'step' : undefined}>
                {t('updates.run.stepOf', { n: i + 1, total: run.steps.length })} {t(`updates.run.step.${st}`)}{i < at ? ` ${t('updates.run.stepDone')}` : ''}
              </li>
            ))}
          </ol>
          {run.step === 'restart' ? <p className="text-[13px] text-muted">{t('updates.run.restartNote')}</p> : null}
          {run.step === 'host' ? <p className="text-[13px] text-muted">{t('updates.run.hostNote')}</p> : null}
        </div>
      ) : null}
      {reconnecting ? <p role="status" className="text-[13px] text-muted">{t('updates.run.reconnecting')}</p> : null}
      {run.status === 'done' && sawEnd ? <div><Button size="sm" onClick={() => window.location.reload()}>{t('updates.run.reload')}</Button> <span className="text-[13px] text-muted">{t('updates.run.reloadWhy')}</span></div> : null}
      {why ? <p role={sawEnd ? 'alert' : undefined} className="text-sm text-danger">{why}</p> : null}
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
  const [after, setAfter] = useState<string | null | undefined>(undefined) // see RunPanel; undefined until Apply
  const running = s.run?.status === 'running' // only the software waits for its run; data and packs still update
  const askRollback = (c: UpdateComponent) => { setDataLossOk(false); setRollback(c) }
  const file = useRef<HTMLInputElement>(null)
  const comp = (id: string) => t(`updates.comp.${id}`, { defaultValue: id })
  const availableOf = (id: string): UpdateAvailable | undefined => s.available.find((a) => a.component === id)
  // The system helper (D-316) has no Apply of its own: the software release brings it, and the software run updates it first.
  const hostNext = availableOf('software')?.host_version
  const includesHost = (a: UpdateAvailable) => (a.host_version ? <span className="max-w-xs text-[12px] text-muted">{t('updates.host.includes', { version: a.host_version })}</span> : null)

  async function check() {
    try {
      const r = await m.check.mutateAsync()
      toast.success(r.applied ? t('updates.checkedApplied', { count: r.applied }) : r.available.length ? t('updates.checkedNew', { count: r.available.length }) : t('updates.checkedNone'))
    } catch (e) { toast.error(errMsg(e, t)) }
  }
  async function apply(id: string) {
    if (id === 'software') setAfter(s.run?.id ?? null)
    try {
      await m.apply.mutateAsync(id)
      if (id !== 'software') toast.success(t('updates.applied', { name: comp(id) })) // the software reports at the end of its run (RunPanel)
    } catch (e) { toast.error(errMsg(e, t)) }
    // not reset: the new run reaches the page after this returns (react-query notifies later); a refused Apply leaves the same run on screen
  }
  async function doRollback(c: UpdateComponent) {
    try {
      await m.rollback.mutateAsync(c.rollback_restores_data ? { component: c.id, confirm_data_loss: true } : { component: c.id })
      if (c.id !== 'software') toast.success(t('updates.rolledBack', { name: comp(c.id) }))
    } catch (e) {
      toast.error(errMsg(e, t))
      if (e instanceof ApiError && e.code === 'confirm_required') { // the release changed since the dialog opened: ask again with the warning
        const fresh = (await m.refresh()).components.find((x) => x.id === c.id)
        if (fresh) { askRollback(fresh); return }
      }
    }
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

  // A build made from source (0.0.0-dev, no release signature) is not a failure: neutral label, not the red "Unsigned".
  const sigChip = (c: UpdateComponent) => (c.signature === 'valid' ? <Chip tone="ok">{t('updates.sig.valid')}</Chip>
    : c.signature === 'unsigned' && c.version.endsWith('-dev') ? <Chip tone="off">{t('updates.sig.dev')}</Chip>
    : <Chip tone="danger">{t(`updates.sig.${c.signature}`)}</Chip>)

  const columns: ColumnDef<UpdateComponent>[] = [
    { id: 'name', header: t('updates.col.component'), accessorFn: (c) => comp(c.id), cell: ({ row }) => <div className="grid"><span className="font-medium">{comp(row.original.id)}</span>{row.original.id === 'host' ? <span className="max-w-xs text-[12px] text-muted">{t('updates.host.how')}</span> : <span className="text-[12px] text-muted">{t(`updates.kind.${row.original.kind}`)}</span>}</div> },
    { id: 'version', header: t('updates.col.version'), accessorFn: (c) => c.version, cell: ({ row }) => <div className="grid"><span className="font-mono text-[12.5px]">{row.original.version}</span><span className="text-[12px] text-muted">{fmtDateTime(row.original.installed_at)}</span></div> },
    { id: 'sig', header: t('updates.col.signature'), accessorFn: (c) => c.signature, cell: ({ row }) => sigChip(row.original) },
    { id: 'available', header: t('updates.col.available'), enableSorting: false, accessorFn: (c) => availableOf(c.id)?.version ?? '', cell: ({ row }) => {
      if (row.original.id === 'host') return hostNext ? <span className="font-mono text-[12.5px]">{hostNext}</span> : <span className="text-muted">{t('updates.latest')}</span>
      const a = availableOf(row.original.id)
      if (!a) return <span className="text-muted">{t('updates.latest')}</span>
      return (
        <div className="flex flex-wrap items-center gap-2">
          <div className="grid"><span className="font-mono text-[12.5px]">{a.version}</span><span className="max-w-xs text-[12px] text-muted">{a.note}</span>{includesHost(a)}</div>
          <Button size="sm" variant="primary" disabled={admin.disabled || m.apply.isPending || (running && a.component === 'software')} title={admin.title} onClick={() => void apply(a.component)}>{t('updates.apply')} <span className="sr-only">{comp(a.component)}</span></Button>
        </div>
      )
    } },
    { id: 'rollback', header: t('updates.col.rollback'), enableSorting: false, accessorFn: () => '', cell: ({ row }) => (row.original.id === 'host' ? <span className="text-muted">–</span> : row.original.previous
      ? <Button size="sm" disabled={admin.disabled || (running && row.original.id === 'software')} title={admin.title} onClick={() => askRollback(row.original)}>{t('updates.rollbackTo', { version: row.original.previous })} <span className="sr-only">{comp(row.original.id)}</span></Button>
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
        {/* No empty table (D-407): the list comes from the running release's signed manifest, which a build without a release never gets. */}
        {s.managed.length ? (
          <DataTable data={s.managed} columns={managedCols} caption={t('updates.managed.title')} pageSize={20}
            mobileRow={(p) => <div className="flex flex-wrap items-center justify-between gap-2"><div className="grid"><span className="font-medium">{p.name}</span><span className="font-mono text-[12px] text-muted">{p.version}</span></div>{p.status === 'ok' ? <Chip tone="ok">{t('updates.managed.pinned')}</Chip> : <Chip tone="warn">{t('updates.managed.pending')}</Chip>}</div>} />
        ) : <p className="max-w-3xl text-sm text-muted">{t('updates.managed.none')}</p>}
      </section>

      <section id="vedette" aria-labelledby="vedette-band" className="mt-12">
        <Band id="vedette-band" n="3" title={t('updates.vedette.title')} desc={t('updates.vedette.desc')} />
      {s.run ? <RunPanel run={s.run} name={comp(s.run.component)} reconnecting={reconnecting} after={after} /> : null}
      <UpdateNotices s={s} />
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
        {/* One status line (D-407): a failed check says why, then the last good one if any; never "Never checked." above a failure. */}
        <p className={`mt-3 text-[13px] ${s.last_check_error && s.last_check_error.code !== 'update_not_published' ? 'text-warn' : 'text-muted'}`}>
          {s.last_check_error ? t('updates.checkFailed', { time: fmtRelative(s.last_check_error.at), reason: s.last_check_error.message }) : isNever(s.last_check) ? t('updates.neverChecked') : t('updates.lastCheck', { time: fmtRelative(s.last_check) })}
          {s.last_check_error && !isNever(s.last_check) ? ` ${t('updates.lastGood', { time: fmtRelative(s.last_check) })}` : ''} {s.check_enabled ? '' : t('updates.checkOff')}
        </p>
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
                <div className="flex flex-wrap items-center justify-between gap-2"><span className="font-medium">{comp(c.id)}</span>{sigChip(c)}</div>
                {c.id === 'host' ? <span className="text-[12px] text-muted">{t('updates.host.how')}</span> : null}
                <span className="font-mono text-[12.5px]">{c.version} <span className="font-sans text-[12px] text-muted">{fmtDateTime(c.installed_at)}</span></span>
                {c.id === 'host' ? (hostNext ? <span className="text-[13px]">{t('updates.col.available')}: <span className="font-mono">{hostNext}</span></span> : <span className="text-[13px] text-muted">{t('updates.latest')}</span>)
                : a ? <div className="flex flex-wrap items-center gap-2"><span className="text-[13px]">{t('updates.col.available')}: <span className="font-mono">{a.version}</span></span><Button size="sm" variant="primary" disabled={admin.disabled || m.apply.isPending || (running && a.component === 'software')} title={admin.title} onClick={() => void apply(a.component)}>{t('updates.apply')} <span className="sr-only">{comp(a.component)}</span></Button></div> : <span className="text-[13px] text-muted">{t('updates.latest')}</span>}
                {a ? includesHost(a) : null}
                {c.previous ? <div><Button size="sm" disabled={admin.disabled || (running && c.id === 'software')} title={admin.title} onClick={() => askRollback(c)}>{t('updates.rollbackTo', { version: c.previous })} <span className="sr-only">{comp(c.id)}</span></Button></div> : null}
              </div>
            )
          }} />
      </Section>

      <Section title={t('updates.advisories')} description={t('updates.advisoriesDesc')}>
        {s.advisories.length ? (
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
        ) : <p className="max-w-3xl text-sm text-muted">{t(isNever(s.last_check) ? 'updates.advisoriesNotYet' : s.stale_since ? 'updates.advisoriesStale' : 'updates.advisoriesNone')}</p>}
      </Section>

      {BUNDLE_IN_UI ? (
      <Section title={t('updates.bundle.title')} description={t('updates.bundle.desc')}>
        <div className="flex flex-wrap items-center gap-2">
          <Button disabled={operator.disabled} title={operator.title} onClick={() => void download('/core/updates/bundle', 'vedette-bundle.json').catch((e) => toast.error(errMsg(e, t)))}><Download />{t('updates.bundle.export')}</Button>
          <input ref={file} type="file" hidden tabIndex={-1} aria-label={t('updates.bundle.file')} accept=".json,application/json" onChange={(e) => void importBundle(e.target.files?.[0])} />
          <Button disabled={admin.disabled || m.importBundle.isPending || running} title={admin.title} onClick={() => file.current?.click()}><Upload />{t('updates.bundle.import')}</Button>
        </div>
      </Section>
      ) : null}

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
          <DialogFooter><Button onClick={() => setRollback(null)}>{t('common:cancel')}</Button><Button variant="danger" disabled={m.rollback.isPending || (running && rollback?.id === 'software') || (!!rollback?.rollback_restores_data && !dataLossOk)} onClick={() => rollback && void doRollback(rollback)}>{t('updates.rollbackAsk.confirm')}</Button></DialogFooter>
        </DialogContent>
      </Dialog>
      </section>
    </>
  )
})

export default function UpdatesSection() {
  const { t } = useTranslation('core')
  const install = useInstallKind()
  // D-381: a container-only install has no spare slot, rollback, channels or packages: the customer pulls the new images (S-CORE-9 G4).
  if (install === 'container') return (
    <>
      <PageHeader title={t('settings.updates')} meta={t('container.updates.meta')} stories={['S-CORE-2', 'S-CORE-9']} />
      <ContainerNotices />
      <ContainerUpdates />
    </>
  )
  return install ? <ApplianceUpdates /> : <><PageHeader title={t('settings.updates')} stories={['S-CORE-2', 'S-CORE-9']} /><InstallPending /></>
}

/** D-386 on a container-only install: the same notices, from the same read; nothing while it fails. */
function ContainerNotices() {
  const { data } = useUpdates()
  return data ? <UpdateNotices s={data} bundle={false} /> : null
}

function ApplianceUpdates() {
  const { t } = useTranslation('core')
  const q = useUpdates()
  const os = useOsState()
  const sec = os.data?.pending.filter((p) => p.security).length ?? 0
  const name = os.data?.os?.name // null before the box first looked for updates (D-407)
  const title = !name ? t('settings.updates') : sec ? t('updates.titleOs', { name, count: sec }) : t('updates.titleOsClean', { name })
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
