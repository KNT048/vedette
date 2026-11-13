import { useCallback, useMemo, useRef, useState } from 'react'
import { Link, useSearchParams } from 'react-router'
import { useTranslation } from 'react-i18next'
import { toast } from 'sonner'
import { Check, Circle, OctagonX, Play } from 'lucide-react'
import { Section, Panel } from '@/components/common/PageHeader'
import { DataTable, type ColumnDef } from '@/components/common/DataTable'
import { EmptyState, QueryState } from '@/components/common/States'
import { Chip } from '@/components/common/StatusChip'
import { Button } from '@/components/ui/button'
import { Checkbox } from '@/components/ui/checkbox'
import { Dialog, DialogContent } from '@/components/ui/dialog'
import { fmtDate, fmtDateTime, fmtRelative } from '@/lib/format'
import { useCan } from '@/lib/session'
import { isLive, useRuns, useScanConfig, useStartRun, useStopRun, useTargets } from './api'
import { errMsg } from './errors'
import { ResultChip, RunStatusChip } from './shared'
import type { RunIdentRow, RunResultRow, ScanConfigResponse, ScanRun, ScanTarget } from './types'

function Progress({ run }: { run: ScanRun }) {
  const { t } = useTranslation('scan')
  const can = useCan('operator')
  const stop = useStopRun()
  const stopping = run.status === 'stopping'
  const pct = run.total ? Math.round((run.done / run.total) * 100) : 0
  return (
    <section aria-labelledby="progress-title" className="mb-8 rounded-md border border-accent/40 bg-accent-soft/50 p-4">
      <h2 id="progress-title" className="text-base font-semibold">{stopping ? t('progress.stopping') : t('progress.running', { done: run.done, total: run.total })}</h2>
      <div role="progressbar" aria-label={t('progress.bar')} aria-valuemin={0} aria-valuemax={100} aria-valuenow={pct} className="my-3 h-2 overflow-hidden rounded-full bg-surface">
        <div className="h-full bg-accent transition-[width]" style={{ width: `${pct}%` }} />
      </div>
      <div className="flex flex-wrap items-center gap-x-4 gap-y-2">
        <p className="text-sm" role="status">{stopping ? t('progress.stoppingBody') : run.current ? t('progress.current', { label: run.current.label, ip: run.current.ip }) : ''}</p>
        <Button variant="danger" className="ml-auto" disabled={!can || stopping || stop.isPending} title={can ? undefined : t('common:needRole', { role: t('common:role.operator') })}
          onClick={() => stop.mutate(run.id, { onError: (e) => toast.error(errMsg(e)) })}>
          <OctagonX />{stopping ? t('progress.stoppingButton') : t('progress.stop')}
        </Button>
      </div>
      <p className="mt-2 text-[13px] text-muted">{t('progress.note')}</p>
    </section>
  )
}

function TargetRow({ t: target, checked, onChange }: { t: ScanTarget; checked: boolean; onChange: (v: boolean) => void }) {
  const { t } = useTranslation('scan')
  const id = `tg-${target.id}`
  return (
    <li className="flex flex-wrap items-center gap-x-3 gap-y-1 px-3 py-2">
      <Checkbox id={id} checked={checked} disabled={!target.selectable} onCheckedChange={(v) => onChange(v === true)} />
      <label htmlFor={id} className={target.selectable ? 'text-sm' : 'text-sm text-muted'}>
        <span className="font-medium">{target.label}</span>{target.ip && target.ip !== '—' ? <> <span className="text-muted">{target.ip}</span></> : null}
      </label>
      {target.findings > 0 ? <Chip tone="warn">{t('start.findings', { count: target.findings })}</Chip> : null}
      {target.fragile && target.selectable ? <Chip tone="off" title={t('start.fragileHint')}>{t('start.fragile')}</Chip> : null}
      {target.pick_only ? <span className="text-[13px] text-muted">{t(target.device_kind === 'unknown' ? 'start.pickUnknown' : target.fragile ? 'start.pickFragile' : 'start.pickManual')}</span> : null}
      {target.reason ? <span className="text-[13px] text-muted">{t(`reason.${target.reason}`)}</span> : null}
    </li>
  )
}

function Setup({ cfg, internal }: { cfg: ScanConfigResponse; internal: ScanTarget[] }) {
  const { t } = useTranslation('scan')
  const scopeOk = cfg.can_scan && cfg.scope.networks.length > 0
  const devOk = internal.some((x) => x.selectable)
  if (scopeOk && devOk) return null
  const steps = [
    { key: 'scope', ok: scopeOk, title: t('start.stepScope'), help: t('start.stepScopeHelp'), to: '/devices/setup', cta: t('start.openSetup') },
    { key: 'devices', ok: devOk, title: t('start.stepDevices'), help: internal.length ? t('start.stepDevicesNoneOk') : t('start.stepDevicesNone'), to: '/devices', cta: t('start.openDevices') },
  ]
  return (
    <section aria-labelledby="setup-title" className="rounded-md border border-dashed border-warn bg-warn-soft/60 p-4">
      <h3 id="setup-title" className="text-sm font-semibold">{t('start.setupTitle')}</h3>
      <p className="mt-1 max-w-3xl text-sm">{t('start.setupIntro')}</p>
      <ol className="mt-3 grid gap-3">
        {steps.map((s, i) => (
          <li key={s.key} className="flex items-start gap-3 text-sm">
            {s.ok ? <Check className="mt-0.5 size-4 shrink-0 text-ok" aria-hidden /> : <Circle className="mt-0.5 size-4 shrink-0 text-muted" aria-hidden />}
            <div className="grid gap-1">
              <span className="font-medium">{i + 1}. {s.title} <span className="sr-only">({s.ok ? t('start.stepDone') : t('start.stepTodo')})</span></span>
              {s.ok ? null : (
                <>
                  <span className="max-w-2xl text-[13px] text-muted">{s.help}</span>
                  <Link to={s.to} className="w-fit text-accent underline underline-offset-4">{s.cta}</Link>
                </>
              )}
            </div>
          </li>
        ))}
      </ol>
    </section>
  )
}

function StartPanel({ targets, cfg, live, engineBusy }: { targets: ScanTarget[]; cfg: ScanConfigResponse; live: boolean; engineBusy: boolean }) {
  const { t } = useTranslation('scan')
  const can = useCan('operator')
  const start = useStartRun()
  const [params] = useSearchParams()
  const bulk = targets.filter((x) => x.selectable && !x.pick_only)
  const [raw, setRaw] = useState<Set<string>>(() => {
    const want = params.get('target')
    // D-126 (2): only a person's own tick picks a fragile, unclassified or hand-declared device; the page never ticks one for them.
    const hit = want ? targets.find((x) => x.id === want && x.selectable && !x.pick_only) : undefined
    if (want) return new Set(hit ? [hit.id] : []) // came for one device: tick nothing else
    return new Set(bulk.filter((x) => x.findings > 0).map((x) => x.id))
  })
  const internal = targets.filter((x) => x.kind === 'internal')
  const external = targets.filter((x) => x.kind === 'external')
  // The ids the person ticked by hand: the only way a pick-only device gets in (D-126 (2)).
  const [picks, setPicks] = useState<Set<string>>(() => new Set())
  const flip = (s: Set<string>, id: string, v: boolean) => { const n = new Set(s); if (v) n.add(id); else n.delete(id); return n }
  const toggle = (id: string, v: boolean) => { setRaw((s) => flip(s, id, v)); setPicks((s) => flip(s, id, v)) }
  // Security review M1: whenever the list refreshes, a device that became pick-only leaves a selection it entered without a tick.
  const sel = useMemo(() => new Set([...raw].filter((id) => {
    const x = targets.find((y) => y.id === id)
    return !!x && x.selectable && (!x.pick_only || picks.has(id))
  })), [raw, picks, targets])
  const blocked = !cfg.can_scan ? cfg.block_reason : live ? t('start.busy') : engineBusy ? t('start.engineBusy') : !can ? t('common:needRole', { role: t('common:role.operator') }) : sel.size === 0 ? t('start.none') : null
  const c = cfg.config
  return (
    <div className="grid gap-4">
      <Setup cfg={cfg} internal={internal} />
      <Panel className="grid gap-1 p-4 text-sm">
        <p>{cfg.scope.networks.length ? t('start.scope', { networks: cfg.scope.networks.join(', ') }) : t('start.noNetworks')}</p>
        <p className={cfg.scope.commitment ? 'text-muted' : 'text-danger'}>
          {cfg.scope.commitment ? t('start.commitment', { date: fmtDate(cfg.scope.commitment.confirmed_at), by: cfg.scope.commitment.by }) : t('start.noCommitment')}
        </p>
        <p className="text-[13px] text-muted">{t('start.asIs')}</p>
        <p className="text-muted">{t('start.manualNote', { from: c.window.from, to: c.window.to, rate: c.rate })}</p>
        <p className="text-muted">{t('start.safeNote')}</p>
      </Panel>
      <div className="flex flex-wrap items-center gap-2">
        <Button size="sm" onClick={() => setRaw(new Set(bulk.map((x) => x.id)))}>{t('start.selectAll')}</Button>
        <Button size="sm" onClick={() => setRaw(new Set(bulk.filter((x) => x.findings > 0).map((x) => x.id)))}>{t('start.selectFindings')}</Button>
        <Button size="sm" onClick={() => { setRaw(new Set()); setPicks(new Set()) }}>{t('start.selectNone')}</Button>
        <span className="text-[13px] text-muted" aria-live="polite">{t('start.selected', { count: sel.size })}</span>
      </div>
      <div className="max-h-96 overflow-y-auto rounded-md border border-rule bg-surface">
        <fieldset>
          <legend className="sticky top-0 w-full border-b border-rule bg-sunken px-3 py-1.5 text-[12px] font-medium text-muted">{t('start.internal')}</legend>
          {internal.length ? <ul className="divide-y divide-rule">{internal.map((x) => <TargetRow key={x.id} t={x} checked={sel.has(x.id)} onChange={(v) => toggle(x.id, v)} />)}</ul> : <p className="px-3 py-3 text-sm text-muted">{t('start.noInternal')}</p>}
        </fieldset>
        <fieldset>
          <legend className="sticky top-0 w-full border-y border-rule bg-sunken px-3 py-1.5 text-[12px] font-medium text-muted">{t('start.external')}</legend>
          {external.length ? <ul className="divide-y divide-rule">{external.map((x) => <TargetRow key={x.id} t={x} checked={sel.has(x.id)} onChange={(v) => toggle(x.id, v)} />)}</ul> : (
            <p className="px-3 py-3 text-sm text-muted">{t('start.noExternal')}</p>
          )}
          <p className="border-t border-rule px-3 py-2 text-[13px] text-muted">{t('start.externalHint')} <Link to="/exposure" className="text-accent underline underline-offset-4">{t('start.openExposure')}</Link></p>
        </fieldset>
      </div>
      <div className="flex flex-wrap items-center gap-3">
        <Button variant="primary" disabled={!!blocked || start.isPending}
          onClick={() => start.mutate([...sel], { onSuccess: () => toast.success(t('start.started')), onError: (e) => toast.error(errMsg(e)) })}>
          <Play />{t('start.go', { count: sel.size })}
        </Button>
        {blocked ? <span className="text-[13px] text-muted">{blocked}</span> : null}
      </div>
    </div>
  )
}

/** D-501: what Scan now identified on each device before checking it, or exactly why it could not (the box's own sentence). */
function Identification({ rows }: { rows: RunIdentRow[] }) {
  const { t } = useTranslation('scan')
  if (!rows.length) return null
  return (
    <section aria-labelledby="ident-title" className="grid gap-2">
      <h3 id="ident-title" className="text-sm font-semibold">{t('res.identTitle')}</h3>
      <ul className="divide-y divide-rule rounded-md border border-rule">
        {rows.map((r) => (
          <li key={r.target_id} className="grid gap-1 px-3 py-2 text-[13px]">
            <div className="flex flex-wrap items-center gap-x-2 gap-y-1">
              <Link to={`/devices/${r.target_id}`} className="font-medium text-accent underline-offset-4 hover:underline">{r.label}</Link>
              <span className="text-muted">{r.ip}</span>
              {r.reason ? <Chip tone={r.reason === 'not_scanned' ? 'off' : 'warn'}>{t(`ident.${r.reason}`)}</Chip> : <Chip tone="ok">{t('ident.identified')}</Chip>}
            </div>
            {r.found.length ? <span>{r.found.join(' · ')}</span> : null}
            <span className="text-muted">{r.note}</span>
          </li>
        ))}
      </ul>
    </section>
  )
}

function ResultDialog({ run, onClose, opener }: { run: ScanRun | null; onClose: () => void; opener: React.RefObject<HTMLElement | null> }) {
  const { t } = useTranslation('scan')
  const columns: ColumnDef<RunResultRow>[] = [
    { id: 'device', header: t('res.device'), accessorFn: (r) => r.label, cell: ({ row: { original: r } }) => <div className="grid"><span className="font-medium">{r.label}</span><span className="text-[12px] text-muted">{r.ip}</span></div> },
    { id: 'template', header: t('res.template'), accessorFn: (r) => r.template ?? '', cell: ({ row: { original: r } }) => <span className="text-[13px]">{r.template ?? <span className="text-muted">–</span>}</span> },
    { id: 'result', header: t('res.result'), accessorFn: (r) => r.result, cell: ({ row: { original: r } }) => <ResultChip kind={r.result} /> },
    { id: 'note', header: t('res.note'), accessorFn: (r) => r.note, cell: ({ row: { original: r } }) => (
      <div className="grid text-[13px]"><span>{r.note}</span>{r.finding_id ? <Link to={`/findings/${r.finding_id}`} className="w-fit text-accent underline underline-offset-4">{t('res.openFinding')}</Link> : null}</div>
    ) },
  ]
  // Giữ nội dung lần mở trước trong lúc đóng để Radix kịp trả focus về nút mở (nếu gỡ ngay, focus rơi về body).
  const last = useRef<ScanRun | null>(null)
  if (run) last.current = run
  const shown = run ?? last.current
  return (
    <Dialog open={!!run} onOpenChange={(o) => { if (!o) onClose() }}>
      {shown ? (
        <DialogContent wide title={t('res.title', { time: fmtDateTime(shown.started_at) })} description={t('res.description', { done: shown.done, total: shown.total })} onCloseAutoFocus={(e) => { e.preventDefault(); opener.current?.focus() }}>
          {shown.stop_reason ? <p role="note" className="rounded-md border border-dashed border-warn bg-warn-soft/60 px-3 py-2 text-sm">{shown.stop_reason}</p> : null}
          <Identification rows={shown.identification} />
          <DataTable caption={t('res.caption')} data={shown.results} columns={columns} pageSize={20} empty={t('res.empty')} />
        </DialogContent>
      ) : null}
    </Dialog>
  )
}

function History({ runs }: { runs: ScanRun[] }) {
  const { t } = useTranslation('scan')
  const [params] = useSearchParams()
  // ?run= opens that run's results: the "see the run" link of a stopped rescan (D-145 (7))
  const [open, setOpen] = useState<string | null>(() => params.get('run'))
  const opener = useRef<HTMLElement | null>(null)
  const view = useCallback((e: React.MouseEvent<HTMLElement>, id: string) => { opener.current = e.currentTarget; setOpen(id) }, [])
  // Cột phải ổn định: cột mới mỗi lần render làm TanStack gắn lại mọi ô, nút "Xem kết quả" bị thay và mất focus khi đóng hộp thoại.
  const columns = useMemo<ColumnDef<ScanRun>[]>(() => [
    { id: 'started', header: t('hist.started'), accessorFn: (r) => r.started_at, cell: ({ row: { original: r } }) => <span className="whitespace-nowrap">{fmtDateTime(r.started_at)}</span> },
    { id: 'trigger', header: t('hist.trigger'), accessorFn: (r) => r.trigger, cell: ({ row: { original: r } }) => <div className="grid text-[13px]"><span>{t(`trigger.${r.trigger}`)}</span>{r.trigger_note ? <span className="text-muted">{r.trigger_note}</span> : <span className="text-muted">{r.started_by === 'system' ? t('hist.bySystem') : r.started_by}</span>}</div> },
    { id: 'total', header: t('hist.devices'), accessorFn: (r) => r.total, cell: ({ row: { original: r } }) => <span>{r.done === r.total ? r.total : t('hist.partial', { done: r.done, total: r.total })}</span> },
    { id: 'status', header: t('hist.status'), accessorFn: (r) => r.status, cell: ({ row: { original: r } }) => <RunStatusChip run={r} /> },
    { id: 'matched', header: t('hist.matched'), accessorFn: (r) => r.matched, cell: ({ row: { original: r } }) => (r.matched ? <span className="font-medium text-danger">{r.matched}</span> : <span className="text-muted">0</span>) },
    { id: 'actions', header: () => <span className="sr-only">{t('hist.actions')}</span>, enableSorting: false, cell: ({ row: { original: r } }) => (
      <Button size="sm" disabled={isLive(r)} aria-label={t('hist.viewAria', { time: fmtDateTime(r.started_at) })} onClick={(e) => view(e, r.id)}>{t('hist.view')}</Button>
    ) },
  ], [t, view])
  return (
    <>
      <DataTable caption={t('hist.caption')} data={runs} columns={columns} pageSize={10}
        mobileRow={(r) => (
          <div className="grid gap-1.5">
            <div className="flex items-start justify-between gap-3">
              <span className="font-medium">{fmtDateTime(r.started_at)}</span>
              <RunStatusChip run={r} />
            </div>
            <span className="text-[13px] text-muted">{t(`trigger.${r.trigger}`)}{r.trigger_note ? `: ${r.trigger_note}` : r.started_by === 'system' ? '' : `, ${r.started_by}`}</span>
            <div className="flex flex-wrap items-center gap-x-3 gap-y-1 text-[13px]">
              <span>{t('hist.devicesCount', { count: r.total })}</span>
              <span className={r.matched ? 'font-medium text-danger' : 'text-muted'}>{t('hist.matchedCount', { count: r.matched })}</span>
            </div>
            <Button size="sm" className="w-fit" disabled={isLive(r)} aria-label={t('hist.viewAria', { time: fmtDateTime(r.started_at) })} onClick={(e) => view(e, r.id)}>{t('hist.view')}</Button>
          </div>
        )}
        empty={<EmptyState title={t('hist.empty')}>{t('hist.emptyHelp')}</EmptyState>} />
      <ResultDialog run={runs.find((r) => r.id === open) ?? null} onClose={() => setOpen(null)} opener={opener} />
    </>
  )
}

function Last({ run }: { run: ScanRun }) {
  const { t } = useTranslation('scan')
  return (
    <div role="status" className="mb-8 flex flex-wrap items-center gap-x-3 gap-y-1 rounded-md border border-rule bg-surface px-4 py-3 text-sm">
      <RunStatusChip run={run} />
      <span>{run.status === 'done' ? t('last.done', { time: fmtRelative(run.ended_at), total: run.total, count: run.matched }) : t('last.stopped', { time: fmtRelative(run.ended_at), done: run.done, total: run.total })}</span>
      {run.stop_reason ? <span className="w-full text-[13px] text-muted">{run.stop_reason}</span> : null}
    </div>
  )
}

export function RunsTab() {
  const { t } = useTranslation('scan')
  const runs = useRuns()
  const cfg = useScanConfig()
  const targets = useTargets()
  const live = runs.data?.items.find(isLive)
  const last = runs.data?.items.find((r) => !isLive(r))
  return (
    <>
      {live ? <Progress run={live} /> : last ? <Last run={last} /> : null}
      <Section id="start" title={t('start.title')} description={t('start.description')} stories={['S-SCAN-1', 'S-SCAN-4']}>
        <QueryState query={targets}>{(d) => <QueryState query={cfg}>{(c) => <StartPanel targets={d.items} cfg={c} live={!!live} engineBusy={!!runs.data?.engine_busy} />}</QueryState>}</QueryState>
      </Section>
      <Section id="history" title={t('hist.title')} description={t('hist.description')} stories={['S-SCAN-3']}>
        <QueryState query={runs}>{(d) => <History runs={d.items} />}</QueryState>
      </Section>
    </>
  )
}
