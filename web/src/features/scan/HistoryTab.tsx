import { useCallback, useMemo, useRef, useState } from 'react'
import { Link, useSearchParams } from 'react-router'
import { useTranslation } from 'react-i18next'
import { toast } from 'sonner'
import { OctagonX } from 'lucide-react'
import { Notice, Section } from '@/components/common/PageHeader'
import { DataTable, type ColumnDef } from '@/components/common/DataTable'
import { EmptyState, QueryState } from '@/components/common/States'
import { Chip } from '@/components/common/StatusChip'
import { JobProgress } from '@/components/progress/JobProgress'
import { Button } from '@/components/ui/button'
import { Dialog, DialogContent } from '@/components/ui/dialog'
import { fmtDateTime, fmtRelative } from '@/lib/format'
import { useCan } from '@/lib/session'
import { isLive, useRuns, useStopRun } from './api'
import { errMsg } from './errors'
import { ResultChip, RunStatusChip, runOutcome } from './shared'
import { RescanLog } from './RescanLog'
import type { RunIdentRow, RunResultRow, ScanRun } from './types'

function Progress({ run }: { run: ScanRun }) {
  const { t } = useTranslation('scan')
  const can = useCan('operator')
  const stop = useStopRun()
  const stopping = run.status === 'stopping'
  const pct = run.total ? Math.round((run.done / run.total) * 100) : 0
  return (
    <section aria-labelledby="progress-title" className="mb-8 rounded-md border border-accent/40 bg-accent-soft p-4">
      <h2 id="progress-title" className="text-base font-semibold">{stopping ? t('progress.stopping') : t('progress.device', { n: Math.min(run.done + 1, run.total), total: run.total })}</h2>
      {/* #830: the devices bar only when there are several; one device's progress is the step bar below */}
      {run.total > 1 ? (
        <div role="progressbar" aria-label={t('progress.bar')} aria-valuemin={0} aria-valuemax={100} aria-valuenow={pct} className="my-3 h-2 overflow-hidden rounded-full bg-surface">
          <div className="h-full bg-accent transition-[width]" style={{ width: `${pct}%` }} />
        </div>
      ) : null}
      <div className="mt-2 flex flex-wrap items-center gap-x-4 gap-y-2">
        <p className="text-sm" role="status">{stopping ? t('progress.stoppingBody') : run.current ? t('progress.current', { label: run.current.label, ip: run.current.ip }) : ''}</p>
        <Button variant="danger" className="ml-auto" disabled={!can} busy={stopping || stop.isPending} busyLabel={t('common:busy.stopping')} title={can ? undefined : t('common:needRole', { role: t('common:role.operator') })}
          onClick={() => stop.mutate(run.id, { onError: (e) => toast.error(errMsg(e)) })}>
          <OctagonX />{t('progress.stop')}
        </Button>
      </div>
      {stopping ? null : <JobProgress progress={run.progress} className="mt-3 rounded-md bg-surface p-3" />}
      <p className="mt-2 text-meta text-muted">{t('progress.note')}</p>
    </section>
  )
}

/** What Scan now identified on each device before checking it, or exactly why it could not (the box's own sentence). */
function Identification({ rows }: { rows: RunIdentRow[] }) {
  const { t } = useTranslation('scan')
  if (!rows.length) return null
  return (
    <section aria-labelledby="ident-title" className="grid gap-2">
      <h3 id="ident-title" className="text-sm font-semibold">{t('res.identTitle')}</h3>
      <ul className="divide-y divide-rule rounded-md border border-rule">
        {rows.map((r) => (
          <li key={r.target_id} className="grid gap-1 px-3 py-2 text-meta">
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
    { id: 'device', header: t('res.device'), accessorFn: (r) => r.label, cell: ({ row: { original: r } }) => <div className="grid"><span className="font-medium">{r.label}</span><span className="text-caption text-muted">{r.ip}</span></div> },
    { id: 'template', header: t('res.template'), accessorFn: (r) => r.template ?? '', cell: ({ row: { original: r } }) => <span className="text-meta">{r.template ?? <span className="text-muted">–</span>}</span> },
    { id: 'result', header: t('res.result'), accessorFn: (r) => r.result, cell: ({ row: { original: r } }) => <ResultChip kind={r.result} /> },
    { id: 'note', header: t('res.note'), accessorFn: (r) => r.note, cell: ({ row: { original: r } }) => (
      <div className="grid text-meta"><span>{r.note}</span>{r.finding_id ? <Link to={`/findings/${r.finding_id}`} className="w-fit text-accent underline underline-offset-4">{t('res.openFinding')}</Link> : null}</div>
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
          {shown.stop_reason ? <Notice tone="warn" role="note" className="mb-0" title={shown.stop_reason} /> : null}
          <Identification rows={shown.identification} />
          <DataTable urlKey="scan-results" caption={t('res.caption')} data={shown.results} columns={columns} pageSize={20} empty={t('res.empty')} />
        </DialogContent>
      ) : null}
    </Dialog>
  )
}

function History({ runs }: { runs: ScanRun[] }) {
  const { t } = useTranslation('scan')
  const [params] = useSearchParams()
  // ?run= opens that run's results: the "see the run" link of a stopped rescan
  const [open, setOpen] = useState<string | null>(() => params.get('run'))
  const opener = useRef<HTMLElement | null>(null)
  const view = useCallback((e: React.MouseEvent<HTMLElement>, id: string) => { opener.current = e.currentTarget; setOpen(id) }, [])
  // Cột phải ổn định: cột mới mỗi lần render làm TanStack gắn lại mọi ô, nút "Xem kết quả" bị thay và mất focus khi đóng hộp thoại.
  const columns = useMemo<ColumnDef<ScanRun>[]>(() => [
    { id: 'started', header: t('hist.started'), accessorFn: (r) => r.started_at, cell: ({ row: { original: r } }) => <span className="whitespace-nowrap">{fmtDateTime(r.started_at)}</span> },
    { id: 'trigger', header: t('hist.trigger'), accessorFn: (r) => r.trigger, cell: ({ row: { original: r } }) => <div className="grid text-meta"><span>{t(`trigger.${r.trigger}`)}</span>{r.trigger_note ? <span className="text-muted">{r.trigger_note}</span> : <span className="text-muted">{r.started_by === 'system' ? t('hist.bySystem') : r.started_by}</span>}</div> },
    { id: 'total', header: t('hist.devices'), accessorFn: (r) => r.total, cell: ({ row: { original: r } }) => <span>{r.done === r.total ? r.total : t('hist.partial', { done: r.done, total: r.total })}</span> },
    { id: 'status', header: t('hist.status'), accessorFn: (r) => r.status, cell: ({ row: { original: r } }) => <RunStatusChip run={r} /> },
    // What the run found in words, from its results (never "0 matches" when nothing could be checked)
    { id: 'found', header: t('hist.found'), accessorFn: (r) => r.matched, cell: ({ row: { original: r } }) => <span className={r.matched ? 'text-meta font-medium text-danger' : 'text-meta'}>{runOutcome(r, t)}</span> },
    { id: 'actions', header: () => <span className="sr-only">{t('hist.actions')}</span>, enableSorting: false, cell: ({ row: { original: r } }) => (
      <Button size="sm" disabled={isLive(r)} aria-label={t('hist.viewAria', { time: fmtDateTime(r.started_at) })} onClick={(e) => view(e, r.id)}>{t('hist.view')}</Button>
    ) },
  ], [t, view])
  return (
    <>
      <DataTable urlKey="scan-history" caption={t('hist.caption')} data={runs} columns={columns} pageSize={10}
        mobileRow={(r) => (
          <div className="grid gap-1.5">
            <div className="flex items-start justify-between gap-3">
              <span className="font-medium">{fmtDateTime(r.started_at)}</span>
              <RunStatusChip run={r} />
            </div>
            <span className="text-meta text-muted">{t(`trigger.${r.trigger}`)}{r.trigger_note ? `: ${r.trigger_note}` : r.started_by === 'system' ? '' : `, ${r.started_by}`}</span>
            <div className="flex flex-wrap items-center gap-x-3 gap-y-1 text-meta">
              <span>{t('hist.devicesCount', { count: r.total })}</span>
              <span className={r.matched ? 'font-medium text-danger' : ''}>{runOutcome(r, t)}</span>
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
      <span>{run.status === 'done' ? t('last.doneOutcome', { time: fmtRelative(run.ended_at), outcome: runOutcome(run, t) }) : t('last.stopped', { time: fmtRelative(run.ended_at), done: run.done, total: run.total })}</span>
      {run.stop_reason ? <span className="w-full text-meta text-muted">{run.stop_reason}</span> : null}
    </div>
  )
}

/** #850: Settings › Scanning › History: the run going on (with Stop now), the last one, every run with its results, and the automatic rescans. */
export function HistoryTab() {
  const { t } = useTranslation('scan')
  const [params] = useSearchParams()
  const runs = useRuns()
  const live = runs.data?.items.find(isLive)
  const last = runs.data?.items.find((r) => !isLive(r))
  return (
    <>
      {live ? <Progress run={live} /> : last ? <Last run={last} /> : null}
      <Section id="history" title={t('hist.title')} description={t('hist.description')} info={t('hist.descriptionInfo')} stories={['S-SCAN-3']}>
        {/* a link with another ?run= (a rescan's "see the run") opens that run: the table starts again from the link */}
        <QueryState query={runs}>{(d) => <History key={params.get('run') ?? ''} runs={d.items} />}</QueryState>
      </Section>
      <RescanLog />
    </>
  )
}
