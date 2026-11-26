import { Link } from 'react-router'
import { useTranslation } from 'react-i18next'
import { DataTable, type ColumnDef } from '@/components/common/DataTable'
import { EmptyState, QueryState } from '@/components/common/States'
import { fmtDateTime, fmtEnd } from '@/lib/format'
import { isLive, useRows } from './api'
import { runHref } from './node'
import { RunState } from './NodeParts'
import type { Scan, TargetNode } from './types'

const link = 'font-medium text-accent underline-offset-4 hover:underline'

/** The runs of this target, newest first: who or what started each, how deep, how it ended and what it changed; its steps are on the run page. */
export function ScansPanel({ node }: { node: TargetNode }) {
  const q = useRows(node.id, 'scans', { poll: isLive(node.last_scan) })
  return <QueryState query={q}>{(d) => <ScansTable node={node} scans={d.items} />}</QueryState>
}

function ScansTable({ node, scans }: { node: TargetNode; scans: Scan[] }) {
  const { t } = useTranslation('exposure')
  const when = (s: Scan) => s.started_at ?? s.queued_at
  const columns: ColumnDef<Scan>[] = [
    { id: 'when', header: t('scans.col.when'), accessorFn: when, cell: ({ row }) => {
      const s = row.original
      return <span className="grid gap-0.5"><Link className={link} to={runHref(s.run_id)}>{fmtDateTime(when(s))}</Link>{s.ended_at && s.started_at ? <span className="text-caption text-muted">{t('scans.ended', { end: fmtEnd(s.started_at, s.ended_at) })}</span> : null}</span>
    } },
    { id: 'trigger', header: t('scans.col.trigger'), accessorFn: (s) => s.trigger, cell: ({ row }) => <span className="text-meta">{row.original.trigger === 'manual' ? t('scans.by', { who: row.original.requested_by }) : t(`scans.trigger.${row.original.trigger}`)}</span> },
    { id: 'mode', header: t('scans.col.mode'), accessorFn: (s) => s.mode, cell: ({ row }) => <span className="text-meta">{t(`run.mode.${row.original.mode}`)}</span> },
    { id: 'status', header: t('scans.col.status'), accessorFn: (s) => s.status, cell: ({ row }) => <RunState scan={row.original} /> },
    { id: 'result', header: t('scans.col.result'), enableSorting: false, cell: ({ row }) => <Result s={row.original} /> },
  ]
  return (
    <DataTable urlKey="exposure-scans" caption={t('scans.caption', { value: node.value })} data={scans} columns={columns} pageSize={25} initialSort={[{ id: 'when', desc: true }]}
      mobileRow={(s) => (
        <div className="grid gap-1.5">
          <div className="flex flex-wrap items-center gap-2"><Link className={link} to={runHref(s.run_id)}>{fmtDateTime(when(s))}</Link><RunState scan={s} /></div>
          <span className="text-meta text-muted">{s.trigger === 'manual' ? t('scans.by', { who: s.requested_by }) : t(`scans.trigger.${s.trigger}`)} · {t(`run.mode.${s.mode}`)}</span>
          <Result s={s} />
        </div>
      )}
      empty={<EmptyState title={t('scans.emptyTitle')}>{t('scans.emptyBody')}</EmptyState>} />
  )
}

/** What a run left (services and issues, with what was new or closed), or why it did not finish. */
function Result({ s }: { s: Scan }) {
  const { t } = useTranslation('exposure')
  const c = s.counts
  // A scheduled run reads the pages without attacking them: the box's own line says so, so the run does not look incomplete.
  const webNote = s.web_steps.find((w) => w.step === 'zap_active' && w.state === 'skipped')?.note
  return (
    <span className="grid gap-0.5 text-meta">
      {c ? <span>{t('run.result', { services: c.services, newServices: c.new_services, closed: c.closed_services, issues: c.issues, newIssues: c.new_issues })}</span> : null}
      {webNote ? <span className="text-muted">{webNote}</span> : null}
      {s.waiting_for ? <span className="text-muted">{t('run.waitingFor', { what: s.waiting_for })}</span> : null}
      {s.error || s.stop_reason ? <span className={s.status === 'failed' ? 'text-danger' : 'text-muted'}>{s.error ?? s.stop_reason}</span> : null}
      {!c && !s.waiting_for && !s.error && !s.stop_reason ? <span className="text-muted">—</span> : null}
    </span>
  )
}
