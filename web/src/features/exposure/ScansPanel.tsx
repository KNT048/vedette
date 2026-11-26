import { Link } from 'react-router'
import { useTranslation } from 'react-i18next'
import { Card } from '@/components/common/Card'
import { DataTable, type ColumnDef } from '@/components/common/DataTable'
import { EmptyState, QueryState } from '@/components/common/States'
import { fmtDateTime, fmtEnd } from '@/lib/format'
import { useRun } from '@/features/scanning/api'
import { RunSteps, useStepsLine } from '@/features/scanning/RunSteps'
import { isLive, useRows } from './api'
import { runHref } from './node'
import { RunState } from './NodeParts'
import type { Scan, TargetNode } from './types'

const link = 'font-medium text-accent underline-offset-4 hover:underline'

/** The runs of this target, newest first: who or what started each, how deep, how it ended and what it changed. The newest one's steps
 *  come first, the same list as its run page, so what a scan is doing (or why a step did not run) is seen here too. */
export function ScansPanel({ node }: { node: TargetNode }) {
  const q = useRows(node.id, 'scans', { poll: isLive(node.last_scan) })
  return <QueryState query={q}>{(d) => <>{newest(d.items) ? <LatestSteps scan={newest(d.items)!} /> : null}<ScansTable node={node} scans={d.items} /></>}</QueryState>
}

const when = (s: Scan) => s.started_at ?? s.queued_at
const newest = (scans: Scan[]): Scan | undefined => scans.reduce<Scan | undefined>((a, s) => (!a || when(s) > when(a) ? s : a), undefined)

/** The steps of the newest scan (the run page's list, compact), with where it stands and the way to its run page. A queued scan has no
 *  steps yet: nothing is shown until it starts. */
function LatestSteps({ scan }: { scan: Scan }) {
  const { t } = useTranslation('exposure')
  const q = useRun(scan.run_id)
  const stepsLine = useStepsLine()
  const steps = q.data?.steps ?? []
  if (!steps.length) return null
  return (
    <Card flush className="my-4">
      <div className="flex flex-wrap items-baseline justify-between gap-x-3 gap-y-1 border-b border-rule px-3 py-2">
        <h3 className="text-sm font-medium">{t(isLive(scan) ? 'scans.stepsNow' : 'scans.stepsLatest', { when: fmtDateTime(when(scan)) })}</h3>
        <span className="text-meta text-muted">{stepsLine(steps)} · <Link className={link} to={runHref(scan.run_id)}>{t('run.open')}</Link></span>
      </div>
      <RunSteps steps={steps} compact label={t('scans.stepsOf', { when: fmtDateTime(when(scan)) })} />
    </Card>
  )
}

function ScansTable({ node, scans }: { node: TargetNode; scans: Scan[] }) {
  const { t } = useTranslation('exposure')
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
  return (
    <span className="grid gap-0.5 text-meta">
      {c ? <span>{t('run.result', { services: c.services, newServices: c.new_services, closed: c.closed_services, issues: c.issues, newIssues: c.new_issues })}</span> : null}
      {s.waiting_for ? <span className="text-muted">{t('run.waitingFor', { what: s.waiting_for })}</span> : null}
      {s.error || s.stop_reason ? <span className={s.status === 'failed' ? 'text-danger' : 'text-muted'}>{s.error ?? s.stop_reason}</span> : null}
      {!c && !s.waiting_for && !s.error && !s.stop_reason ? <span className="text-muted">—</span> : null}
    </span>
  )
}
