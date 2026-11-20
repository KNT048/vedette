import { useState } from 'react'
import { Link, useParams } from 'react-router'
import { useTranslation } from 'react-i18next'
import { toast } from 'sonner'
import { OctagonX, Play } from 'lucide-react'
import { Card } from '@/components/common/Card'
import { KeyValue, PageHeader, Section } from '@/components/common/PageHeader'
import { EmptyState, ErrorState, Loading } from '@/components/common/States'
import { Button } from '@/components/ui/button'
import { Dialog, DialogContent, DialogFooter } from '@/components/ui/dialog'
import { ApiError } from '@/lib/api'
import { fmtDateTime, fmtNumber } from '@/lib/format'
import { useRun, useRunAction } from './api'
import { runHref, runsHref } from './places'
import { RunBar, RunStateChip, useKindLabel, useRunCount, useStartedBy } from './RunParts'
import type { Run, RunDetail } from './types'

const link = 'text-accent underline-offset-4 hover:underline [overflow-wrap:anywhere]'
const errMsg = (e: unknown) => (e instanceof Error ? e.message : String(e))

/** Where a subject of a run (a device, a public target) has its own page; null for what has none (an address no device has yet). */
function subjectHref(kind: string, id: string | null): string | null {
  if (!id) return null
  if (kind === 'device') return `/devices/${encodeURIComponent(id)}`
  if (kind === 'target') return `/exposure/${encodeURIComponent(id)}`
  return null
}

/** A queued run waits for the run that holds its lane (blocked_by, from the box): that run, by name, with its own link. */
function Blocker({ r }: { r: Run }) {
  const { t } = useTranslation('scanning')
  if (r.status !== 'queued' || !r.blocked_by) return null
  return <p className="text-meta">{t('runs.queuedBehind')} <Link to={runHref(r.blocked_by.id)} className={link}>{r.blocked_by.title}</Link></p>
}

/** Stop and Resume, as the box says the person asking may use them (can_stop, can_resume). Stop asks first: work not reached yet is
 *  not done. */
function Actions({ r }: { r: RunDetail }) {
  const { t } = useTranslation('scanning')
  const act = useRunAction()
  const [asking, setAsking] = useState(false)
  const run = (action: 'stop' | 'resume') => act.mutate({ id: r.id, action }, {
    onSuccess: () => { setAsking(false); toast.success(t(action === 'stop' ? 'runs.stopped' : 'runs.resumed')) },
    onError: (e) => toast.error(errMsg(e)),
  })
  if (!r.can_stop && !r.can_resume) return null
  return (
    <div className="flex flex-wrap items-center gap-2">
      {r.can_resume ? (
        <Button busy={act.isPending && act.variables?.action === 'resume'} busyLabel={t('common:busy.starting')} onClick={() => run('resume')}>
          <Play />{t('runs.resume')}
        </Button>
      ) : null}
      {r.can_stop ? (
        <Button variant="danger" onClick={() => setAsking(true)}><OctagonX />{t('runs.stop')}</Button>
      ) : null}
      <Dialog open={asking} onOpenChange={setAsking}>
        <DialogContent title={t('runs.stopTitle')} description={t('runs.stopBody')}>
          <DialogFooter>
            <Button onClick={() => setAsking(false)}>{t('common:cancel')}</Button>
            <Button variant="danger" busy={act.isPending && act.variables?.action === 'stop'} busyLabel={t('common:busy.stopping')} onClick={() => run('stop')}>{t('runs.stopConfirm')}</Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  )
}

function Body({ r }: { r: RunDetail }) {
  const { t } = useTranslation('scanning')
  const kindLabel = useKindLabel()
  const startedBy = useStartedBy()
  const count = useRunCount()
  const subject = r.subject ? subjectHref(r.subject.kind, r.subject.id) : null
  const crumbs = [{ label: t('page.title'), to: '/settings/scanning' }, { label: t('page.tab.runs'), to: runsHref() }]
  return (
    <>
      <PageHeader breadcrumbs={crumbs} title={r.title} meta={`${kindLabel(r.kind)} · ${startedBy(r)}`} actions={<Actions r={r} />} stories={['S-SCAN-4']} />
      <Card className="mb-6 grid gap-3">
        <div className="flex flex-wrap items-center gap-x-3 gap-y-1">
          <RunStateChip status={r.status} />
          {r.status !== 'queued' || !r.blocked_by ? <span className="text-meta">{r.summary}</span> : null}
        </div>
        <Blocker r={r} />
        {r.total > 0 ? (
          <div className="grid max-w-xl gap-1 text-meta">
            <RunBar done={r.done} total={r.total} label={t('runs.progressOf', { title: r.title })} />
          </div>
        ) : null}
        <KeyValue items={[
          ...(r.subject ? [{ label: t('runs.about'), value: subject ? <Link to={subject} className={link}>{r.subject.label}</Link> : r.subject.label }] : []),
          ...(r.parent_id ? [{ label: t('runs.partOf'), value: <Link to={runHref(r.parent_id)} className={link}>{t('runs.parentRun')}</Link> }] : []),
          { label: t('runs.queued'), value: fmtDateTime(r.queued_at) },
          ...(r.started_at ? [{ label: t('runs.started'), value: fmtDateTime(r.started_at) }] : []),
          ...(r.ended_at ? [{ label: t('runs.ended'), value: fmtDateTime(r.ended_at) }] : []),
        ]} />
      </Card>
      {r.steps.length > 1 || r.steps.some((s) => s.note) ? (
        <Section id="run-steps" title={t('runs.steps')}>
          <Card flush>
            <ol className="divide-y divide-rule">
              {r.steps.map((s) => (
                <li key={s.seq} className="grid gap-1 px-4 py-3 text-meta">
                  <div className="flex flex-wrap items-center gap-x-3 gap-y-1">
                    <span className="font-medium [overflow-wrap:anywhere]">{s.name}</span>
                    <RunStateChip status={s.status} />
                    {s.total > 0 ? <span className="tabular-nums text-muted">{count(s)}</span> : null}
                  </div>
                  {s.total > 0 ? <div className="max-w-xl"><RunBar done={s.done} total={s.total} label={t('runs.progressOf', { title: s.name })} /></div> : null}
                  {s.note ? <span className="text-muted">{s.note}</span> : null}
                </li>
              ))}
            </ol>
          </Card>
        </Section>
      ) : null}
      {r.children.length ? (
        <Section id="run-children" title={t('runs.children')}>
          <Card flush>
            <ul className="divide-y divide-rule">
              {r.children.map((c) => (
                <li key={c.id} className="flex flex-wrap items-center gap-x-3 gap-y-1 px-4 py-3 text-meta">
                  <Link to={runHref(c.id)} className={`font-medium ${link}`}>{c.title}</Link>
                  <RunStateChip status={c.status} />
                </li>
              ))}
            </ul>
          </Card>
        </Section>
      ) : null}
      {r.items.length ? (
        <Section id="run-items" title={t('runs.items', { count: r.items_total })}>
          <Card flush>
            <ul className="divide-y divide-rule">
              {r.items.map((it) => {
                const to = subjectHref(it.subject_kind, it.subject_id)
                return (
                  <li key={it.seq} className="grid gap-0.5 px-4 py-2 text-meta">
                    <span className="flex flex-wrap items-center gap-x-2">
                      {to ? <Link to={to} className={`font-medium ${link}`}>{it.label}</Link> : <span className="font-medium">{it.label}</span>}
                      <span className="text-muted">{t(`runs.outcome.${it.outcome}`, { defaultValue: it.outcome })}</span>
                    </span>
                    {it.note ? <span className="text-muted">{it.note}</span> : null}
                  </li>
                )
              })}
            </ul>
          </Card>
          {r.items_total > r.items.length ? <p className="mt-2 text-meta text-muted">{t('runs.itemsFirst', { shown: fmtNumber(r.items.length), total: fmtNumber(r.items_total) })}</p> : null}
        </Section>
      ) : null}
      {r.log.length ? (
        <details className="group rounded-md border border-rule bg-surface">
          <summary className="cursor-pointer px-4 py-3 text-sm font-medium">{t('runs.log', { count: r.log.length })}</summary>
          <ol className="grid gap-0.5 border-t border-rule px-4 py-3 font-mono text-caption">
            {r.log.map((l, i) => (
              <li key={i} className={l.level === 'error' ? 'text-danger' : l.level === 'warn' ? 'text-warn' : undefined}>
                <span className="text-muted">{fmtDateTime(l.ts)}</span> {l.text}
              </li>
            ))}
          </ol>
        </details>
      ) : null}
    </>
  )
}

/**
 * /runs/<id>: one run of any engine. What it is and who or what started it, its state with the reason when it waits or stopped,
 * its progress per step, the devices it touched (each a link), the runs under it and the tail of its log; Stop and Resume where they
 * apply. Every "Open the run" of the app comes here. Read again while the run moves or waits.
 */
export default function RunPage() {
  const { t } = useTranslation('scanning')
  const { id = '' } = useParams()
  const q = useRun(id)
  const crumbs = [{ label: t('page.title'), to: '/settings/scanning' }, { label: t('page.tab.runs'), to: runsHref() }]
  if (q.error instanceof ApiError && q.error.status === 404) {
    return (
      <>
        <PageHeader breadcrumbs={crumbs} title={t('runs.goneTitle')} />
        <EmptyState title={t('runs.gone')} action={<Link to={runsHref()} className={link}>{t('runs.seeAll')}</Link>} />
      </>
    )
  }
  if (q.error) return <><PageHeader breadcrumbs={crumbs} title={t('runs.pageTitle')} /><ErrorState error={q.error} onRetry={() => void q.refetch()} /></>
  if (q.isPending) return <><PageHeader breadcrumbs={crumbs} title={t('runs.pageTitle')} /><Loading /></>
  return <Body r={q.data} />
}
