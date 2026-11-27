import { useState } from 'react'
import { Link, useParams, useSearchParams } from 'react-router'
import { useTranslation } from 'react-i18next'
import { toast } from 'sonner'
import { OctagonX, Play } from 'lucide-react'
import { Card } from '@/components/common/Card'
import { KeyValue, PageHeader, Section } from '@/components/common/PageHeader'
import { EmptyState, ErrorState, Loading } from '@/components/common/States'
import { Button } from '@/components/ui/button'
import { Dialog, DialogContent, DialogFooter } from '@/components/ui/dialog'
import type { Crumb } from '@/components/common/Breadcrumbs'
import { ApiError } from '@/lib/api'
import { fmtDateTime, fmtNumber } from '@/lib/format'
import { useNavPlace } from '@/lib/navPlace'
import { useRun, useRunAction } from './api'
import { runHref, runPlace, runsHref, type RunPlace } from './places'
import { RunBar, RunStateChip, useKindLabel, useStartedBy } from './RunParts'
import { RunSteps, useStepsLine } from './RunSteps'
import type { Run, RunDetail } from './types'
import { RowTitle } from '@/components/common/ListParts'

const link = 'text-accent underline-offset-4 hover:underline [overflow-wrap:anywhere]'
const errMsg = (e: unknown) => (e instanceof Error ? e.message : String(e))

/** Where a subject of a run (a device, a public target) has its own page; null for what has none (an address no device has yet). */
function subjectHref(kind: string, id: string | null): string | null {
  if (!id) return null
  if (kind === 'device') return `/devices/${encodeURIComponent(id)}`
  if (kind === 'target') return `/exposure/${encodeURIComponent(id)}`
  if (kind === 'run') return runHref(id) // a run this one reused (an address's own deep scan)
  return null
}

/** The breadcrumb of a run's page and the menu entry it keeps lit (useNavPlace): back to the target's Scans tab, to the device, or to
 *  Settings › Scanning › Runs. */
function usePlace(place: RunPlace): { crumbs: Crumb[]; nav: string } {
  const { t } = useTranslation('scanning')
  const enc = encodeURIComponent
  if (place.kind === 'target') {
    return { nav: '/exposure', crumbs: [{ label: t('common:shell.exposure'), to: '/exposure' }, { label: place.label, to: `/exposure/${enc(place.id)}` },
      { label: t('runs.place.scans'), to: `/exposure/${enc(place.id)}?tab=scans` }] }
  }
  if (place.kind === 'device') {
    return { nav: '/devices', crumbs: [{ label: t('common:shell.devices'), to: '/devices' }, { label: place.label, to: `/devices/${enc(place.id)}` }] }
  }
  return { nav: '/settings/scanning', crumbs: [{ label: t('page.title'), to: '/settings/scanning' }, { label: t('page.tab.runs'), to: runsHref() }] }
}

/** A queued run waits for the run that holds its lane (blocked_by, from the box): the summary above says its place in line and when it
 *  starts; this line opens the run in its way. */
function Blocker({ r }: { r: Run }) {
  const { t } = useTranslation('scanning')
  if (r.status !== 'queued' || !r.blocked_by) return null
  return <p className="text-meta">{t('runs.inItsWay')} <Link to={runHref(r.blocked_by.id)} className={link}>{r.blocked_by.title}</Link></p>
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
          {/* a run that waits has not stopped: the button starts it now instead of at its turn, "Resume" is for a stopped run */}
          <Play />{t(r.status === 'waiting' ? 'runs.startNow' : 'runs.resume')}
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

function Body({ r, crumbs }: { r: RunDetail; crumbs: Crumb[] }) {
  const { t } = useTranslation('scanning')
  const kindLabel = useKindLabel()
  const startedBy = useStartedBy()
  const stepsLine = useStepsLine()
  // the subject's page is linked once: by the breadcrumb when the run's page sits under it, by About otherwise
  const href = r.subject ? subjectHref(r.subject.kind, r.subject.id) : null
  const subject = href && !crumbs.some((c) => c.to === href) ? href : null
  // A public scan's items of kind "port" record which ports its service step checked, for the next scan; they are not devices or
  // addresses, so they are neither listed nor counted (the count can only leave out the ones among the items read).
  const items = r.items.filter((it) => it.subject_kind !== 'port')
  const itemsTotal = r.items_total - (r.items.length - items.length)
  return (
    <>
      <PageHeader breadcrumbs={crumbs} title={r.title} meta={`${kindLabel(r.kind)} · ${startedBy(r)}`} actions={<Actions r={r} />} stories={['S-SCAN-4']} />
      <Card className="mb-6 grid gap-3">
        <div className="flex flex-wrap items-center gap-x-3 gap-y-1">
          <RunStateChip status={r.status} />
          {/* the box's one line: for a queued run its place in line and when it starts ("… (2nd in line); it starts in about 9 minutes") */}
          <span className="text-meta">{r.summary}</span>
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
        <Section id="run-steps" title={t('runs.steps')} description={stepsLine(r.steps)}>
          <Card flush>
            <RunSteps steps={r.steps} label={t('runs.stepsOf', { title: r.title })} />
          </Card>
        </Section>
      ) : null}
      {r.children.length ? (
        <Section id="run-children" title={t('runs.children')}>
          <Card flush>
            <ul className="divide-y divide-rule">
              {r.children.map((c) => (
                <li key={c.id} className="flex flex-wrap items-center gap-x-3 gap-y-1 px-4 py-3 text-meta">
                  <RowTitle to={runHref(c.id)}>{c.title}</RowTitle>
                  <RunStateChip status={c.status} />
                </li>
              ))}
            </ul>
          </Card>
        </Section>
      ) : null}
      {items.length ? (
        <Section id="run-items" title={t('runs.items', { count: itemsTotal })}>
          <Card flush>
            <ul className="divide-y divide-rule">
              {items.map((it) => {
                const to = subjectHref(it.subject_kind, it.subject_id)
                return (
                  <li key={it.seq} className="grid gap-0.5 px-4 py-2 text-meta">
                    <span className="flex flex-wrap items-center gap-x-2">
                      <RowTitle to={to ?? undefined}>{it.label}</RowTitle>
                      <span className="text-muted">{t(`runs.outcome.${it.outcome}`, { defaultValue: it.outcome })}</span>
                    </span>
                    {it.note ? <span className="text-muted">{it.note}</span> : null}
                  </li>
                )
              })}
            </ul>
          </Card>
          {itemsTotal > items.length ? <p className="mt-2 text-meta text-muted">{t('runs.itemsFirst', { shown: fmtNumber(items.length), total: fmtNumber(itemsTotal) })}</p> : null}
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
  const [params] = useSearchParams()
  const q = useRun(id)
  const from = params.get('from')
  // Its place is the run's subject (a target, a device) or Settings › Scanning when opened from there; until the run is read, only a
  // link from Settings says where it belongs.
  const known = !!q.data || from === 'settings' || !!q.error
  const { crumbs, nav } = usePlace(runPlace(q.data?.subject ?? null, q.data || q.error ? from : 'settings'))
  useNavPlace(known ? nav : null)
  if (q.error instanceof ApiError && q.error.status === 404) {
    return (
      <>
        <PageHeader breadcrumbs={crumbs} title={t('runs.goneTitle')} />
        <EmptyState title={t('runs.gone')} action={<Link to={runsHref()} className={link}>{t('runs.seeAll')}</Link>} />
      </>
    )
  }
  if (q.error) return <><PageHeader breadcrumbs={crumbs} title={t('runs.pageTitle')} /><ErrorState error={q.error} onRetry={() => void q.refetch()} /></>
  if (q.isPending) return <><PageHeader breadcrumbs={known ? crumbs : []} title={t('runs.pageTitle')} /><Loading /></>
  return <Body r={q.data} crumbs={crumbs} />
}
