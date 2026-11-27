import { useState } from 'react'
import { Link, useNavigate } from 'react-router'
import { useTranslation } from 'react-i18next'
import { toast } from 'sonner'
import { CalendarClock, Play } from 'lucide-react'
import { ErrorState } from '@/components/common/States'
import { Button } from '@/components/ui/button'
import { Dialog, DialogClose, DialogContent, DialogFooter } from '@/components/ui/dialog'
import { useCan } from '@/lib/session'
import { useRunSchedule, useSaveSchedule, useSchedule } from './api'
import { describeRule, intervalProblem, toDraft, toSave, type Draft } from './rule'
import { fieldError, fmtInZone, orgZoneOf, ScheduleFields } from './ScheduleFields'
import type { Schedule } from './types'
import { ExpandToggle } from '@/components/common/ListParts'

const errMsg = (e: unknown) => (e instanceof Error ? e.message : String(e))

/** One line for a schedule: "Off", or its rule ("Weekly on Sun at 23:00, in the scan window"). */
export function ScheduleText({ schedule: s }: { schedule: Schedule }) {
  const { t } = useTranslation('schedule')
  return <>{s.enabled ? describeRule(s.rule, t, (iso) => fmtInZone(iso, s.zone)) : t('state.off')}</>
}

/** The one line of a schedule read by its key, for a list cell; "–" until it is read. */
export function ScheduleTextOf({ ownerKey }: { ownerKey: string }) {
  const q = useSchedule(ownerKey)
  return q.data ? <ScheduleText schedule={q.data} /> : <>–</>
}

/**
 * One schedule, as a line where it is used: what it is set to and when it next starts, with Change (a dialog with the fields and the
 * next three start times), Run now (it opens the run it started) and, while paused, Resume. Details (the next three start times,
 * the last start and who changed it) are one click away. `ownerKey` is the schedule's owner_key (scan.vuln,
 * exposure.target:<id> …); `name` says what it starts, for the dialog's title. `runNow={false}` where the place already has its
 * own button that starts the same work.
 */
/** `blocked`: why the owner does not let the schedule start now (for example terms not accepted yet); it replaces the next start. */
export function ScheduleEditor({ ownerKey, name, runNow = true, blocked }: { ownerKey: string; name: string; runNow?: boolean; blocked?: string }) {
  const { t } = useTranslation('schedule')
  const q = useSchedule(ownerKey)
  if (q.error) return <ErrorState error={q.error} onRetry={() => void q.refetch()} />
  if (!q.data) return <p role="status" className="text-meta text-muted">{t('loading')}</p>
  return <Summary s={q.data} name={name} runNow={runNow} blocked={blocked} />
}

function Summary({ s, name, runNow, blocked }: { s: Schedule; name: string; runNow: boolean; blocked?: string }) {
  const { t } = useTranslation('schedule')
  const navigate = useNavigate()
  const can = useCan(s.edit_role)
  const run = useRunSchedule(s.owner_key)
  const save = useSaveSchedule(s.owner_key)
  const [editing, setEditing] = useState(false)
  const [details, setDetails] = useState(false)
  const locked = can ? undefined : t('common:needRole', { role: t(`common:role.${s.edit_role}`) })
  const paused = !!s.paused_until && Date.parse(s.paused_until) > Date.now()
  const when = (iso: string) => fmtInZone(iso, s.zone)
  const next = !s.enabled ? null
    : blocked ? blocked
    : paused ? t('next.paused', { date: when(s.paused_until!) })
    : s.waiting_for ? t('next.waiting', { what: s.waiting_for })
    : s.upcoming[0] ? t('next.at', { time: when(s.upcoming[0]) }) : t('next.none')
  const startNow = () => run.mutate(undefined, {
    onSuccess: (r) => {
      if (r.run_id) { const id = r.run_id; toast.success(t('run.started', { name }), { action: { label: t('run.open'), onClick: () => void navigate(`/runs/${id}`) } }) }
      else toast.success(t('run.startedNoRun', { name }))
    },
    onError: (e) => toast.error(errMsg(e)),
  })
  const resume = () => save.mutate({ enabled: s.enabled, paused_until: null, rule: s.rule }, { onSuccess: () => toast.success(t('resumed', { name })), onError: (e) => toast.error(errMsg(e)) })
  const panel = `sched-${s.owner_key.replace(/[^a-z0-9]/gi, '-')}-details`
  return (
    <div className="grid gap-1.5">
      <div className="flex flex-wrap items-center gap-x-3 gap-y-2">
        <span className="inline-flex min-w-0 items-center gap-2 text-sm">
          <CalendarClock className="size-4 shrink-0 text-muted" aria-hidden />
          <span><span className="sr-only">{t('srName', { name })} </span><ScheduleText schedule={s} /></span>
        </span>
        <span className="flex flex-wrap gap-2">
          <Button size="sm" disabled={!can} title={locked} aria-label={t('change', { name })} onClick={() => setEditing(true)}>{t('changeShort')}</Button>
          {paused ? <Button size="sm" disabled={!can} title={locked} busy={save.isPending} busyLabel={t('common:busy.saving')} onClick={resume}>{t('resume')}</Button> : null}
          {runNow ? <Button size="sm" disabled={!can} title={locked} busy={run.isPending} busyLabel={t('common:busy.starting')} aria-label={t('run.label', { name })} onClick={startNow}><Play />{t('run.short')}</Button> : null}
        </span>
      </div>
      {next ? <p className={blocked && s.enabled ? 'text-meta text-warn' : 'text-meta text-muted'}>{next}</p> : null}
      {s.last_skip_reason ? <p className="text-meta text-warn">{t('skipped', { time: s.last_skip_at ? when(s.last_skip_at) : '', reason: s.last_skip_reason })}</p> : null}
      {s.upcoming.length > 1 || s.last_run_id || s.updated_by ? (
        <div className="grid gap-1.5">
          <ExpandToggle open={details} onToggle={() => setDetails(!details)} controls={panel} label={t('detailsOf', { name })}>{t('details')}</ExpandToggle>
          {details ? (
            <div id={panel} className="grid gap-2 border-l-2 border-rule pl-4 text-sm">
              {s.enabled && !paused && !blocked && s.upcoming.length ? (
                <div className="grid gap-0.5">
                  <p className="font-medium">{t('preview.title')}</p>
                  <ol className="grid gap-0.5">{s.upcoming.map((u) => <li key={u}>{when(u)}</li>)}</ol>
                </div>
              ) : null}
              {s.last_run_id ? <p>{s.last_due_at ? t('lastStart', { time: when(s.last_due_at) }) : null} <Link to={`/runs/${s.last_run_id}`} className="text-accent underline-offset-4 hover:underline">{t('run.openLast')}</Link></p> : null}
              {s.updated_by && s.updated_at ? <p className="text-meta text-muted">{t('changedBy', { who: s.updated_by, time: when(s.updated_at) })}</p> : null}
            </div>
          ) : null}
        </div>
      ) : null}
      {editing ? <EditDialog s={s} name={name} onClose={() => setEditing(false)} /> : null}
    </div>
  )
}

function EditDialog({ s, name, onClose }: { s: Schedule; name: string; onClose: () => void }) {
  const { t } = useTranslation('schedule')
  const save = useSaveSchedule(s.owner_key)
  const orgZone = orgZoneOf(s)
  const [draft, setDraft] = useState<Draft>(() => toDraft(s, orgZone))
  const change = (d: Draft) => { setDraft(d); save.reset() }
  function submit(e: React.FormEvent) {
    e.preventDefault()
    if (draft.enabled && intervalProblem(draft, s.limits)) return // the field says why; nothing is sent
    save.mutate(toSave(draft, orgZone), { onSuccess: () => { toast.success(t('saved', { name })); onClose() } })
  }
  const title = t('editTitle', { name })
  return (
    <Dialog open onOpenChange={(o) => { if (!o) onClose() }}>
      <DialogContent title={title}>
        <form noValidate onSubmit={submit} className="grid gap-4" aria-label={title}>
          <ScheduleFields schedule={s} draft={draft} onChange={change} error={save.error} idPrefix={`sched-${s.owner_key.replace(/[^a-z0-9]/gi, '-')}`} />
          {save.error && !fieldError(save.error) ? <p role="alert" className="text-sm text-danger">{errMsg(save.error)}</p> : null}
          <DialogFooter>
            <DialogClose asChild><Button type="button">{t('common:cancel')}</Button></DialogClose>
            <Button type="submit" variant="primary" busy={save.isPending} busyLabel={t('common:busy.saving')}>{t('common:save')}</Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  )
}
