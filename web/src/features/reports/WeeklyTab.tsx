import { useState } from 'react'
import { Link } from 'react-router'
import { useTranslation } from 'react-i18next'
import { toast } from 'sonner'
import { Printer, Send, Sparkles, X } from 'lucide-react'
import { Panel, Section } from '@/components/common/PageHeader'
import { DataTable } from '@/components/common/DataTable'
import { EmptyState, QueryState } from '@/components/common/States'
import { Chip } from '@/components/common/StatusChip'
import { Button, buttonVariants } from '@/components/ui/button'
import { Dialog, DialogClose, DialogContent, DialogFooter } from '@/components/ui/dialog'
import { Field, Input, Select } from '@/components/ui/input'
import { Switch } from '@/components/ui/switch'
import { Label } from '@/components/ui/input'
import { fmtDateTime } from '@/lib/format'
import { useCan, useMe } from '@/lib/session'
import { useChannels } from '@/features/notify/api'
import { useHistory, useSaveSchedule, useSchedule, useSendWeekly, useWeekly, useWeeklyAi } from './api'
import { WeeklyDocument } from './WeeklyDocument'
import { ActionError } from './parts'
import type { HistoryEntry, Schedule, Weekday } from './types'

const DAYS: Weekday[] = [1, 2, 3, 4, 5, 6, 7]
const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/

export default function WeeklyTab() {
  return (
    <>
      <Preview />
      <ScheduleSection />
      <HistorySection />
    </>
  )
}

function Preview() {
  const { t } = useTranslation('reports')
  const weekly = useWeekly()
  const { data: me } = useMe()
  const sched = useSchedule()
  const operator = useCan('operator')
  const ai = useWeeklyAi()
  const send = useSendWeekly()
  const [confirm, setConfirm] = useState(false)
  const needRole = operator ? undefined : t('common:needRole', { role: t('common:role.operator') })
  const recipients = sched.data?.recipients ?? []
  const c = weekly.data?.report.counts
  const noData = !!c && c.devices === 0 && c.open_confirmed + c.open_suspected === 0 && c.new_findings === 0 && c.resolved === 0
  return (
    <Section id="rep-preview" title={t('weekly.preview.title')} description={t('weekly.preview.description')} stories={['S-REP-1']}
      actions={weekly.data && !noData ? (
        <>
          <Button onClick={() => ai.mutate(undefined, { onSuccess: () => toast.success(t('weekly.ai.done')) })} disabled={!operator || !weekly.data.ai_available || ai.isPending} title={needRole ?? (weekly.data.ai_available ? undefined : t('weekly.ai.unavailable'))}><Sparkles aria-hidden />{ai.isPending ? t('weekly.ai.working') : t('weekly.ai.button')}</Button>
          <Link to="/reports/print/weekly" className={buttonVariants({ variant: 'secondary' })}><Printer aria-hidden />{t('print.button')}</Link>
          <Button variant="primary" onClick={() => setConfirm(true)} disabled={!operator} title={needRole}><Send aria-hidden />{t('weekly.send.button')}</Button>
        </>
      ) : null}>
      <ActionError error={ai.error} />
      <QueryState query={weekly}>
        {(w) => noData
          ? <EmptyState title={t('weekly.empty.title')} action={<Link to="/devices" className={buttonVariants({ variant: 'primary' })}>{t('weekly.empty.cta')}</Link>}>{t('weekly.empty.body')}</EmptyState>
          : <Panel className="p-6"><WeeklyDocument report={w.report} org={me?.org ?? ''} /></Panel>}
      </QueryState>
      <Dialog open={confirm} onOpenChange={setConfirm}>
        <DialogContent title={t('weekly.send.title')} description={recipients.length ? t('weekly.send.body', { count: recipients.length }) : t('weekly.send.noRecipients')}>
          {recipients.length ? <ul className="ml-5 list-disc text-sm">{recipients.map((e) => <li key={e}>{e}</li>)}</ul> : null}
          <p className="text-[13px] text-muted">{t('weekly.send.flow')}</p>
          <ActionError error={send.error} />
          <DialogFooter>
            <DialogClose asChild><Button>{t('common:cancel')}</Button></DialogClose>
            <Button variant="primary" disabled={send.isPending || recipients.length === 0} onClick={() => send.mutate(undefined, { onSuccess: () => { setConfirm(false); toast.success(t('weekly.send.sent')) } })}>{send.isPending ? t('weekly.send.sending') : t('weekly.send.confirm')}</Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </Section>
  )
}

function ScheduleSection() {
  const { t } = useTranslation('reports')
  const sched = useSchedule()
  const admin = useCan('admin')
  return (
    <Section id="rep-schedule" title={t('weekly.schedule.title')} description={t('weekly.schedule.description')} stories={['S-REP-1']}>
      <QueryState query={sched}>{(s) => admin ? <ScheduleWithChannels s={s} /> : <ScheduleForm s={s} noChannel={false} />}</QueryState>
    </Section>
  )
}

/** Only an admin can read the channels (S-REP-1: the weekly mail leaves through the email channel, so warn when none is on). */
function ScheduleWithChannels({ s }: { s: Schedule }) {
  const ch = useChannels({ retry: false })
  const noChannel = !!ch.data && !ch.data.channels.some((c) => c.type === 'email' && c.configured && c.enabled)
  return <ScheduleForm s={s} noChannel={noChannel} />
}

function ScheduleForm({ s, noChannel }: { s: Schedule; noChannel: boolean }) {
  const { t } = useTranslation('reports')
  const admin = useCan('admin')
  const save = useSaveSchedule()
  const [enabled, setEnabled] = useState(s.enabled)
  const [day, setDay] = useState<Weekday>(s.day)
  const [hour, setHour] = useState(s.hour)
  const [rec, setRec] = useState(s.recipients)
  const [email, setEmail] = useState('')
  const [emailErr, setEmailErr] = useState('')
  const reason = admin ? undefined : t('common:needRole', { role: t('common:role.admin') })

  function submit(e: React.FormEvent) {
    e.preventDefault()
    if (email.trim() !== '') { setEmailErr(t('weekly.schedule.pending')); return }
    if (enabled && rec.length === 0) { setEmailErr(t('weekly.schedule.needRecipient')); return }
    save.mutate({ enabled, day, hour, recipients: rec }, { onSuccess: () => toast.success(t('weekly.schedule.saved')) })
  }
  function add() {
    const e = email.trim().toLowerCase()
    if (!EMAIL_RE.test(e)) { setEmailErr(t('weekly.schedule.badEmail')); return }
    if (rec.includes(e)) { setEmailErr(t('weekly.schedule.dupEmail')); return }
    setRec([...rec, e]); setEmail(''); setEmailErr('')
  }
  return (
    <form noValidate className="grid max-w-2xl gap-4" onSubmit={submit}>
      <div className="flex items-center gap-3">
        <Switch id="rep-enabled" checked={enabled} onCheckedChange={setEnabled} disabled={!admin} title={reason} />
        <Label htmlFor="rep-enabled">{t('weekly.schedule.enabled')}</Label>
      </div>
      <div className="grid gap-4 sm:grid-cols-2">
        <Field label={t('weekly.schedule.day')} htmlFor="rep-day">
          <Select id="rep-day" value={day} onChange={(e) => setDay(Number(e.target.value))} disabled={!admin} title={reason}>{DAYS.map((d) => <option key={d} value={d}>{t(`weekly.schedule.days.${d}`)}</option>)}</Select>
        </Field>
        <Field label={t('weekly.schedule.hour')} htmlFor="rep-hour">
          <Select id="rep-hour" value={hour} onChange={(e) => setHour(Number(e.target.value))} disabled={!admin} title={reason}>{Array.from({ length: 24 }, (_, h) => <option key={h} value={h}>{`${String(h).padStart(2, '0')}:00`}</option>)}</Select>
        </Field>
      </div>
      <div className="grid gap-2">
        <Field label={t('weekly.schedule.recipients')} htmlFor="rep-email" hint={t('weekly.schedule.recipientsHint')} error={emailErr || undefined}>
          <div className="flex gap-2">
            <Input id="rep-email" type="email" value={email} onChange={(e) => { setEmail(e.target.value); setEmailErr('') }} onKeyDown={(e) => { if (e.key === 'Enter') { e.preventDefault(); add() } }} disabled={!admin} aria-invalid={emailErr ? true : undefined} aria-describedby={emailErr ? 'rep-email-error' : 'rep-email-hint'} placeholder="name@company.com" />
            <Button onClick={add} disabled={!admin || email.trim() === ''} title={reason}>{t('weekly.schedule.add')}</Button>
          </div>
        </Field>
        {rec.length ? (
          <ul className="flex flex-wrap gap-2" aria-label={t('weekly.schedule.list')}>
            {rec.map((e) => <li key={e} className="inline-flex items-center gap-1 rounded-md border border-rule bg-surface py-0.5 pl-2 pr-1 text-sm">{e}<button type="button" className="rounded p-1 text-muted hover:bg-sunken hover:text-ink disabled:opacity-50" disabled={!admin} aria-label={t('weekly.schedule.remove', { email: e })} onClick={() => setRec(rec.filter((x) => x !== e))}><X className="size-3.5" aria-hidden /></button></li>)}
          </ul>
        ) : <p className="text-sm text-muted">{t('weekly.schedule.noRecipients')}</p>}
      </div>
      {enabled && noChannel ? (
        <p role="alert" className="rounded-md border border-warn/50 bg-warn-soft px-3 py-2 text-[13px]">{t('weekly.schedule.noChannel')} <Link to="/settings/channels" className="text-accent underline-offset-4 hover:underline">{t('weekly.schedule.setupChannel')}</Link></p>
      ) : null}
      <p className="text-[13px] text-muted">{s.next_run && s.enabled && !noChannel ? t('weekly.schedule.next', { time: fmtDateTime(s.next_run) }) : t('weekly.schedule.off')} {t('weekly.schedule.channel')}</p>
      <ActionError error={save.error} />
      <div><Button type="submit" variant="primary" disabled={!admin || save.isPending} title={reason}>{save.isPending ? t('weekly.schedule.saving') : t('common:save')}</Button></div>
    </form>
  )
}

function HistorySection() {
  const { t } = useTranslation('reports')
  const hist = useHistory()
  type Row = Omit<HistoryEntry, 'report'>
  return (
    <Section id="rep-history" title={t('weekly.history.title')} description={t('weekly.history.description')} stories={['S-REP-1']}>
      <QueryState query={hist}>
        {(h) => h.items.length === 0 ? <EmptyState title={t('weekly.history.empty')}>{t('weekly.history.emptyBody')}</EmptyState> : (
          <DataTable<Row> caption={t('weekly.history.caption')} data={h.items} initialSort={[{ id: 'ts', desc: true }]}
            columns={[
              { id: 'ts', header: t('weekly.history.col.time'), accessorKey: 'ts', cell: ({ getValue }: { getValue: () => unknown }) => fmtDateTime(getValue() as string) },
              { id: 'trigger', header: t('weekly.history.col.trigger'), accessorFn: (r: Row) => t(`weekly.history.trigger.${r.trigger}`) },
              { id: 'to', header: t('weekly.history.col.to'), accessorFn: (r: Row) => t('weekly.history.people', { count: r.recipients.length }), cell: ({ row }: { row: { original: Row } }) => <span title={row.original.recipients.join(', ')}>{t('weekly.history.people', { count: row.original.recipients.length })}</span> },
              { id: 'status', header: t('weekly.history.col.status'), accessorKey: 'status', cell: ({ row }: { row: { original: Row } }) => row.original.status === 'sent' ? <Chip tone="ok">{t('weekly.history.sent')}</Chip> : <span className="grid gap-1"><Chip tone="warn">{t('weekly.history.failed')}</Chip><span className="max-w-xs whitespace-normal text-[12px] text-muted">{row.original.error}</span></span> },
              { id: 'open', header: t('weekly.history.col.open'), enableSorting: false, cell: ({ row }: { row: { original: Row } }) => <Link to={`/reports/print/weekly/${row.original.id}`} className="text-accent underline-offset-4 hover:underline">{t('weekly.history.open')}</Link> },
            ]} />
        )}
      </QueryState>
    </Section>
  )
}
