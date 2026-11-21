import { useState } from 'react'
import { Link } from 'react-router'
import { useTranslation } from 'react-i18next'
import { toast } from 'sonner'
import { CalendarClock, Printer, Send } from 'lucide-react'
import { BusyNote } from '@/components/common/BusyNote'
import { EmptyState, QueryState } from '@/components/common/States'
import { useSchedule } from '@/components/schedule/api'
import { fmtInZone } from '@/components/schedule/ScheduleFields'
import { Button, buttonVariants } from '@/components/ui/button'
import { Dialog, DialogClose, DialogContent, DialogFooter } from '@/components/ui/dialog'
import { useCan, useMe } from '@/lib/session'
import { useDefinition, useReportDocument, useSendReport } from './api'
import { ActionError } from './parts'
import { SecurityReport } from './SecurityReport'
import type { ReportDefinition, ReportDocument } from './types'

/** Nothing to report: no finding open, new or handled, and nothing seen from outside or detected. */
export function emptyReport(d: ReportDocument) {
  const s = d.summary
  return !!s && s.open_now === 0 && s.new === 0 && s.handled === 0 && !d.exposure?.targets.length && !d.detections?.by_kind.length
}

/** The sheet the report is drawn on: an A4 page wide on screen; the only thing printed (index.css, .print-report). */
export function Paper({ children }: { children: React.ReactNode }) {
  return <div className="print-report mx-auto w-full max-w-[210mm] rounded-md border border-rule bg-surface p-5 sm:p-10">{children}</div>
}

export default function ReportTab() {
  const { t } = useTranslation('reports')
  const doc = useReportDocument()
  const def = useDefinition()
  const { data: me } = useMe()
  return (
    <QueryState query={doc}>
      {(d) => emptyReport(d) ? (
        <EmptyState title={t('report.empty.title')} action={<Link to="/devices" className={buttonVariants({ variant: 'primary' })}>{t('report.empty.cta')}</Link>}>
          {t('report.empty.body')}
        </EmptyState>
      ) : (
        <div className="grid gap-4">
          <div role="toolbar" aria-label={t('report.actions')} className="no-print mx-auto flex w-full max-w-[210mm] flex-wrap items-center justify-between gap-3">
            {def.data ? <NextSend def={def.data} /> : <span />}
            <div className="flex flex-wrap items-center gap-2">
              <Button onClick={() => window.print()}><Printer aria-hidden />{t('print.button')}</Button>
              {def.data ? <SendNow recipients={def.data.recipients} /> : null}
            </div>
          </div>
          <Paper><SecurityReport doc={d} org={me?.org ?? ''} /></Paper>
        </div>
      )}
    </QueryState>
  )
}

/** When the report goes out next and to how many people, with the way to change it. */
function NextSend({ def }: { def: ReportDefinition }) {
  const { t } = useTranslation('reports')
  const q = useSchedule(def.schedule_key)
  const s = q.data
  const paused = !!s?.paused_until && Date.parse(s.paused_until) > Date.now()
  const next = s && s.enabled && !paused && def.recipients.length ? s.upcoming[0] : undefined
  return (
    <p className="inline-flex flex-wrap items-center gap-x-2 gap-y-1 text-meta text-muted">
      <CalendarClock aria-hidden className="size-4 shrink-0" />
      <span>{!s ? '' : next ? t('report.next', { time: fmtInZone(next, s.zone), recipients: t('report.nextRecipients', { count: def.recipients.length }) }) : t('report.off')}</span>
      <Link to="/reports?tab=settings" className="text-accent underline-offset-4 hover:underline">{t('report.openSettings')}</Link>
    </p>
  )
}

function SendNow({ recipients }: { recipients: string[] }) {
  const { t } = useTranslation('reports')
  const operator = useCan('operator')
  const send = useSendReport()
  const [open, setOpen] = useState(false)
  // No Send with nobody to send to: one line says what is missing instead.
  if (recipients.length === 0) return <span className="text-meta text-muted">{t('report.send.noRecipients')}</span>
  const needRole = operator ? undefined : t('common:needRole', { role: t('common:role.operator') })
  return (
    <>
      <Button variant="primary" onClick={() => { send.reset(); setOpen(true) }} disabled={!operator} title={needRole}><Send aria-hidden />{t('report.send.button')}</Button>
      <Dialog open={open} onOpenChange={setOpen}>
        <DialogContent title={t('report.send.title')} description={t('report.send.body', { count: recipients.length })}>
          <ul className="ml-5 list-disc text-sm">{recipients.map((e) => <li key={e}>{e}</li>)}</ul>
          <BusyNote id="report-send-wait" busy={send.isPending}>{t('common:busy.sending')}</BusyNote>
          <ActionError error={send.error} />
          <DialogFooter>
            <DialogClose asChild><Button>{t('common:cancel')}</Button></DialogClose>
            <Button variant="primary" busy={send.isPending} busyLabel={t('common:busy.sending')} aria-describedby="report-send-wait"
              onClick={() => send.mutate(undefined, { onSuccess: () => { setOpen(false); toast.success(t('report.send.sent')) } })}>{t('report.send.confirm')}</Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </>
  )
}
