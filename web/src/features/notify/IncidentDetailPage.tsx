import { useRef, useState, type MouseEvent, type RefObject } from 'react'
import { Link, useParams } from 'react-router'
import { useTranslation } from 'react-i18next'
import { toast } from 'sonner'
import { RotateCcw } from 'lucide-react'
import { KeyValue, Notice, PageHeader, Section } from '@/components/common/PageHeader'
import { Breadcrumbs } from '@/components/common/Breadcrumbs'
import { Card } from '@/components/common/Card'
import { DataTable, type ColumnDef } from '@/components/common/DataTable'
import { EmptyState, QueryState, RequireModule } from '@/components/common/States'
import { Chip } from '@/components/common/StatusChip'
import { SeverityBadge } from '@/components/common/status'
import { Button } from '@/components/ui/button'
import { Dialog, DialogContent, DialogFooter } from '@/components/ui/dialog'
import { Field, Textarea } from '@/components/ui/input'
import { PageTabs } from '@/components/common/PageFrame'
import { ApiError } from '@/lib/api'
import { fmtDateTime } from '@/lib/format'
import { useCan } from '@/lib/session'
import { notOffered } from '@/lib/v1'
import { useIncident, useSetStatus } from './api'
import { IncidentStatusChip, MessagePreview, NotSentFix, kindKey } from './shared'
import { knownKind } from './types'
import { useNewChannel } from './NewChannel'
import type { IncidentDetail, SendRecord } from './types'

const errMsg = (e: unknown) => (e instanceof ApiError ? e.message : String(e))
const link = 'text-accent underline-offset-4 hover:underline'

/** The header's actions on an incident: Respond (the response module) and Acknowledge / Resolve, each of which asks for an optional
 *  note in a dialog, or Reopen. The state they led to is written in the Summary. */
function HandleActions({ d, respond }: { d: IncidentDetail; respond: boolean }) {
  const { t } = useTranslation('notify')
  const can = useCan('operator')
  const set = useSetStatus()
  const [asking, setAsking] = useState<'acknowledged' | 'resolved' | null>(null)
  const opener = useRef<HTMLButtonElement | null>(null)
  const a = d.incident
  const need = can ? undefined : t('common:needRole', { role: t('common:role.operator') })
  const ask = (s: 'acknowledged' | 'resolved') => (e: MouseEvent<HTMLButtonElement>) => { opener.current = e.currentTarget; setAsking(s) }
  const reopen = () => set.mutate({ id: a.id, status: 'new', note: '' }, { onSuccess: () => toast.success(t('detail.updated')), onError: (e) => toast.error(errMsg(e)) })
  const reopenButton = <Button disabled={!can || set.isPending} busy={set.isPending && set.variables?.status === 'new'} busyLabel={t('detail.reopening')} title={need} onClick={reopen}><RotateCcw />{t('detail.reopen')}</Button>
  return (
    <>
      {a.status === 'resolved' ? reopenButton : (
        <>
          {respond ? <Button asChild><Link to={`/response?incident=${encodeURIComponent(a.id)}`}>{t('detail.respond')}</Link></Button> : null}
          {a.status === 'acknowledged' ? reopenButton : null}
          {a.status === 'new' ? <Button disabled={!can} title={need} onClick={ask('acknowledged')}>{t('detail.acknowledge')}</Button> : null}
          <Button variant="primary" disabled={!can} title={need} onClick={ask('resolved')}>{t('detail.resolve')}</Button>
        </>
      )}
      <HandleDialog id={a.id} status={asking} onClose={() => setAsking(null)} opener={opener} />
    </>
  )
}

/** The note of an acknowledge or a resolve, asked in a dialog: the note is optional, the audit line is always written. */
function HandleDialog({ id, status, onClose, opener }: { id: string; status: 'acknowledged' | 'resolved' | null; onClose: () => void; opener: RefObject<HTMLButtonElement | null> }) {
  const { t } = useTranslation('notify')
  const set = useSetStatus()
  const [note, setNote] = useState('')
  const [was, setWas] = useState(status)
  if (status !== was) { setWas(status); if (status) setNote('') }
  const go = () => {
    if (!status) return
    set.mutate({ id, status, note }, { onSuccess: () => { onClose(); toast.success(t('detail.updated')) }, onError: (e) => toast.error(errMsg(e)) })
  }
  return (
    <Dialog open={status !== null} onOpenChange={(o) => { if (!o) onClose() }}>
      <DialogContent title={status ? t(`detail.dialog.${status}`) : ''} description={t('detail.dialog.description')} onCloseAutoFocus={(e) => { e.preventDefault(); opener.current?.focus() }}>
        <Field label={t('detail.note')} htmlFor="al-note"><Textarea id="al-note" value={note} maxLength={500} onChange={(e) => setNote(e.target.value)} placeholder={t('detail.notePlaceholder')} /></Field>
        <DialogFooter>
          <Button onClick={onClose}>{t('common:cancel')}</Button>
          <Button variant="primary" busy={set.isPending} busyLabel={t(status === 'resolved' ? 'detail.resolving' : 'detail.acknowledging')} onClick={go}>{status ? t(status === 'resolved' ? 'detail.resolve' : 'detail.acknowledge') : null}</Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}

/** Who handled the incident and when, with the note: one line of the Summary. */
function HandledLine({ a }: { a: IncidentDetail['incident'] }) {
  const { t } = useTranslation('notify')
  const who = a.status === 'resolved' && a.resolved_reason
    ? t('detail.closedBy', { reason: a.resolved_reason, time: fmtDateTime(a.handled_at) })
    : t('detail.handledBy', { status: t(`incidents.status.${a.status}`), user: a.handled_by ?? '', time: fmtDateTime(a.handled_at) })
  return <span>{who}{a.note ? ` ${t('detail.noteShown', { note: a.note })}` : ''}</span>
}

function Content() {
  const { t } = useTranslation('notify')
  const { id = '' } = useParams()
  const q = useIncident(id)
  const admin = useCan('admin') // the fix links open Settings, Alert channels: an admin's page
  const newChannel = useNewChannel()
  const respond = !notOffered('response') // Respond starts a new action: none while this build does not offer the response module, even on a box that has it on
  // docs/UI.md §3: the parent above the title, also while the incident loads or is missing, so the way back is always there.
  const crumbs = [{ label: t('common:shell.incidents'), to: '/incidents' }]
  return (
    <>
    {q.data ? null : <Breadcrumbs items={crumbs} />}
    <QueryState query={q}>
      {(d) => {
        const a = d.incident
        const log: ColumnDef<SendRecord>[] = [
          { id: 'time', header: t('detail.log.time'), accessorFn: (r) => r.at, cell: ({ row }) => <span className="whitespace-nowrap">{fmtDateTime(row.original.at)}</span> },
          { id: 'channel', header: t('detail.log.channel'), accessorFn: (r) => r.channel, cell: ({ row }) => t(`ch.${row.original.channel}`) },
          { id: 'to', header: t('detail.log.to'), accessorFn: (r) => r.to },
          { id: 'result', header: t('detail.log.result'), accessorFn: (r) => Number(r.ok), cell: ({ row: { original: r } }) => (
            <div className="grid gap-1">{r.ok ? <Chip tone="ok">{t('detail.ok')}</Chip> : r.delayed ? <Chip tone="accent">{t('history.delayed')}</Chip> : <Chip tone="warn">{t('detail.failed')}</Chip>}{r.error ? <span className="max-w-[48ch] text-meta">{r.error}</span> : null}</div>
          ) },
        ]
        return (
          <>
            <PageHeader breadcrumbs={crumbs} title={a.title} meta={t('detail.meta', { time: fmtDateTime(a.first_seen) })} stories={['S-ALERT-3']} actions={<HandleActions d={d} respond={respond} />} />
            <Section id="summary" title={t('detail.summary')}>
              <Card>
              <KeyValue items={[
                { label: t('detail.kind'), value: t(kindKey(a)) },
                { label: t('detail.severity'), value: <SeverityBadge severity={a.severity} /> },
                { label: t('detail.status'), value: <IncidentStatusChip status={a.status} /> },
                ...(a.status === 'new' ? [] : [{ label: t('detail.handled'), value: <HandledLine a={a} /> }]),
                { label: t('detail.devices'), value: <span className="flex flex-wrap gap-x-3">{a.devices.map((x) => <Link key={x.id} to={`/devices/${x.id}`} className={link}>{x.name}</Link>)}</span> },
                { label: t('detail.firstSeen'), value: fmtDateTime(a.first_seen) },
                { label: t('detail.lastSeen'), value: fmtDateTime(a.last_seen) },
                { label: t('detail.count'), value: t('incidents.times', { count: a.count }) },
                { label: t('detail.origin'), value: <Link to={a.link} className={link}>{t(`detail.open.${knownKind(a.kind)}`)}</Link> },
                { label: t('detail.what'), value: <span className="whitespace-pre-line">{a.what}</span> },
                { label: t('detail.action'), value: a.action },
              ]} />
              </Card>
            </Section>
            <Section id="sent" title={t('detail.sentTitle')} description={t('detail.sentDescription')}>
              {d.previews.length === 0 ? (
                a.not_sent ? (
                  // Why no channel has it, from the box's decision, and where to fix it
                  <EmptyState title={a.not_sent.reason === 'queued' || a.not_sent.reason === 'quiet_hours' ? t('detail.notYetTitle') : t('detail.noSendsTitle')} action={<NotSentFix notSent={a.not_sent} admin={admin} />}>{a.not_sent.text}</EmptyState>
                ) : <EmptyState title={t('detail.noSendsTitle')} action={newChannel.button(t('incidents.setupChannels'))} info={t('detail.noSendsBodyInfo')}>{t('detail.noSendsBody')}</EmptyState>
              ) : (
                <PageTabs label={t('detail.sentTitle')} tabs={d.previews.map((p) => ({ id: p.channel, label: t(`ch.${p.channel}`), panel: <MessagePreview preview={p} label={t(`ch.${p.channel}`)} /> }))} />
              )}
            </Section>
            <Section id="log" title={t('detail.logTitle')}>
              {a.not_sent?.reason === 'failed' ? <Notice tone="warn" title={a.not_sent.text} actions={<NotSentFix notSent={a.not_sent} admin={admin} />} /> : null}
              {a.sends.length ? <DataTable urlKey="incident-sends" caption={t('detail.logCaption')} data={a.sends} columns={log} initialSort={[{ id: 'time', desc: true }]} summary={t('history.summary', { count: a.sends.length })} /> : <EmptyState title={t('detail.noSendsTitle')} />}
            </Section>
          </>
        )
      }}
    </QueryState>
    {newChannel.dialogs}
    </>
  )
}

export default function IncidentDetailPage() {
  return <RequireModule module="notify" page><Content /></RequireModule>
}
