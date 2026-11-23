import { useState } from 'react'
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
import { Field, Textarea } from '@/components/ui/input'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs'
import { ApiError } from '@/lib/api'
import { fmtDateTime } from '@/lib/format'
import { useCan } from '@/lib/session'
import { notOffered } from '@/lib/v1'
import { useIncident, useSetStatus } from './api'
import { IncidentStatusChip, MessagePreview, NotSentFix, kindKey } from './shared'
import { knownKind } from './types'
import { useNewChannel } from './NewChannel'
import type { IncidentDetail, IncidentStatus, SendRecord } from './types'

const errMsg = (e: unknown) => (e instanceof ApiError ? e.message : String(e))
const link = 'text-accent underline-offset-4 hover:underline'

/** Acknowledge, resolve or reopen; Respond (the response module) is one more way to handle an open incident, so it sits here too. */
function Handle({ d, respond }: { d: IncidentDetail; respond: boolean }) {
  const { t } = useTranslation('notify')
  const can = useCan('operator')
  const set = useSetStatus()
  const [note, setNote] = useState('')
  const a = d.incident
  const need = can ? undefined : t('common:needRole', { role: t('common:role.operator') })
  const go = (status: IncidentStatus) => set.mutate({ id: a.id, status, note }, { onSuccess: () => { setNote(''); toast.success(t('detail.updated')) }, onError: (e) => toast.error(errMsg(e)) })
  return (
    <Section id="handle" title={t('detail.handleTitle')}
      actions={respond && a.status !== 'resolved' ? <Button asChild><Link to={`/response?incident=${encodeURIComponent(a.id)}`}>{t('detail.respond')}</Link></Button> : undefined}>
      <div className="grid max-w-xl gap-3">
        {a.status !== 'resolved' ? (
          <>
            {a.status === 'acknowledged' ? <p className="text-sm">{t('detail.handledBy', { status: t('incidents.status.acknowledged'), user: a.handled_by ?? '', time: fmtDateTime(a.handled_at) })} {a.note ? t('detail.noteShown', { note: a.note }) : null}</p> : null}
            <Field label={t('detail.note')} htmlFor="al-note"><Textarea id="al-note" value={note} maxLength={500} onChange={(e) => setNote(e.target.value)} placeholder={t('detail.notePlaceholder')} disabled={!can} /></Field>
            <div className="flex flex-wrap gap-2">
              {a.status === 'new' ? <Button disabled={!can || set.isPending} busy={set.isPending && set.variables?.status === 'acknowledged'} busyLabel={t('detail.acknowledging')} title={need} onClick={() => go('acknowledged')}>{t('detail.acknowledge')}</Button> : null}
              <Button variant="primary" disabled={!can || set.isPending} busy={set.isPending && set.variables?.status === 'resolved'} busyLabel={t('detail.resolving')} title={need} onClick={() => go('resolved')}>{t('detail.resolve')}</Button>
              {a.status === 'acknowledged' ? <Button disabled={!can || set.isPending} busy={set.isPending && set.variables?.status === 'new'} busyLabel={t('detail.reopening')} title={need} onClick={() => go('new')}><RotateCcw />{t('detail.reopen')}</Button> : null}
            </div>
          </>
        ) : (
          <>
            <p className="text-sm">{a.resolved_reason ? t('detail.closedBy', { reason: a.resolved_reason, time: fmtDateTime(a.handled_at) }) : t('detail.handledBy', { status: t('incidents.status.resolved'), user: a.handled_by ?? '', time: fmtDateTime(a.handled_at) })} {a.note ? t('detail.noteShown', { note: a.note }) : null}</p>
            <div><Button disabled={!can || set.isPending} busy={set.isPending && set.variables?.status === 'new'} busyLabel={t('detail.reopening')} title={need} onClick={() => go('new')}><RotateCcw />{t('detail.reopen')}</Button></div>
          </>
        )}
      </div>
    </Section>
  )
}

function Content() {
  const { t } = useTranslation('notify')
  const { id = '' } = useParams()
  const q = useIncident(id)
  const admin = useCan('admin') // the fix links open Settings, Alert channels: an admin's page
  const newChannel = useNewChannel()
  const respond = !notOffered('response') // Respond starts a new action: none while this build does not offer the response module, even on a box that has it on
  // docs/UI.md §3: the parent above the title, also while the incident loads or is missing, so the way back is always there.
  const crumbs = [{ label: t('nav.incidents'), to: '/incidents' }]
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
            <PageHeader breadcrumbs={crumbs} title={a.title} meta={t('detail.meta', { time: fmtDateTime(a.first_seen) })} stories={['S-ALERT-3']} />
            <Section id="summary" title={t('detail.summary')}>
              <Card>
              <KeyValue items={[
                { label: t('detail.kind'), value: t(kindKey(a)) },
                { label: t('detail.severity'), value: <SeverityBadge severity={a.severity} /> },
                { label: t('detail.status'), value: <IncidentStatusChip status={a.status} /> },
                { label: t('detail.devices'), value: <span className="flex flex-wrap gap-x-3">{a.devices.map((x) => <Link key={x.id} to={`/devices/${x.id}`} className={link}>{x.name}</Link>)}</span> },
                { label: t('detail.firstSeen'), value: fmtDateTime(a.first_seen) },
                { label: t('detail.lastSeen'), value: fmtDateTime(a.last_seen) },
                { label: t('detail.count'), value: t('incidents.times', { count: a.count }) },
                { label: t('detail.origin'), value: <Link to={a.link} className={link}>{t(`detail.open.${knownKind(a.kind)}`)}</Link> },
                { label: t('detail.what'), value: a.what },
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
                <Tabs defaultValue={d.previews[0]!.channel}>
                  <TabsList>{d.previews.map((p) => <TabsTrigger key={p.channel} value={p.channel}>{t(`ch.${p.channel}`)}</TabsTrigger>)}</TabsList>
                  {d.previews.map((p) => <TabsContent key={p.channel} value={p.channel}><MessagePreview preview={p} label={t(`ch.${p.channel}`)} /></TabsContent>)}
                </Tabs>
              )}
            </Section>
            <Section id="log" title={t('detail.logTitle')}>
              {a.not_sent?.reason === 'failed' ? <Notice tone="warn" title={a.not_sent.text} actions={<NotSentFix notSent={a.not_sent} admin={admin} />} /> : null}
              {a.sends.length ? <DataTable urlKey="incident-sends" caption={t('detail.logCaption')} data={a.sends} columns={log} initialSort={[{ id: 'time', desc: true }]} /> : <EmptyState title={t('detail.noSendsTitle')} />}
            </Section>
            <Handle d={d} respond={respond} />
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
