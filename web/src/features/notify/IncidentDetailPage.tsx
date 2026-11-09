import { useState } from 'react'
import { Link, useParams } from 'react-router'
import { useTranslation } from 'react-i18next'
import { toast } from 'sonner'
import { RotateCcw } from 'lucide-react'
import { KeyValue, PageHeader, Section } from '@/components/common/PageHeader'
import { DataTable, type ColumnDef } from '@/components/common/DataTable'
import { EmptyState, QueryState, RequireModule } from '@/components/common/States'
import { Chip, SeverityChip } from '@/components/common/StatusChip'
import { Button } from '@/components/ui/button'
import { Field, Textarea } from '@/components/ui/input'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs'
import { ApiError } from '@/lib/api'
import { fmtDateTime } from '@/lib/format'
import { useCan } from '@/lib/session'
import { useIncident, useSetStatus } from './api'
import { IncidentStatusChip, MessagePreview } from './shared'
import type { IncidentDetail, IncidentStatus, SendRecord } from './types'

const errMsg = (e: unknown) => (e instanceof ApiError ? e.message : String(e))
const link = 'text-accent underline-offset-4 hover:underline'

function Handle({ d }: { d: IncidentDetail }) {
  const { t } = useTranslation('notify')
  const can = useCan('operator')
  const set = useSetStatus()
  const [note, setNote] = useState('')
  const a = d.incident
  const need = can ? undefined : t('common:needRole', { role: t('common:role.operator') })
  const go = (status: IncidentStatus) => set.mutate({ id: a.id, status, note }, { onSuccess: () => { setNote(''); toast.success(t('detail.updated')) }, onError: (e) => toast.error(errMsg(e)) })
  return (
    <Section id="handle" title={t('detail.handleTitle')}>
      <div className="grid max-w-xl gap-3">
        {a.status !== 'resolved' ? (
          <>
            {a.status === 'acknowledged' ? <p className="text-sm">{t('detail.handledBy', { status: t('incidents.status.acknowledged'), user: a.handled_by ?? '', time: fmtDateTime(a.handled_at) })} {a.note ? t('detail.noteShown', { note: a.note }) : null}</p> : null}
            <Field label={t('detail.note')} htmlFor="al-note"><Textarea id="al-note" value={note} maxLength={500} onChange={(e) => setNote(e.target.value)} placeholder={t('detail.notePlaceholder')} disabled={!can} /></Field>
            <div className="flex flex-wrap gap-2">
              {a.status === 'new' ? <Button disabled={!can || set.isPending} title={need} onClick={() => go('acknowledged')}>{t('detail.acknowledge')}</Button> : null}
              <Button variant="primary" disabled={!can || set.isPending} title={need} onClick={() => go('resolved')}>{t('detail.resolve')}</Button>
              {a.status === 'acknowledged' ? <Button disabled={!can || set.isPending} title={need} onClick={() => go('new')}><RotateCcw />{t('detail.reopen')}</Button> : null}
            </div>
          </>
        ) : (
          <>
            <p className="text-sm">{t('detail.handledBy', { status: t('incidents.status.resolved'), user: a.handled_by ?? '', time: fmtDateTime(a.handled_at) })} {a.note ? t('detail.noteShown', { note: a.note }) : null}</p>
            <div><Button disabled={!can || set.isPending} title={need} onClick={() => go('new')}><RotateCcw />{t('detail.reopen')}</Button></div>
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
  return (
    <QueryState query={q}>
      {(d) => {
        const a = d.incident
        const log: ColumnDef<SendRecord>[] = [
          { id: 'time', header: t('detail.log.time'), accessorFn: (r) => r.at, cell: ({ row }) => <span className="whitespace-nowrap">{fmtDateTime(row.original.at)}</span> },
          { id: 'channel', header: t('detail.log.channel'), accessorFn: (r) => r.channel, cell: ({ row }) => t(`ch.${row.original.channel}`) },
          { id: 'to', header: t('detail.log.to'), accessorFn: (r) => r.to },
          { id: 'result', header: t('detail.log.result'), accessorFn: (r) => Number(r.ok), cell: ({ row: { original: r } }) => (
            <div className="grid gap-1">{r.ok ? <Chip tone="ok">{t('detail.ok')}</Chip> : <Chip tone="warn">{t('detail.failed')}</Chip>}{r.error ? <span className="max-w-[48ch] text-[13px]">{r.error}</span> : null}</div>
          ) },
        ]
        return (
          <>
            <p className="mb-3 text-sm"><Link to="/incidents" className={link}>{t('detail.back')}</Link></p>
            <PageHeader title={a.title} meta={t('detail.meta', { time: fmtDateTime(a.first_seen) })} stories={['S-ALERT-3']}
              actions={<Link to={`/response?incident=${encodeURIComponent(a.id)}`} className="inline-flex h-9 items-center rounded-md border border-rule px-3 text-sm font-medium text-accent hover:bg-sunken">{t('detail.respond')}</Link>} />
            <Section id="summary" title={t('detail.summary')}>
              <KeyValue items={[
                { label: t('detail.kind'), value: t(`incidents.kind.${a.kind}`) },
                { label: t('detail.severity'), value: <SeverityChip severity={a.severity} /> },
                { label: t('detail.status'), value: <IncidentStatusChip status={a.status} /> },
                { label: t('detail.devices'), value: <span className="flex flex-wrap gap-x-3">{a.devices.map((x) => <Link key={x.id} to={`/devices/${x.id}`} className={link}>{x.name}</Link>)}</span> },
                { label: t('detail.firstSeen'), value: fmtDateTime(a.first_seen) },
                { label: t('detail.lastSeen'), value: fmtDateTime(a.last_seen) },
                { label: t('detail.count'), value: t('incidents.times', { count: a.count }) },
                { label: t('detail.origin'), value: <Link to={a.link} className={link}>{t(`detail.open.${a.kind}`)}</Link> },
                { label: t('detail.what'), value: a.what },
                { label: t('detail.action'), value: a.action },
              ]} />
            </Section>
            <Section id="sent" title={t('detail.sentTitle')} description={t('detail.sentDescription')}>
              {d.previews.length === 0 ? (
                <EmptyState title={t('detail.noSendsTitle')} action={<Link to="/settings/channels" className={link}>{t('incidents.setupChannels')}</Link>}>{t('detail.noSendsBody')}</EmptyState>
              ) : (
                <Tabs defaultValue={d.previews[0]!.channel}>
                  <TabsList>{d.previews.map((p) => <TabsTrigger key={p.channel} value={p.channel}>{t(`ch.${p.channel}`)}</TabsTrigger>)}</TabsList>
                  {d.previews.map((p) => <TabsContent key={p.channel} value={p.channel}><MessagePreview preview={p} label={t(`ch.${p.channel}`)} /></TabsContent>)}
                </Tabs>
              )}
            </Section>
            <Section id="log" title={t('detail.logTitle')}>
              {a.sends.length ? <DataTable caption={t('detail.logCaption')} data={a.sends} columns={log} initialSort={[{ id: 'time', desc: true }]} /> : <EmptyState title={t('detail.noSendsTitle')} />}
            </Section>
            <Handle d={d} />
          </>
        )
      }}
    </QueryState>
  )
}

export default function IncidentDetailPage() {
  return <RequireModule module="notify"><Content /></RequireModule>
}
