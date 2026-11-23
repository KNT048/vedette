import { Link } from 'react-router'
import { useTranslation } from 'react-i18next'
import { toast } from 'sonner'
import { Section } from '@/components/common/PageHeader'
import { DataTable, type ColumnDef } from '@/components/common/DataTable'
import { EmptyState, QueryState } from '@/components/common/States'
import { Chip } from '@/components/common/StatusChip'
import { BusyNote } from '@/components/common/BusyNote'
import { Button } from '@/components/ui/button'
import { ApiError } from '@/lib/api'
import { fmtDateTime } from '@/lib/format'
import { useCan } from '@/lib/session'
import { useHistory, useResend, useSendNow } from './api'
import { NotSentFix, waitingReason } from './shared'
import type { HistoryItem, UnsentNotice } from './types'

/** The vulnerability alerts of the last days that no channel delivered, each with the box's sentence of why and, for an admin, where to
 *  fix it: a notice is never missing without a reason on this page. */
function NotSentNotices({ rows, days }: { rows: UnsentNotice[]; days: number }) {
  const { t } = useTranslation('notify')
  const admin = useCan('admin')
  const can = useCan('operator')
  const send = useSendNow()
  // One that will not go out by itself can be sent now, to every channel that is on (the box refuses when its findings are handled since).
  const now = (r: UnsentNotice) => (waitingReason(r.not_sent) ? null : (
    <Button size="sm" disabled={!can || send.isPending} busy={send.isPending && send.variables === r.id} busyLabel={t('common:busy.sending')}
      title={can ? t('history.notSent.sendNowInfo') : t('common:needRole', { role: t('common:role.operator') })} aria-label={t('history.notSent.sendNowFor', { what: r.what })}
      onClick={() => send.mutate(r.id, { onSuccess: () => toast.success(t('history.notSent.sendNowOk')), onError: (e) => toast.error(e instanceof ApiError ? e.message : String(e)) })}>
      {t('history.notSent.sendNow')}
    </Button>
  ))
  const why = (r: UnsentNotice) => (
    <div className="grid justify-items-start gap-1">
      <Chip tone={waitingReason(r.not_sent) ? 'accent' : 'warn'}>{t(waitingReason(r.not_sent) ? 'history.notSent.waiting' : 'history.notSent.notSent')}</Chip>
      <span className="min-w-[10rem] max-w-[48ch] text-meta">{r.not_sent.text}</span>
      <NotSentFix notSent={r.not_sent} admin={admin} />
      {now(r)}
    </div>
  )
  const what = (r: UnsentNotice) => <Link to={r.link} className="text-accent underline-offset-4 hover:underline">{r.what}</Link>
  const columns: ColumnDef<UnsentNotice>[] = [
    { id: 'time', header: t('history.col.time'), accessorFn: (r) => r.at, cell: ({ row: { original: r } }) => <span className="whitespace-nowrap">{fmtDateTime(r.at)}</span> },
    { id: 'what', header: t('history.col.what'), accessorFn: (r) => r.what, cell: ({ row }) => what(row.original) },
    { id: 'result', header: t('history.col.result'), accessorFn: (r) => r.not_sent.reason, cell: ({ row }) => why(row.original) },
  ]
  const mobileRow = (r: UnsentNotice) => (
    <div className="grid gap-1.5 text-sm">
      {what(r)}
      <p className="text-meta text-muted">{fmtDateTime(r.at)}</p>
      {why(r)}
    </div>
  )
  return (
    <div className="mb-6 grid gap-2">
      <h3 className="text-base font-semibold">{t('history.notSent.title')}</h3>
      {rows.length === 0 ? <p className="text-meta text-muted">{t('history.notSent.none', { days })}</p> : <>
        <p className="max-w-3xl text-meta text-muted">{t('history.notSent.description', { days })}</p>
        <DataTable urlKey="notify-not-sent" caption={t('history.notSent.caption')} data={rows} columns={columns} mobileRow={mobileRow} initialSort={[{ id: 'time', desc: true }]} />
      </>}
    </div>
  )
}

/** Settings, Alert channels, History: every message sent, all kinds, and the vulnerability alerts that were not sent. */
export default function History() {
  const { t } = useTranslation('notify')
  const q = useHistory()
  const can = useCan('operator')
  const resend = useResend()
  const where = (r: HistoryItem) => t('history.via', { channel: t(`ch.${r.channel}`), to: r.to })
  const what = (r: HistoryItem) => <div className="grid"><Link to={r.link} className="text-accent underline-offset-4 hover:underline">{r.what}</Link><span className="text-caption text-muted">{t(`history.kind.${r.kind}`)}</span></div>
  const result = (r: HistoryItem) => (
    <div className="grid justify-items-start gap-1">{r.ok ? <Chip tone="ok">{t('history.ok')}</Chip> : r.delayed ? <Chip tone="accent">{t('history.delayed')}</Chip> : <Chip tone="warn">{t('history.failed')}</Chip>}{r.error ? <span className="min-w-[10rem] max-w-[48ch] text-meta">{r.error}</span> : null}</div>
  )
  // A delayed message is sent again by the box itself once the provider's wait is over: no Send again.
  const again = (r: HistoryItem) => (r.delayed ? null : <>
    <Button size="sm" disabled={!can || resend.isPending} busy={resend.isPending && resend.variables === r.id} busyLabel={t('common:busy.sending')} title={can ? undefined : t('common:needRole', { role: t('common:role.operator') })} aria-label={t('history.resendFor', { channel: t(`ch.${r.channel}`) })}
      onClick={() => resend.mutate(r.id, { onSuccess: (res) => { if (res.ok) toast.success(t('history.resendOk', { channel: t(`ch.${r.channel}`) })); else toast.error(res.error ?? t('history.failed')) }, onError: (e) => toast.error(e instanceof ApiError ? e.message : String(e)) })}>
      {t('history.resend')}
    </Button>
    {/* The box sends the message again through the channel and waits for its answer */}
    <BusyNote busy={resend.isPending && resend.variables === r.id}>{t('history.resendWaiting')}</BusyNote>
  </>)
  // Three columns, the channel and its recipients under the time and Send again under the result, so nothing is cut off in the
  // ~730 px content column of a 1280 px screen (app sidebar + settings nav) nor at 1024 px; under 768 px each message is a card.
  //
  const columns: ColumnDef<HistoryItem>[] = [
    { id: 'time', header: t('history.col.time'), accessorFn: (r) => r.at, cell: ({ row: { original: r } }) => (
      <div className="grid"><span className="whitespace-nowrap">{fmtDateTime(r.at)}</span><span className="max-w-[12rem] break-words text-caption text-muted">{where(r)}</span></div>
    ) },
    { id: 'what', header: t('history.col.what'), accessorFn: (r) => r.what, cell: ({ row }) => what(row.original) },
    { id: 'result', header: t('history.col.result'), accessorFn: (r) => Number(r.ok), cell: ({ row }) => <div className="grid justify-items-start gap-2">{result(row.original)}{again(row.original)}</div> },
  ]
  const mobileRow = (r: HistoryItem) => (
    <div className="grid gap-1.5 text-sm">
      {what(r)}
      <p className="break-words text-meta text-muted">{fmtDateTime(r.at)}, {where(r)}</p>
      {result(r)}
      <div>{again(r)}</div>
    </div>
  )
  return (
    <Section id="history" title={t('history.title')} description={t('history.description')} info={<><p>{t('history.metaInfo')}</p><p>{t('history.retention')}</p></>}>
      <QueryState query={q}>
        {(d) => (
          <>
            <p className="mb-3 max-w-3xl text-meta text-muted">{d.suppressed.count > 0 ? t('history.meta', { count: d.suppressed.count, days: d.suppressed.days }) : t('history.metaNone', { days: d.suppressed.days })}</p>
            <NotSentNotices rows={d.not_sent} days={d.suppressed.days} />
            {d.items.length === 0 ? <EmptyState title={t('history.emptyTitle')} info={t('history.emptyBodyInfo')}>{t('history.emptyBody')}</EmptyState>
              : <DataTable urlKey="notify-history" caption={t('history.caption')} data={d.items} columns={columns} mobileRow={mobileRow} initialSort={[{ id: 'time', desc: true }]} />}
          </>
        )}
      </QueryState>
    </Section>
  )
}
