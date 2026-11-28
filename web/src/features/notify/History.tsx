import { Link, useSearchParams } from 'react-router'
import { useTranslation } from 'react-i18next'
import { toast } from 'sonner'
import { Section } from '@/components/common/PageHeader'
import { DataTable, type ColumnDef } from '@/components/common/DataTable'
import { EmptyState, QueryState } from '@/components/common/States'
import { Chip } from '@/components/common/StatusChip'
import { BusyNote } from '@/components/common/BusyNote'
import { Button } from '@/components/ui/button'
import { Select } from '@/components/ui/input'
import { ApiError } from '@/lib/api'
import { fmtDateTime } from '@/lib/format'
import { useCan } from '@/lib/session'
import { useHistory, useResend, useSendNow } from './api'
import { NotSentFix, waitingReason } from './shared'
import { CHANNEL_TYPES, type HistoryItem, type UnsentNotice } from './types'

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
    <Section id="not-sent" title={t('history.notSent.title')} description={rows.length === 0 ? undefined : t('history.notSent.description', { days })}>
      {rows.length === 0 ? <p className="text-meta text-muted">{t('history.notSent.none', { days })}</p>
        : <DataTable urlKey="notify-not-sent" caption={t('history.notSent.caption')} data={rows} columns={columns} mobileRow={mobileRow} initialSort={[{ id: 'time', desc: true }]}
          summary={t('history.notSent.summary', { count: rows.length })} />}
    </Section>
  )
}

/** The sent messages' list key in the URL (its search, page, size and sort). */
const SENT_KEY = 'notify-history'
const RESULTS = ['sent', 'failed', 'delayed'] as const
const KINDS = ['incident', 'vuln', 'approval'] as const
type Result = (typeof RESULTS)[number]
const resultOf = (r: HistoryItem): Result => (r.ok ? 'sent' : r.delayed ? 'delayed' : 'failed')
/** A filter value from the URL: one of the known values, else none (an old or hand-typed link shows every row). */
const pick = <V extends string>(values: readonly V[], v: string | null): V | '' => (values.includes(v as V) ? (v as V) : '')

/** The filters of the sent messages, kept in the URL (`?channel=email&result=failed&kind=vuln`), so a link (Home's failed count, a
 *  first-run summary that failed) opens the list already narrowed, and back and reload keep it. */
function useFilters() {
  const [params, setParams] = useSearchParams()
  const f = { channel: pick(CHANNEL_TYPES, params.get('channel')), result: pick(RESULTS, params.get('result')), kind: pick(KINDS, params.get('kind')) }
  const set = (key: keyof typeof f, v: string) => {
    const p = new URLSearchParams(params)
    if (v) p.set(key, v)
    else p.delete(key)
    setParams(p, { replace: true })
  }
  // Clear filters also clears the table's own search and page: the table writes them in the same moment from the same URL, and only
  // the last write of one render is kept, so this one says them too.
  const clear = () => {
    const p = new URLSearchParams(params)
    for (const k of ['channel', 'result', 'kind', `${SENT_KEY}.q`, `${SENT_KEY}.page`]) p.delete(k)
    setParams(p, { replace: true })
  }
  return { f, set, clear, on: !!(f.channel || f.result || f.kind) }
}

/** Every message sent, all kinds, newest first, with filters by channel, result and kind on top of the table's own search. */
function SentMessages({ items }: { items: HistoryItem[] }) {
  const { t } = useTranslation('notify')
  const can = useCan('operator')
  const resend = useResend()
  const { f, set, clear, on } = useFilters()
  const rows = items.filter((r) => (!f.channel || r.channel === f.channel) && (!f.result || resultOf(r) === f.result) && (!f.kind || r.kind === f.kind))
  // The channels the list holds (in the app's order), and the one a link asked for even when none of its messages is left
  const channels = CHANNEL_TYPES.filter((c) => c === f.channel || items.some((r) => r.channel === c))
  const where = (r: HistoryItem) => t('history.via', { channel: t(`ch.${r.channel}`), to: r.to })
  // A copy sent with Send again says so: two rows with the same words are one message and its resend, not two alerts.
  const what = (r: HistoryItem) => <div className="grid"><Link to={r.link} className="text-accent underline-offset-4 hover:underline">{r.what}</Link><span className="text-caption text-muted">{t(`history.kind.${r.kind}`)}{r.resent ? ` · ${t('history.resent')}` : ''}</span></div>
  const result = (r: HistoryItem) => (
    <div className="grid justify-items-start gap-1">{r.ok ? <Chip tone="ok">{t('history.ok')}</Chip> : r.delayed ? <Chip tone="accent">{t('history.delayed')}</Chip> : <Chip tone="warn">{t('history.failed')}</Chip>}{r.error ? <span className="min-w-[10rem] max-w-[48ch] text-meta">{r.error}</span> : null}</div>
  )
  // A delayed message is sent again by the box itself once the provider's wait is over: no Send again.
  const again = (r: HistoryItem) => (r.delayed ? null : <>
    <Button size="sm" disabled={!can || resend.isPending} busy={resend.isPending && resend.variables === r.id} busyLabel={t('common:busy.sending')} title={can ? undefined : t('common:needRole', { role: t('common:role.operator') })} aria-label={t('history.resendFor', { channel: t(`ch.${r.channel}`), what: r.what, time: fmtDateTime(r.at) })}
      onClick={() => resend.mutate(r.id, { onSuccess: (res) => { if (res.ok) toast.success(t('history.resendOk', { channel: t(`ch.${r.channel}`) })); else toast.error(res.error ?? t('history.failed')) }, onError: (e) => toast.error(e instanceof ApiError ? e.message : String(e)) })}>
      {t('history.resend')}
    </Button>
    {/* The box sends the message again through the channel and waits for its answer */}
    <BusyNote busy={resend.isPending && resend.variables === r.id}>{t('history.resendWaiting')}</BusyNote>
  </>)
  // Three columns, the channel and its recipients under the time and Send again under the result, so nothing is cut off at 1024 px
  // next to the app sidebar; under 768 px each message is a card.
  const columns: ColumnDef<HistoryItem>[] = [
    { id: 'time', header: t('history.col.time'), accessorFn: (r) => r.at, cell: ({ row: { original: r } }) => (
      <div className="grid"><span className="whitespace-nowrap">{fmtDateTime(r.at)}</span><span className="max-w-[12rem] break-words text-caption text-muted">{where(r)}</span></div>
    ) },
    { id: 'what', header: t('history.col.what'), accessorFn: (r) => r.what, cell: ({ row }) => what(row.original) },
    { id: 'result', header: t('history.col.result'), accessorFn: (r) => Number(r.ok), cell: ({ row }) => <div className="grid justify-items-start gap-2">{result(row.original)}{again(row.original)}</div> },
    // not shown: the search reads the recipients too
    { id: 'where', header: t('history.col.to'), accessorFn: (r) => where(r), enableSorting: false },
  ]
  const mobileRow = (r: HistoryItem) => (
    <div className="grid gap-1.5 text-sm">
      {what(r)}
      <p className="break-words text-meta text-muted">{fmtDateTime(r.at)}, {where(r)}</p>
      {result(r)}
      <div>{again(r)}</div>
    </div>
  )
  const toolbar = (
    <>
      <Select aria-label={t('history.filter.channel')} className="w-auto" value={f.channel} onChange={(e) => set('channel', e.target.value)}>
        <option value="">{t('history.filter.anyChannel')}</option>
        {channels.map((c) => <option key={c} value={c}>{t(`ch.${c}`)}</option>)}
      </Select>
      <Select aria-label={t('history.filter.result')} className="w-auto" value={f.result} onChange={(e) => set('result', e.target.value)}>
        <option value="">{t('history.filter.anyResult')}</option>
        {RESULTS.map((r) => <option key={r} value={r}>{t(`history.filter.results.${r}`)}</option>)}
      </Select>
      <Select aria-label={t('history.filter.kind')} className="w-auto" value={f.kind} onChange={(e) => set('kind', e.target.value)}>
        <option value="">{t('history.filter.anyKind')}</option>
        {KINDS.map((k) => <option key={k} value={k}>{t(`history.kind.${k}`)}</option>)}
      </Select>
    </>
  )
  return (
    <Section id="sent" title={t('history.sent.title')} description={t('history.sent.description')}>
      {items.length === 0 ? <EmptyState title={t('history.emptyTitle')} info={t('history.emptyBodyInfo')}>{t('history.emptyBody')}</EmptyState>
        : <DataTable urlKey={SENT_KEY} caption={t('history.caption')} data={rows} columns={columns} mobileRow={mobileRow} hiddenColumns={['where']} initialSort={[{ id: 'time', desc: true }]} summary={t('history.summary', { count: rows.length })}
            filterPlaceholder={t('history.filter.search')} toolbar={toolbar} filtered={on} onClearFilters={clear} resetPageOn={f} />}
    </Section>
  )
}

/** Settings › Alert channels › History: the vulnerability alerts that were not sent, and every message sent (GET /notify/history,
 *  the latest 500), filtered in the browser. */
export default function History() {
  const { t } = useTranslation('notify')
  const q = useHistory()
  return (
    <QueryState query={q}>
      {(d) => (
        <>
          <p className="mb-5 max-w-3xl text-meta text-muted">{d.suppressed.count > 0 ? t('history.meta', { count: d.suppressed.count, days: d.suppressed.days }) : t('history.metaNone', { days: d.suppressed.days })}</p>
          <NotSentNotices rows={d.not_sent} days={d.suppressed.days} />
          <SentMessages items={d.items} />
        </>
      )}
    </QueryState>
  )
}
