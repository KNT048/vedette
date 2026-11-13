import { useState, type FormEvent } from 'react'
import { Link, useNavigate } from 'react-router'
import { useTranslation } from 'react-i18next'
import { toast } from 'sonner'
import { Search } from 'lucide-react'
import { PageHeader, Section } from '@/components/common/PageHeader'
import { DataTable, type ColumnDef } from '@/components/common/DataTable'
import { EmptyState, QueryState } from '@/components/common/States'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Segmented } from '@/components/ui/segmented'
import { fmtPercent, rawProductLine } from '@/lib/format'
import { fmtDay, fmtStamp } from './dates'
import { useCan } from '@/lib/session'
import { useSetup } from '@/app/RequireSession'
import { ApiError } from '@/lib/api'
import { useAnswerWeekly, useFeedStatus, useHot, useWeekly } from './api'
import { YouHaveCell } from './YouHaveCell'
import type { HotRow } from './types'

function SearchBox() {
  const { t } = useTranslation('feeds')
  const navigate = useNavigate()
  const [q, setQ] = useState('')
  function submit(e: FormEvent) {
    e.preventDefault()
    if (q.trim()) navigate(`/lookup?q=${encodeURIComponent(q.trim())}`)
  }
  return (
    <form role="search" onSubmit={submit} className="flex w-full min-w-[min(100%,22rem)] max-w-md flex-wrap gap-2">
      <Input value={q} maxLength={200} className="min-w-[17rem] flex-1" onChange={(e) => setQ(e.target.value)} placeholder={t('search.placeholder')} aria-label={t('search.placeholder')} />
      <Button type="submit"><Search />{t('search.submit')}</Button>
    </form>
  )
}

/** D-92/D-134: the sentence that replaces a count or an empty table while the CISA list is off or has never loaded; null when there is nothing to say. */
function useKevNotice() {
  const { t } = useTranslation('feeds')
  const status = useFeedStatus()
  // A box that has never fetched answers generated_at = 1970-01-01 (the contract has no null there): Home says "no data yet" instead.
  const never = !!status.data && new Date(status.data.generated_at).getFullYear() < 2000
  const kev = status.data?.kev
  const link = <Link to="/settings/feeds" className="text-accent underline-offset-4 hover:underline">{t('home.kevSeeFeeds')}</Link>
  const notice = kev?.state === 'off' ? <>{t('home.kevOff')} {link}</>
    : kev?.state === 'never_loaded' && !(never && !kev.error) ? <>{t('home.kevNever', { reason: kev.error ?? t('home.kevNoAttempt') })} {link}</> : null
  return { never, notice }
}

function HotBoard() {
  const { t } = useTranslation('feeds')
  const { notice } = useKevNotice()
  const navigate = useNavigate()
  const [win, setWin] = useState<'24h' | '7d'>('7d')
  const hot = useHot(win)
  const columns: ColumnDef<HotRow>[] = [
    { id: 'product', header: t('hot.col.product'), accessorFn: (r) => r.display, cell: ({ row }) => {
      const raw = rawProductLine(row.original.display, row.original.vendor, row.original.product)
      return (
        <div className="grid">
          <span className="font-medium">{row.original.display}</span>
          {raw ? <span className="text-[12px] text-muted">{raw}</span> : null}
        </div>
      )
    } },
    { id: 'cves', header: t('hot.col.cves'), accessorFn: (r) => r.cves.length, cell: ({ row }) => (
      <div className="flex flex-wrap gap-x-2">
        {row.original.cves.map((c) => <Link key={c.cve} to={`/cve/${c.cve}`} onClick={(e) => e.stopPropagation()} className="whitespace-nowrap text-accent underline-offset-4 hover:underline">{c.cve}</Link>)}
      </div>
    ) },
    { id: 'epss', header: t('hot.col.epss'), accessorFn: (r) => r.max_epss ?? -1, cell: ({ row }) => {
      const d = row.original.max_epss_delta
      return (
        <span className="whitespace-nowrap">{fmtPercent(row.original.max_epss)}{d !== null && d > 0.0005 ? <span className="ml-1.5 text-[12px] text-warn">{t('hot.delta', { delta: fmtPercent(d) })}</span> : null}</span>
      )
    } },
    { id: 'template', header: t('hot.col.template'), accessorFn: (r) => Number(r.has_template), cell: ({ row }) => (row.original.has_template ? t('hot.yes') : <span className="text-muted">–</span>) },
    { id: 'ransomware', header: t('hot.col.ransomware'), accessorFn: (r) => Number(r.ransomware), cell: ({ row }) => (row.original.ransomware ? <span className="font-medium text-danger">{t('hot.yes')}</span> : <span className="text-muted">–</span>) },
    { id: 'youHave', header: t('hot.col.youHave'), accessorFn: (r) => (r.you_have === 'yes' ? 2 : r.you_have === 'maybe' ? 1 : 0), cell: ({ row }) => <YouHaveCell value={row.original.you_have} /> },
  ]
  return (
    <Section id="hot" title={t('hot.title')} description={t('hot.description')} stories={['S-FEED-1']}
      actions={
        <Segmented label={t('hot.window')} value={win} onChange={setWin} options={[{ value: '24h', label: t('hot.24h') }, { value: '7d', label: t('hot.7d') }]} />
      }>
      <QueryState query={hot}>
        {(d) => d.rows.length ? (
          <DataTable caption={t('hot.title')} data={d.rows} columns={columns} onRowClick={(r) => navigate(`/cve/${r.cves[0]!.cve}`)} rowTone={(r) => (r.you_have === 'yes' ? 'danger' : undefined)}
            mobileRow={(r) => (
              <div className="grid gap-1.5">
                <div className="flex items-start justify-between gap-3">
                  <span className="font-medium">{r.display}</span>
                  <YouHaveCell value={r.you_have} />
                </div>
                <div className="flex flex-wrap gap-x-3 gap-y-1 text-[13px]">
                  {r.cves.map((c) => <Link key={c.cve} to={`/cve/${c.cve}`} className="text-accent">{c.cve}</Link>)}
                </div>
                <div className="flex flex-wrap gap-x-4 text-[12px] text-muted">
                  <span>{t('hot.col.epss')}: {fmtPercent(r.max_epss)}</span>
                  {r.ransomware ? <span className="font-medium text-danger">{t('hot.col.ransomware')}</span> : null}
                  {r.has_template ? <span>{t('hot.col.template')}</span> : null}
                </div>
              </div>
            )} />
        ) : (
          notice ? (
            <div className="rounded-md border border-dashed border-rule bg-surface px-6 py-8"><p className="font-medium">{notice}</p></div>
          ) : (
            <EmptyState title={t('hot.empty', { window: win === '24h' ? t('hot.24h') : t('hot.7d') })}>
              {d.latest ? t('hot.emptyLatest', { date: fmtDay(d.latest.date_added), product: d.latest.display }) : null}
            </EmptyState>
          )
        )}
      </QueryState>
    </Section>
  )
}

function Weekly() {
  const { t } = useTranslation('feeds')
  const weekly = useWeekly()
  const answer = useAnswerWeekly()
  const canAct = useCan('operator')
  function send(id: string, a: 'have' | 'not_relevant') {
    answer.mutate({ id, answer: a }, {
      onSuccess: () => toast.success(a === 'have' ? t('weekly.addedToast') : t('weekly.hiddenToast')),
      onError: (e) => toast.error(e instanceof ApiError ? e.message : String(e)),
    })
  }
  return (
    <Section id="weekly" title={t('weekly.title')} description={t('weekly.description')} stories={['S-FEED-2']}>
      <QueryState query={weekly}>
        {(d) => (
          <ol className="grid divide-y divide-rule rounded-md border border-rule bg-surface">
            {d.items.filter((i) => i.answer !== 'not_relevant').map((i) => (
              <li key={i.id} className="grid gap-3 px-4 py-3 md:grid-cols-[1fr_auto] md:items-center">
                <p className="max-w-[72ch] text-[15px] leading-relaxed">{i.text} <Link to={`/cve/${i.cve}`} className="text-[13px] text-accent underline-offset-4 hover:underline">{i.cve}</Link></p>
                <div className="flex gap-2">
                  {i.answer === 'have' ? <span className="text-[13px] text-ok">{t('weekly.added')}</span> : (
                    <>
                      <Button size="sm" variant="primary" disabled={!canAct || answer.isPending} title={canAct ? undefined : t('common:needRole', { role: t('common:role.operator') })} onClick={() => send(i.id, 'have')}>{t('weekly.have')}</Button>
                      <Button size="sm" disabled={!canAct || answer.isPending} onClick={() => send(i.id, 'not_relevant')}>{t('weekly.notRelevant')}</Button>
                    </>
                  )}
                </div>
              </li>
            ))}
          </ol>
        )}
      </QueryState>
    </Section>
  )
}

export default function HomePage() {
  const { t } = useTranslation('feeds')
  const status = useFeedStatus()
  const setup = useSetup()
  const hot = useHot('7d')
  const rows = hot.data?.rows ?? []
  const cves = rows.reduce((n, r) => n + r.cves.length, 0)
  const matched = rows.filter((r) => r.you_have === 'yes').length
  const { never, notice: kevTitle } = useKevNotice()
  const title = !hot.data ? t('home.titleLoading') : kevTitle ? kevTitle : never ? t('home.titleNone') : status.data?.inventory_on === false ? t('home.titleNoInv', { count: cves }) : t('home.title', { count: cves, matched })
  return (
    <>
      <PageHeader
        title={title}
        stories={['S-FEED-1', 'S-FEED-3']}
        meta={never ? t('home.metaNone') : status.data ? <>{t('home.meta', { time: fmtStamp(status.data.generated_at), sources: status.data.sources.map((s) => s.name).join(', ') })}{setup.data?.data_mode === 'sample' ? ` ${t('home.sampleInventory')}` : ''}</> : null}
        actions={<SearchBox />}
      />
      {matched > 0 ? (
        <p className="-mt-2 mb-6 text-sm"><Link to="/findings" className="text-accent underline-offset-4 hover:underline">{t('home.toFindings')}</Link></p>
      ) : null}
      <HotBoard />
      <Weekly />
    </>
  )
}
