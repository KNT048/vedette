import { useEffect, useState, type FormEvent } from 'react'
import { Link, useNavigate } from 'react-router'
import { useTranslation } from 'react-i18next'
import { toast } from 'sonner'
import { Search } from 'lucide-react'
import { PageHeader, Section } from '@/components/common/PageHeader'
import { DataTable, type ColumnDef } from '@/components/common/DataTable'
import { CveList } from '@/components/common/status'
import { EmptyState, QueryState } from '@/components/common/States'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Segmented } from '@/components/ui/segmented'
import { fmtDate, fmtDateTime, fmtPercent, fmtWhen, rawProductLine } from '@/lib/format'
import { useCan } from '@/lib/session'
import { useSetup } from '@/app/RequireSession'
import { ApiError } from '@/lib/api'
import { useAnswerWeekly, useFeedStatus, useHot, useWeekly } from './api'
import { YouHaveCell } from './YouHaveCell'
import { HomeDashboard } from './HomeDashboard'
import { affectedDevices, exploitedDevices, isFirstRun, useHome } from './homeSummary'
import { useModuleEnabled } from '@/lib/modules'
import { TwoStepPrompt } from '@/features/core/TwoStepPrompt'
import { AlertChannelPrompt } from '@/features/core/AlertChannelPrompt'
import { AiBudgetPrompt } from '@/features/ai/Budget'
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

/** The sentence that replaces a count or an empty table while the CISA list is off or has never loaded; null when there is nothing to say. */
/**
 * The board is not a list that ran once at install. It says how often the box checks CISA's list, when it last did, and
 * CISA's own last addition (CISA may add nothing for days); a failed check says so, with the last good pull and the way to fix it;
 * a list never pulled says that. All from GET /feeds/status (and the board's own `latest`), times in the reader's time zone.
 */
function KevFreshness({ latest }: { latest: { date_added: string; display: string } | null }) {
  const { t } = useTranslation('feeds')
  const kev = useFeedStatus().data?.kev
  const now = useMinute()
  // off, or never loaded with a reason: the board's notice says it, with the last try and the link (useKevNotice)
  if (!kev || kev.state === 'off' || (kev.state === 'never_loaded' && kev.error)) return null
  const every = t('fresh.every', { count: kev.interval_hours })
  const added = latest ? ` ${t('fresh.latest', { date: fmtDate(latest.date_added), product: latest.display })}` : ''
  const link = <Link to="/settings/feeds#feed-cisa-kev" className="text-accent underline-offset-4 hover:underline">{t('fresh.openFeeds')}</Link>
  if (kev.error) {
    // #938 review r1: the failed state keeps the cadence (Vedette keeps trying, backing off after failures) and CISA's last addition
    return (
      <p role="status" className="mb-3 text-meta text-danger [overflow-wrap:anywhere]">
        {t('fresh.failed', { every, time: fmtWhen(kev.checked_at, now), reason: kev.error })}{' '}
        {kev.last_success ? t('fresh.lastGood', { time: fmtWhen(kev.last_success, now) }) : t('fresh.neverGood')}{added} {link}
      </p>
    )
  }
  if (!kev.checked_at) return <p className="mb-3 text-meta text-muted">{t('fresh.never', { every })} {link}</p>
  // Both copies are asked every check; the line says which one the newest list came from, and a copy that
  // failed alone is a quiet note (cisa.gov answers 403 to some countries), never an alarm
  const time = fmtWhen(kev.checked_at, now)
  const copies = kev.copies ?? [] // an older box (or a test fixture) without the field
  const both = copies.length > 0 && kev.answered_by
  const ok = both ? t('fresh.okBoth', { every, time, from: t(kev.answered_by === MIRROR ? 'fresh.fromMirror' : 'fresh.fromCisa') }) : t('fresh.ok', { every, time })
  const notes = copies.filter((c) => c.error).map((c) => ` ${t('fresh.copyFailed', { why: c.error })}`).join('')
  return <p className="mb-3 text-meta text-muted">{ok}{notes}{added}</p>
}

/** What modules/feeds records when the newest list came from CISA's GitHub copy (feeds.AnsweredMirror). */
const MIRROR = 'CISA GitHub mirror'

/** The time, a minute at a time: "10:54" becomes "17 Nov 2026, 10:54" after midnight without waiting for a refetch. */
function useMinute() {
  const [now, setNow] = useState(() => new Date())
  useEffect(() => {
    const id = setInterval(() => setNow(new Date()), 60_000)
    return () => clearInterval(id)
  }, [])
  return now
}

function useKevNotice() {
  const { t } = useTranslation('feeds')
  const status = useFeedStatus()
  // A box that has never fetched answers generated_at = 1970-01-01 (the contract has no null there): Home says "no data yet" instead.
  const never = !!status.data && new Date(status.data.generated_at).getFullYear() < 2000
  const kev = status.data?.kev
  const link = <Link to="/settings/feeds" className="text-accent underline-offset-4 hover:underline">{t('home.kevSeeFeeds')}</Link>
  const notice = kev?.state === 'off' ? <>{t('home.kevOff')} {link}</>
    : kev?.state === 'never_loaded' && !(never && !kev.error) ? <>{t('home.kevNever', { reason: kev.error ?? t('home.kevNoAttempt') })}{kev.checked_at ? ` ${t('fresh.lastTried', { time: fmtWhen(kev.checked_at), count: kev.interval_hours })}` : ''} {link}</> : null
  // What Home's dashboard says instead of "nothing exploited": the notice, or, on a box that has never fetched (no notice, the
  // headline says "no data yet"), that nothing was fetched yet.
  const noClaim = notice ?? (never ? <>{t('home.kevNoData')} {link}</> : null)
  return { never, notice, noClaim }
}

type HotWindow = '24h' | '7d'

function HotBoard({ noDevices, win, setWin }: { noDevices: boolean; win: HotWindow; setWin: (w: HotWindow) => void }) {
  const { t } = useTranslation('feeds')
  const { notice } = useKevNotice()
  const navigate = useNavigate()
  const hot = useHot(win)
  const columns: ColumnDef<HotRow>[] = [
    { id: 'product', header: t('hot.col.product'), accessorFn: (r) => r.display, cell: ({ row }) => {
      const raw = rawProductLine(row.original.display, row.original.vendor, row.original.product)
      return (
        <div className="grid">
          <span className="font-medium">{row.original.display}</span>
          {raw ? <span className="text-caption text-muted">{raw}</span> : null}
        </div>
      )
    } },
    { id: 'cves', header: t('hot.col.cves'), accessorFn: (r) => r.cves.length, cell: ({ row }) => (
      <CveList items={row.original.cves} label={t('hot.col.cves')} />
    ) },
    { id: 'epss', header: t('hot.col.epss'), accessorFn: (r) => r.max_epss ?? -1, cell: ({ row }) => {
      const d = row.original.max_epss_delta
      return (
        <span className="whitespace-nowrap">{fmtPercent(row.original.max_epss)}{d !== null && d > 0.0005 ? <span className="ml-1.5 text-caption text-warn">{t('hot.delta', { delta: fmtPercent(d) })}</span> : null}</span>
      )
    } },
    { id: 'template', header: t('hot.col.template'), accessorFn: (r) => Number(r.has_template), cell: ({ row }) => (row.original.has_template ? t('hot.yes') : <span className="text-muted">–</span>) },
    { id: 'ransomware', header: t('hot.col.ransomware'), accessorFn: (r) => Number(r.ransomware), cell: ({ row }) => (row.original.ransomware ? <span className="font-medium text-danger">{t('hot.yes')}</span> : <span className="text-muted">–</span>) },
    { id: 'youHave', header: t('hot.col.youHave'), accessorFn: (r) => (r.you_have === 'yes' ? 2 : r.you_have === 'maybe' ? 1 : 0), cell: ({ row }) => <YouHaveCell value={row.original.you_have} noDevices={noDevices} /> },
  ]
  return (
    <Section id="hot" title={t('hot.title')} description={t('hot.description')} info={t('hot.descriptionInfo')} stories={['S-FEED-1']}
      actions={
        <Segmented label={t('hot.window')} value={win} onChange={setWin} options={[{ value: '24h', label: t('hot.24h') }, { value: '7d', label: t('hot.7d') }]} />
      }>
      <KevFreshness latest={hot.data?.latest ?? null} />
      <QueryState query={hot}>
        {(d) => d.rows.length ? (
          <DataTable urlKey="hot-cves" caption={t('hot.title')} data={d.rows} columns={columns} onRowClick={(r) => navigate(`/cve/${r.cves[0]!.cve}`)} rowTone={(r) => (r.you_have === 'yes' ? 'danger' : undefined)}
            mobileRow={(r) => (
              <div className="grid gap-1.5">
                <div className="flex items-start justify-between gap-3">
                  <span className="font-medium">{r.display}</span>
                  <YouHaveCell value={r.you_have} noDevices={noDevices} />
                </div>
                <CveList items={r.cves} label={t('hot.col.cves')} />
                <div className="flex flex-wrap gap-x-4 text-caption text-muted">
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
              {d.latest ? t('hot.emptyLatest', { date: fmtDate(d.latest.date_added), product: d.latest.display }) : null}
            </EmptyState>
          )
        )}
      </QueryState>
    </Section>
  )
}

/** "This week in plain words". `linked`: the CVEs the board above already links to their page; a sentence names such a CVE without
 *  a second link to the same page (one link per CVE on a page). */
function Weekly({ linked }: { linked: ReadonlySet<string> }) {
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
    <Section id="weekly" title={t('weekly.title')} description={t('weekly.description')} info={t('weekly.descriptionInfo')} stories={['S-FEED-2']}>
      <QueryState query={weekly}>
        {(d) => {
          const items = d.items.filter((i) => i.answer !== 'not_relevant')
          // No empty bordered list; one line says there is nothing this week
          if (items.length === 0) return <p className="text-sm text-muted">{t('weekly.none')}</p>
          return (
          <ol className="grid divide-y divide-rule rounded-md border border-rule bg-surface">
            {items.map((i) => (
              <li key={i.id} className="grid gap-3 px-4 py-3 md:grid-cols-[1fr_auto] md:items-center">
                <p className="max-w-[72ch] text-sm leading-relaxed">{i.text} {linked.has(i.cve) ? <span className="text-meta text-muted">{i.cve}</span> : <Link to={`/cve/${i.cve}`} className="text-meta text-accent underline-offset-4 hover:underline">{i.cve}</Link>}</p>
                <div className="flex gap-2">
                  {i.answer === 'have' ? <span className="text-meta text-ok">{t('weekly.added')}</span> : (
                    <>
                      <Button size="sm" variant="primary" disabled={!canAct || answer.isPending} busy={answer.isPending && answer.variables?.id === i.id && answer.variables.answer === 'have'} busyLabel={t('common:busy.adding')} title={canAct ? undefined : t('common:needRole', { role: t('common:role.operator') })} onClick={() => send(i.id, 'have')}>{t('weekly.have')}</Button>
                      <Button size="sm" disabled={!canAct || answer.isPending} busy={answer.isPending && answer.variables?.id === i.id && answer.variables.answer === 'not_relevant'} busyLabel={t('common:busy.saving')} onClick={() => send(i.id, 'not_relevant')}>{t('weekly.notRelevant')}</Button>
                    </>
                  )}
                </div>
              </li>
            ))}
          </ol>
          )
        }}
      </QueryState>
    </Section>
  )
}

export default function HomePage() {
  const { t } = useTranslation('feeds')
  const status = useFeedStatus()
  const setup = useSetup()
  const hot = useHot('7d')
  const [win, setWin] = useState<HotWindow>('7d')
  const board = useHot(win)
  const linked = new Set((board.data?.rows ?? []).flatMap((r) => r.cves.map((c) => c.cve)))
  const findingsOn = useModuleEnabled('findings')
  const summary = useHome(findingsOn === true)
  const rows = hot.data?.rows ?? []
  const cves = rows.reduce((n, r) => n + r.cves.length, 0)
  const matched = rows.filter((r) => r.you_have === 'yes').length
  const { never, notice: kevTitle, noClaim } = useKevNotice()
  const s = summary.data
  // With findings on, the headline answers "is anything I run being exploited?" from the findings overview; the week's new CVEs are the board below.
  const answer = s ? (isFirstRun(s) ? t('home.titleFirstRun') : exploitedDevices(s) ? t('home.titleOpen', { count: exploitedDevices(s) }) : s.open.findings ? t('home.titleUpdates', { count: affectedDevices(s) }) : t('home.titleClear')) : null
  const loading = !hot.data || (findingsOn === true && summary.isPending)
  const title = loading ? t('home.titleLoading') : kevTitle ? kevTitle : never ? t('home.titleNone') : answer ? answer : status.data?.inventory_on === false ? t('home.titleNoInv', { count: cves }) : t('home.title', { count: cves, matched })
  return (
    <>
      <PageHeader
        title={title}
        stories={['S-FEED-1', 'S-FEED-3', 'S-UI-1']}
        meta={never ? t('home.metaNone') : status.data ? <>{t('home.meta', { time: fmtDateTime(status.data.generated_at), sources: status.data.sources.map((s) => s.name).join(', ') })}{setup.data?.data_mode === 'sample' ? ` ${t('home.sampleInventory')}` : ''}</> : null}
        actions={<SearchBox />}
      />
      <AiBudgetPrompt />
      <HomeDashboard kevNotice={noClaim} prompts={<><AlertChannelPrompt /><TwoStepPrompt /></>} />
      <HotBoard noDevices={s ? s.devices.total <= 1 : false} win={win} setWin={setWin} />
      <Weekly linked={linked} />
    </>
  )
}
