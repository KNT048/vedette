import { lazy, Suspense, useEffect, useState, type ReactNode } from 'react'
import { Link } from 'react-router'
import { useTranslation } from 'react-i18next'
import { useQuery, useQueryClient } from '@tanstack/react-query'
import { Circle, CircleCheck } from 'lucide-react'
import { Card } from '@/components/common/Card'
import { KpiGrid, KpiTile } from '@/components/common/KpiTile'
import { RankedList, RankedRow } from '@/components/common/RankedList'
import { Sparkline } from '@/components/common/Sparkline'
import { Illustration } from '@/components/common/Illustration'
import { EmptyState, ErrorState } from '@/components/common/States'
import { Chip, StatusChip } from '@/components/common/StatusChip'
import { Button } from '@/components/ui/button'
import { api } from '@/lib/api'
import { fmtRelative } from '@/lib/format'
import { useModuleEnabled } from '@/lib/modules'
import { useCan, useMe } from '@/lib/session'
import { cn } from '@/lib/utils'
import { CvssScore } from '@/features/findings/Cvss'
import type { HomeSummary, SummaryItem } from '@/features/findings/types'
import { useChannels } from '@/features/notify/api'
import { useAccount } from '@/features/core/api'

// The add-device dialog is inventory's; Home loads it only when the button is pressed, so the Home chunk does not carry it.
const AddDeviceDialog = lazy(() => import('@/features/inventory/AddDeviceDialog').then((m) => ({ default: m.AddDeviceDialog })))

const KEY = ['findings', 'summary'] as const

/**
 * Home's one read (#825, INV-23): the cached `GET /findings/summary` under the query key the shell's nav badges share (app/nav.ts). The
 * shell is the one poller (every 60 s, paused in a hidden tab, stopped on error); Home only subscribes: a second timer would ask twice a
 * minute. `staleTime` matches the box's 60 s cache, so going back to Home asks nothing new. Finding changes invalidate the key
 * (findings/api.ts useWrite, useBulkStatus), so the page is fresh after a status change.
 */
export function useHome(enabled: boolean) {
  return useQuery({ queryKey: KEY, queryFn: () => api.get<HomeSummary>('/findings/summary'), enabled, staleTime: 60_000, retry: false })
}

/** A box with no device but itself and nothing open: Home shows the first-run path instead of tiles of zeros. */
export const isFirstRun = (s: HomeSummary) => s.devices.total <= 1 && s.open.total === 0

const dayFmt = new Intl.DateTimeFormat('en-GB', { day: 'numeric', month: 'short', timeZone: 'UTC' })

/** The tiles: what needs action now (with its 30-day trend), devices, and, while Notifications is on, alerts and incidents. */
function Tiles({ s }: { s: HomeSummary }) {
  const { t } = useTranslation('feeds')
  const admin = useCan('admin') // the history of sent messages is on an administrator's page
  const { open, trend } = s
  const first = trend[0]!, last = trend[trend.length - 1]!
  const delta = last - first
  const days = trend.length
  const dayOf = (i: number) => (i === days - 1 ? t('dash.now') : dayFmt.format(new Date(Date.parse(s.generated_at) - (days - 1 - i) * 864e5)))
  const suspected = open.total - open.confirmed
  const notify = !!s.alerts && !!s.incidents
  const link = 'text-accent underline-offset-4 hover:underline'
  return (
    <KpiGrid label={t('dash.label')} className={notify ? 'lg:grid-cols-5' : 'lg:grid-cols-3'}>
      <KpiTile className="col-span-2" to="/findings?tab=open" value={open.total} tone={open.total ? 'danger' : 'ok'}
        label={open.total ? t('dash.open', { count: open.total, devices: open.devices }) : t('dash.openNone')}
        sub={open.total ? (
          <>
            {open.confirmed ? <Link to="/findings?tab=open&status=confirmed" className={cn(link, 'font-medium')}>{t('dash.confirmed', { count: open.confirmed })}</Link> : null}
            {suspected ? <span>{t('dash.suspected', { count: suspected })}</span> : null}
            {open.ransomware ? <span className="font-medium text-danger">{t('dash.ransomware', { count: open.ransomware })}</span> : null}
          </>
        ) : null}
        chart={(
          <div className="grid gap-1 sm:grid-cols-[minmax(0,1fr)_auto] sm:items-end sm:gap-4">
            <Sparkline values={trend} tone={last ? 'danger' : 'ok'} label={t('dash.trendLabel', { days, first, last })}
              point={(i) => t('dash.trendDay', { day: dayOf(i), count: trend[i] })} start={dayOf(0)} end={dayOf(days - 1)} />
            <p className={cn('text-meta sm:pb-5', delta > 0 ? 'text-danger' : delta < 0 ? 'text-ok' : 'text-muted')}>
              {delta === 0 ? t('dash.trendSame', { days }) : t(delta > 0 ? 'dash.trendUp' : 'dash.trendDown', { count: Math.abs(delta), days })}
            </p>
          </div>
        )} />
      <KpiTile className={notify ? undefined : 'col-span-2 lg:col-span-1'} to="/devices" value={s.devices.total} label={t('dash.devices', { count: s.devices.total })}
        sub={(
          <>
            {open.devices ? <span>{t('dash.affected', { count: open.devices })}</span> : null}
            {s.devices.pending ? <Link to="/devices?tab=review" className={cn(link, 'font-medium')}>{t('dash.pending', { count: s.devices.pending })}</Link> : null}
          </>
        )} />
      {s.alerts ? (
        <KpiTile to={admin ? '/settings/channels#history' : undefined} value={s.alerts.sent} label={t('dash.alerts', { count: s.alerts.sent, days: s.alerts.days })}
          sub={s.alerts.failed ? <span className="font-medium text-danger">{t('dash.alertsFailed', { count: s.alerts.failed })}</span> : <span>{t('dash.alertsNoneFailed')}</span>} />
      ) : null}
      {s.incidents ? (
        <KpiTile className="col-span-2 lg:col-span-1" to="/incidents?tab=open" value={s.incidents.open} tone={s.incidents.urgent ? 'danger' : undefined}
          label={t('dash.incidents', { count: s.incidents.open })}
          sub={s.incidents.urgent
            ? <Link to="/incidents?tab=open&severity=urgent" className="font-medium text-danger underline-offset-4 hover:underline">{t('dash.urgent', { count: s.incidents.urgent })}</Link>
            : <span>{t('dash.urgentNone')}</span>} />
      ) : null}
    </KpiGrid>
  )
}

/** One "Fix first" row: product (link to the finding), CVE, device, age; certainty, the exploited list, ransomware; CVSS under them. */
function FixRow({ f, rank }: { f: SummaryItem; rank: number }) {
  const { t } = useTranslation('feeds')
  const name = f.product || f.cve
  return (
    <RankedRow rank={rank}
      title={<Link to={`/findings/${encodeURIComponent(f.id)}`} className="underline-offset-4 hover:underline">{name}</Link>}
      meta={(
        <>
          {f.product ? <span className="whitespace-nowrap">{f.cve}</span> : null}
          {f.asset
            ? <Link to={`/devices/${encodeURIComponent(f.asset.id)}`} className="text-ink underline-offset-4 hover:underline [overflow-wrap:anywhere]">{f.asset.name}</Link>
            : <span>{t('dash.removedDevice')}</span>}
          <span className="whitespace-nowrap">{t('dash.since', { when: fmtRelative(f.first_seen) })}</span>
        </>
      )}
      aside={(
        <>
          <div className="flex flex-wrap gap-1.5 md:justify-end">
            <StatusChip status={f.status} />
            <Chip tone="danger">{f.source === 'vulncheck-kev' ? t('dash.inVulncheck') : f.source ? t('dash.inKev') : t('dash.exploited')}</Chip>
            {f.ransomware ? <Chip tone="danger">{t('dash.ransomwareChip')}</Chip> : null}
          </div>
          <CvssScore cvss={f.cvss} prefix />
        </>
      )} />
  )
}

function FixFirst({ s, kevNotice }: { s: HomeSummary; kevNotice: ReactNode }) {
  const { t } = useTranslation('feeds')
  if (!s.top.length) {
    // D-92: while the CISA list is off or never loaded, "nothing exploited" would be a claim Vedette cannot make.
    if (kevNotice) return <div className="mb-8"><EmptyState title={t('dash.fixFirst')}>{kevNotice}</EmptyState></div>
    return (
      <div className="mb-8">
        <EmptyState art="no-findings" title={t('dash.emptyTitle')} info={t('dash.emptyInfo')}>{t('dash.emptyBody', { count: s.devices.total })}</EmptyState>
      </div>
    )
  }
  return (
    <Card id="fix-first" flush className="mb-8" title={t('dash.fixFirst')} info={t('dash.fixFirstInfo')}
      actions={<Link to="/findings?tab=open" className="text-meta text-accent underline-offset-4 hover:underline">{t('dash.allFindings', { count: s.open.total })}</Link>}>
      <RankedList label={t('dash.fixFirst')}>
        {s.top.map((f, i) => <FixRow key={f.id} f={f} rank={i + 1} />)}
      </RankedList>
    </Card>
  )
}

// The first-run card, per user in this browser (a convenience, docs/UI.md §2): "seen" once it was shown with a step to do, so the
// "You're set up" state appears only to someone who went through it; "hidden" after Hide. Storage errors: shown, never remembered.
const SETUP_KEY = (user: string) => `vedette.home.setup.${user}`
function readSetup(user: string): string | null {
  try { return localStorage.getItem(SETUP_KEY(user)) } catch { return null }
}
function writeSetup(user: string, v: 'seen' | 'hidden') {
  try { localStorage.setItem(SETUP_KEY(user), v) } catch { /* the card comes back next visit */ }
}

type Step = { id: string; done: boolean; title: string; line: string; action?: ReactNode }

/** The first-run steps: what Home needs before it can say anything (devices), then what makes the alert arrive (J3), then the sign-in. */
function useSteps(s: HomeSummary, onAdd: () => void): Step[] | null {
  const { t } = useTranslation('feeds')
  const { data: me } = useMe()
  const op = useCan('operator')
  const admin = me?.role === 'admin'
  const notifyOn = useModuleEnabled('notify') === true
  // Both reads are the ones the alert and two-step prompts make (same keys): Home hides those prompts while this card shows its steps.
  const channels = useChannels({ retry: false, enabled: admin && notifyOn })
  const account = useAccount(admin)
  if (!me) return null
  const needRole = op ? undefined : t('common:needRole', { role: t('common:role.operator') })
  const steps: Step[] = [{
    id: 'devices', done: s.devices.total > 1,
    title: t('start.devices.title'),
    line: s.devices.total > 1 ? t('start.devices.done', { count: s.devices.total }) : t('start.devices.line'),
    action: (
      <>
        {admin ? <Button asChild size="sm" variant="primary"><Link to="/devices/setup#range-input">{t('start.devices.range')}</Link></Button> : null}
        <Button size="sm" variant={admin ? 'secondary' : 'primary'} disabled={!op} title={needRole} onClick={onAdd}>{t('start.devices.add')}</Button>
      </>
    ),
  }]
  if (admin && notifyOn && channels.data) {
    const on = channels.data.channels.some((c) => c.configured && c.enabled)
    steps.push({ id: 'alerts', done: on, title: t('start.alerts.title'), line: on ? t('start.alerts.done') : t('start.alerts.line'),
      action: <Button asChild size="sm"><Link to="/settings/channels">{t('start.alerts.go')}</Link></Button> })
  }
  if (admin && account.data && !account.data.user.sso) {
    steps.push({ id: 'twofa', done: me.twofa, title: t('start.twofa.title'), line: me.twofa ? t('start.twofa.done') : t('start.twofa.line'),
      action: <Button asChild size="sm"><Link to="/settings/account?tab=sign-in">{t('start.twofa.go')}</Link></Button> })
  }
  return steps
}

/** The first-run path (docs/UI.md §0): each step done in place (add a device) or linked to the exact page and field; done steps say so. */
function GetStarted({ s, steps, onHide }: { s: HomeSummary; steps: Step[]; onHide: () => void }) {
  const { t } = useTranslation('feeds')
  const done = steps.every((x) => x.done)
  const todo = steps.filter((x) => !x.done).length
  return (
    <Card id="get-started" className="mb-8" title={done ? t('start.doneTitle') : t('start.title')} info={t('start.info')}
      actions={<Button size="sm" variant="ghost" onClick={onHide}>{t('start.hide')}</Button>}>
      <div className="grid gap-6 md:grid-cols-[auto_minmax(0,1fr)] md:items-start">
        <Illustration name={done ? 'setup-done' : 'welcome'} className="justify-self-center" />
        <div className="grid gap-3">
          <p className="text-meta text-muted">{done ? t('start.doneLine', { count: s.devices.total }) : t('start.line', { count: todo })}</p>
          <ol className="grid divide-y divide-rule rounded-md border border-rule">
            {steps.map((x) => (
              <li key={x.id} className="grid grid-cols-[auto_minmax(0,1fr)] gap-x-3 gap-y-2 px-4 py-3 sm:grid-cols-[auto_minmax(0,1fr)_auto] sm:items-center">
                {x.done ? <CircleCheck aria-hidden className="mt-0.5 size-5 text-ok sm:mt-0" /> : <Circle aria-hidden className="mt-0.5 size-5 text-control sm:mt-0" />}
                <div className="grid gap-0.5">
                  <p className={cn('text-sm font-medium', x.done && 'text-muted')}>
                    {x.title}<span className="sr-only">{x.done ? ` (${t('start.doneWord')})` : ` (${t('start.todoWord')})`}</span>
                  </p>
                  <p className="text-meta text-muted">{x.line}</p>
                </div>
                {!x.done && x.action ? <div className="col-start-2 flex flex-wrap gap-2 sm:col-start-3">{x.action}</div> : null}
              </li>
            ))}
          </ol>
        </div>
      </div>
    </Card>
  )
}

/** First run: the card with its steps; afterwards, for the person who saw it with a step to do, until Hide (once all is done it says
 *  "You're set up"). `prompts` (the alert and two-step notices) are shown only when the card is not: the card has those steps. */
function Onboarding({ s, firstRun, prompts }: { s: HomeSummary; firstRun: boolean; prompts: ReactNode }) {
  const { data: me } = useMe()
  const qc = useQueryClient()
  const [adding, setAdding] = useState(false)
  const [hidden, setHidden] = useState(false)
  const steps = useSteps(s, () => setAdding(true))
  const stored = me ? readSetup(me.id) : null
  const show = !!me && !!steps && !hidden && stored !== 'hidden' && (firstRun || stored === 'seen')
  const todo = !!steps && steps.some((x) => !x.done)
  useEffect(() => { if (me && show && todo && stored !== 'seen') writeSetup(me.id, 'seen') }, [me, show, todo, stored])
  if (!show || !me || !steps) return <>{prompts}</>
  const hide = () => { writeSetup(me.id, 'hidden'); setHidden(true) }
  return (
    <>
      <GetStarted s={s} steps={steps} onHide={hide} />
      {adding ? (
        <Suspense fallback={null}>
          {/* A device added here changes the counts: ask the summary again (the box drops its cache on the device's findings). */}
          <AddDeviceDialog open onOpenChange={(o) => { if (!o) { setAdding(false); void qc.invalidateQueries({ queryKey: KEY }) } }} />
        </Suspense>
      ) : null}
    </>
  )
}

/**
 * Home at a glance (#825, S-UI-1): the first-run path, or the tiles and "Fix first", all from one read. Without the findings module, or
 * when the read fails, only `prompts`; a placeholder of the same height while the read is on its way (never a 0 that is really "unknown").
 */
export function HomeDashboard({ kevNotice, prompts }: { kevNotice: ReactNode; prompts: ReactNode }) {
  const { t } = useTranslation('feeds')
  const on = useModuleEnabled('findings')
  const q = useHome(on === true)
  if (on !== true) return <>{prompts}</>
  if (q.isPending) return <div role="status" aria-label={t('dash.loading')} className="mb-5 h-36 rounded-md border border-rule bg-surface" />
  if (q.isError) return <>{prompts}<div className="mb-8"><ErrorState error={q.error} onRetry={() => void q.refetch()} /></div></>
  const s = q.data
  const firstRun = isFirstRun(s)
  return (
    <>
      <Onboarding s={s} firstRun={firstRun} prompts={prompts} />
      {firstRun ? null : (
        <>
          <Tiles s={s} />
          <FixFirst s={s} kevNotice={kevNotice} />
        </>
      )}
    </>
  )
}
