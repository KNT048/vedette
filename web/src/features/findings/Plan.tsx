// Updates to plan (S-TIER-1, S-TIER-2): CVEs on no exploited list, grouped by the update that fixes them
// on one device, as top tools group by fix in a view of their own (Microsoft Defender Vulnerability Management's security
// recommendations, Tenable's remediations). Not findings: no status, no alert, no mitigation pack; every CVE one click away.
import { useEffect, useRef, useState } from 'react'
import { Link } from 'react-router'
import { Trans, useTranslation } from 'react-i18next'
import { Card } from '@/components/common/Card'
import { Notice } from '@/components/common/PageHeader'
import { Chip } from '@/components/common/StatusChip'
import { SeverityBadge } from '@/components/common/status'
import { useQueryClient } from '@tanstack/react-query'
import { toast } from 'sonner'
import { Button } from '@/components/ui/button'
import { ApiError } from '@/lib/api'
import { fmtDate, fmtPercent } from '@/lib/format'
import { useCan } from '@/lib/session'
import { useModules } from '@/lib/modules'
import { useToggleModule } from '@/features/core/api'
import { usePatchFeed } from '@/features/feeds/api'
import { noCvesKey, planCountKey, usePlanAction } from './fix'
import type { Plan, PlanCve, PlanItem } from './types'
import { InfoTip } from '@/components/common/InfoTip'
import { RiskMarker } from '@/features/inventory/RiskMarker'

function Severity({ c }: { c: PlanCve }) {
  return <SeverityBadge compact severity={c.severity ? { band: c.severity, score: c.score } : null} />
}

/** The evidence key of a CVE: an agent's row reads "Last reported by an agent" once no agent reports the device (`gone`). */
const evidenceKey = (basis: PlanCve['basis'], gone: boolean) => (basis === 'agent' && gone ? 'agentLast' : basis)

/** The evidence chip: how Vedette knows the device has the flaw. */
export function EvidenceChip({ basis, gone = false }: { basis: PlanCve['basis']; gone?: boolean }) {
  const { t } = useTranslation('findings')
  const k = evidenceKey(basis, gone)
  // #824: the explanation is behind an ⓘ, not a hover-only title.
  return <span className="inline-flex items-center gap-1"><Chip tone={basis === 'version' || k === 'agentLast' ? 'off' : 'accent'}>{t(`plan.evidence.${k}`)}</Chip><InfoTip topic={t(`plan.evidence.${k}`)}>{t(`plan.evidence.${k}Hint`)}</InfoTip></span>
}

export function TierChip({ tier }: { tier: PlanCve['tier'] }) {
  const { t } = useTranslation('findings')
  return <span className="inline-flex items-center gap-1"><Chip tone={tier === 'likely' ? 'warn' : 'off'}>{t(`plan.tier.${tier}`)}</Chip><InfoTip topic={t(`plan.tier.${tier}`)}>{t(`plan.tier.${tier}Hint`)}</InfoTip></span>
}

function yearAgo() {
  return new Date(Date.now() - 365 * 86_400_000).toISOString().slice(0, 10)
}

/** How many CVEs of an item, and how many items, show before "Show all": an item can fix thousands (a Windows cumulative
 *  update fixed 2,786 on a test box), and the server already sorts them likely first, then by severity. */
export const PLAN_FIRST = 50

function CveList({ item, gone }: { item: PlanItem; gone: boolean }) {
  const { t } = useTranslation('findings')
  const old = yearAgo()
  const [all, setAll] = useState(false)
  const cves = all ? item.cves : item.cves.slice(0, PLAN_FIRST)
  const body = useRef<HTMLTableSectionElement>(null)
  // #808: the button goes away, so focus moves to the first CVE it revealed, not back to the top of the page
  useEffect(() => { if (all) body.current?.querySelectorAll('a')[PLAN_FIRST]?.focus() }, [all])
  return (
    <div className="mt-2 overflow-x-auto rounded-md border border-rule bg-surface">
      <table className="w-full min-w-[640px] text-sm">
        <caption className="sr-only">{t('plan.cve.caption', { software: item.software, device: item.asset.name })}</caption>
        <thead className="bg-sunken text-left text-caption text-muted">
          <tr className="border-b border-rule">
            <th scope="col" className="px-3 py-2 font-medium">{t('plan.cve.cve')}</th>
            <th scope="col" className="px-3 py-2 font-medium">{t('plan.cve.tier')}</th>
            <th scope="col" className="px-3 py-2 font-medium">{t('plan.cve.severity')}</th>
            <th scope="col" className="px-3 py-2 font-medium">{t('plan.cve.published')}</th>
            <th scope="col" className="px-3 py-2 text-right font-medium">{t('plan.cve.epss')}</th>
            <th scope="col" className="px-3 py-2 font-medium">{t('plan.cve.evidence')}</th>
          </tr>
        </thead>
        <tbody ref={body} className="divide-y divide-rule">
          {cves.map((c) => (
            <tr key={c.cve}>
              <th scope="row" className="px-3 py-2 text-left font-medium">
                <Link to={`/cve/${c.cve}`} className="whitespace-nowrap text-accent underline-offset-4 hover:underline">{c.cve}</Link>
              </th>
              <td className="px-3 py-2"><TierChip tier={c.tier} /></td>
              <td className="px-3 py-2"><Severity c={c} /></td>
              <td className="whitespace-nowrap px-3 py-2 text-meta">
                {fmtDate(c.published)}
                {c.published < old ? <span className="block text-caption text-muted">{t('plan.cve.old')}</span> : null}
              </td>
              <td className="whitespace-nowrap px-3 py-2 text-right text-meta tabular-nums">{c.epss === null ? '–' : fmtPercent(c.epss)}</td>
              <td className="px-3 py-2"><EvidenceChip basis={c.basis} gone={gone} /></td>
            </tr>
          ))}
        </tbody>
      </table>
      {cves.length < item.cves.length ? (
        <div className="flex flex-wrap items-center gap-3 border-t border-rule px-3 py-2">
          <p className="text-meta text-muted">{t('plan.firstCves', { shown: cves.length, count: item.cves.length })}</p>
          <Button variant="secondary" size="sm" onClick={() => setAll(true)}>{t('plan.showAllCves', { count: item.cves.length })}</Button>
        </div>
      ) : null}
      <Legend item={item} gone={gone} />
    </div>
  )
}

/** What the chips of this list mean, as text (#803: a `title` alone is out of reach of keyboard and touch). */
function Legend({ item, gone }: { item: PlanItem; gone: boolean }) {
  const { t } = useTranslation('findings')
  const tiers = [...new Set(item.cves.map((c) => c.tier))]
  const bases = [...new Set(item.cves.map((c) => evidenceKey(c.basis, gone)))]
  const row = (key: string, term: string, hint: string) => (
    <div key={key}><dt className="inline font-medium">{term}</dt><dd className="inline">{': '}{hint}</dd></div>
  )
  return (
    <dl className="grid gap-1 border-t border-rule px-3 py-2 text-caption text-muted">
      {tiers.map((x) => row(`tier-${x}`, t(`plan.tier.${x}`), t(`plan.tier.${x}Hint`)))}
      {bases.map((x) => row(`basis-${x}`, t(`plan.evidence.${x}`), t(`plan.evidence.${x}Hint`)))}
    </dl>
  )
}

/** One item: the device, the action, the count, the CVEs inside a disclosure. */
function PlanRow({ i, action, showDevice, likelyOnly }: { i: PlanItem; action: string; showDevice: boolean; likelyOnly: boolean }) {
  const { t } = useTranslation('findings')
  const gone = i.agent_gone // the box's answer for the device (no request per row)
  return (
    <li className="grid min-w-0 gap-1 px-4 py-3">
      <p className="text-sm">
        {showDevice ? <><Link to={`/devices/${i.asset.id}`} className="font-medium text-accent underline-offset-4 hover:underline">{i.asset.name}</Link>{' '}<RiskMarker id={i.asset.id} risk={i.risk} className="align-middle" />{': '}</> : null}
        <span className="font-medium">{action}</span>{': '}
        {/* Microsoft's newest Windows update with none of its CVEs analysed by NVD yet: no count, no list */}
        {i.cves.length === 0 ? t(noCvesKey(i.nvd_lag)) : likelyOnly ? <span className="text-warn">{t('plan.fixesOnlyLikely', { count: i.cves.length })}</span> : (
          <>
            {t(planCountKey(i), { count: i.cves.length })}
            {i.likely > 0 ? <> <span className="text-warn">{t('plan.fixesLikely', { count: i.likely })}</span></> : null}
            {/* Microsoft's newest update is newer than every fix NVD names: the count is the CVEs NVD has analysed so far */}
            {i.nvd_lag ? t('plan.nvdLag') : null}
          </>
        )}
        {gone ? <span className="block text-meta text-muted">{i.agent_reported ? t('plan.lastReported', { date: fmtDate(i.agent_reported) }) : t('plan.lastReportedNoDate')}</span> : null}
        {i.kind === 'distro' && i.distro_data === 'none' ? <span className="block text-meta text-muted">{t('plan.noDataNote')}</span> : null}
      </p>
      {i.cves.length > 0 ? (
        <details className="min-w-0">
          <summary className="w-fit cursor-pointer text-meta text-accent underline-offset-4 hover:underline">{t('plan.show', { count: i.cves.length })}</summary>
          <CveList item={i} gone={gone} />
        </details>
      ) : null}
    </li>
  )
}

/** The items as one list: the device (on the page, not on a device's own page), the action, the count, the CVEs inside a disclosure. */
export function PlanItems({ items, showDevice, likelyOnly = false }: { items: PlanItem[]; showDevice: boolean; likelyOnly?: boolean }) {
  const { t } = useTranslation('findings')
  const action = usePlanAction()
  const [all, setAll] = useState(false)
  const shown = all ? items : items.slice(0, PLAN_FIRST)
  const list = useRef<HTMLUListElement>(null)
  useEffect(() => { if (all) list.current?.children[PLAN_FIRST]?.querySelector<HTMLElement>('a, summary')?.focus() }, [all])
  return (
    <>
    <Card flush>
    <ul ref={list} aria-label={t('plan.listLabel')} className="grid min-w-0 divide-y divide-rule">
      {shown.map((i) => <PlanRow key={i.group} i={i} action={action(i)} showDevice={showDevice} likelyOnly={likelyOnly} />)}
    </ul>
    </Card>
    {shown.length < items.length ? (
      <Button variant="secondary" size="sm" className="mt-3" onClick={() => setAll(true)}>{t('plan.showAllItems', { count: items.length })}</Button>
    ) : null}
    </>
  )
}

/** The two feeds of this page by the name the plan API gives them. */
const FEED_ID = { epss: 'epss-all', recent: 'nvd-recent' } as const
type TierFeed = keyof typeof FEED_ID
/** Settings › Feeds, at the switch of the first feed named (docs/UI.md §0: the exact place, not "see Settings"). */
const feedsAt = (feeds: TierFeed[]) => `/settings/feeds#feed-${FEED_ID[feeds[0] ?? 'epss']}`

/** Do it where you are (docs/UI.md §0): an administrator turns the missing feeds on from this page; the same switches stay in
 *  Settings › Feeds. Anyone else gets nothing here (the line above already says an administrator does it, with the link). */
function TurnOnFeeds({ feeds }: { feeds: TierFeed[] }) {
  const { t } = useTranslation('findings')
  const admin = useCan('admin')
  const patch = usePatchFeed()
  const qc = useQueryClient()
  if (!admin || feeds.length === 0) return null
  const names = feeds.map((f) => t(`plan.feed.${f}`)).join(t('plan.and'))
  async function turnOn() {
    try {
      for (const f of feeds) await patch.mutateAsync({ id: FEED_ID[f], enabled: true })
      toast.success(t('plan.state.turnedOn', { feeds: names, count: feeds.length }))
    } catch (e) {
      toast.error(e instanceof ApiError ? e.message : String(e))
    }
    void qc.invalidateQueries({ queryKey: ['findings', 'plan'] })
  }
  return <Button size="sm" variant="primary" busy={patch.isPending} busyLabel={t('plan.state.turningOn')} onClick={() => void turnOn()}>{t('plan.state.turnOn', { count: feeds.length })}</Button>
}

/** The feeds module is off: an administrator turns it on here (with what it needs), anyone else gets the exact page. */
function TurnOnModule() {
  const { t } = useTranslation('findings')
  const admin = useCan('admin')
  const toggle = useToggleModule()
  const qc = useQueryClient()
  const mods = useModules().data?.modules ?? []
  // what the feeds module needs that is off is turned on with it (Settings › Modules asks first): the toast names those modules
  const also = (mods.find((m) => m.id === 'feeds')?.depends ?? []).filter((d) => mods.find((m) => m.id === d)?.enabled === false).map((d) => t(`modules.${d}.name`, { ns: 'common' }))
  const link = <Link to="/settings/modules" className="text-sm text-accent underline underline-offset-4">{t('plan.state.openModules')}</Link>
  if (!admin) return link
  return (
    <span className="flex flex-wrap items-center gap-3">
      <Button size="sm" variant="primary" busy={toggle.isPending} busyLabel={t('common:busy.turningOn')}
        onClick={() => toggle.mutate({ id: 'feeds', enabled: true, withDependencies: true }, {
          onSuccess: (r) => {
            // the cached plan still says module_off: ask again, so the Notice and this button go away (as TurnOnFeeds does)
            void qc.invalidateQueries({ queryKey: ['findings', 'plan'] })
            if (r.kind === 'ok') toast.success(also.length ? t('plan.state.moduleOnWith', { modules: also.join(', ') }) : t('plan.state.moduleOn'))
          },
          onError: (e) => toast.error(e instanceof ApiError ? e.message : String(e)),
        })}>
        {t('plan.state.turnOnModule')}
      </Button>
      {link}
    </span>
  )
}

/** Why the list is empty or partial (#803): first that this version does not compare yet (then nothing
 *  invites anyone to turn feeds on: they would load ~105,000 NVD records for nothing), else the feeds module off, a feed off or still
 *  loading. null when the data is there and compared. Every missing piece is turned on right here by an administrator (docs/UI.md §0). */
export function PlanDataState({ plan, compact = false }: { plan: Plan; compact?: boolean }) {
  const { t } = useTranslation('findings')
  if (!plan.compared) {
    return compact ? <p className="text-sm text-muted">{t('plan.state.notCompared')}</p> : (
      <Notice tone="accent" title={t('plan.state.notComparedTitle')} info={t('plan.state.notComparedInfo')}><p>{t('plan.state.notCompared')}</p></Notice>
    )
  }
  const { epss, recent } = plan.data
  if (epss === 'module_off' || recent === 'module_off') {
    return compact ? <div className="grid gap-2"><p className="text-sm text-muted">{t('plan.state.moduleOff')}</p><TurnOnModule /></div> : (
      <Notice tone="off" title={t('plan.state.moduleOffTitle')} actions={<TurnOnModule />}><p>{t('plan.state.moduleOff')}</p></Notice>
    )
  }
  const name = (f: TierFeed) => t(`plan.feed.${f}`)
  const off = (['epss', 'recent'] as const).filter((f) => plan.data[f] === 'off')
  const loading = (['epss', 'recent'] as const).filter((f) => plan.data[f] === 'loading')
  const feedsLink = <Link to={feedsAt(off)} className="text-accent underline underline-offset-4" />
  const openFeeds = <Link to={feedsAt(off)} className="text-sm text-accent underline underline-offset-4">{t('plan.state.openFeeds')}</Link>
  const actions = <span className="flex flex-wrap items-center gap-3"><TurnOnFeeds feeds={off} />{openFeeds}</span>
  if (epss === 'off' && recent === 'off') {
    return compact ? <div className="grid gap-2"><p className="text-sm text-muted"><Trans t={t} i18nKey="plan.state.offShort" components={{ a: feedsLink }} /></p><div><TurnOnFeeds feeds={off} /></div></div> : (
      <Notice tone="off" title={t('plan.state.offTitle')} info={t('plan.state.offBodyInfo')} actions={actions}>
        <p>{t('plan.state.offBody')}</p>
      </Notice>
    )
  }
  const parts: string[] = []
  if (off.length) parts.push(t('plan.state.someOff', { feeds: off.map(name).join(t('plan.and')) }))
  if (loading.length) parts.push(t('plan.state.loading', { feeds: loading.map(name).join(t('plan.and')) }))
  if (!parts.length) return null
  return compact ? <div className="grid gap-2"><p className="text-sm text-muted">{parts.join(' ')} {openFeeds}</p>{off.length ? <div><TurnOnFeeds feeds={off} /></div> : null}</div> : (
    <Notice tone="off" title={t('plan.state.partialTitle')} info={loading.length ? t('plan.state.loadingInfo') : undefined} actions={off.length ? actions : openFeeds}>
      <p>{parts.join(' ')}</p>
    </Notice>
  )
}
