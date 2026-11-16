// Updates to plan (S-TIER-1, S-TIER-2; D-613, D-615, D-616): CVEs on no exploited list, grouped by the update that fixes them
// on one device, as top tools group by fix in a view of their own (Microsoft Defender Vulnerability Management's security
// recommendations, Tenable's remediations). Not findings: no status, no alert, no mitigation pack; every CVE one click away.
import { useEffect, useRef, useState } from 'react'
import { Link } from 'react-router'
import { Trans, useTranslation } from 'react-i18next'
import { Notice } from '@/components/common/PageHeader'
import { Chip } from '@/components/common/StatusChip'
import { Button } from '@/components/ui/button'
import { fmtPercent } from '@/lib/format'
import { fmtDay } from '@/features/feeds/dates'
import { usePlanAction } from './fix'
import type { Plan, PlanCve, PlanItem } from './types'

function Severity({ c }: { c: PlanCve }) {
  const { t } = useTranslation('findings')
  if (!c.severity) return <span className="text-[13px] text-muted">{t('plan.cve.notScored')}</span>
  return <span className="whitespace-nowrap text-[13px]">{t(`plan.sev.${c.severity}`)}{c.score !== null ? ` ${c.score.toFixed(1)}` : ''}</span>
}

/** The evidence chip of D-615: how Vedette knows the device has the flaw. */
export function EvidenceChip({ basis }: { basis: PlanCve['basis'] }) {
  const { t } = useTranslation('findings')
  return <Chip tone={basis === 'version' ? 'off' : 'accent'} title={t(`plan.evidence.${basis}Hint`)}>{t(`plan.evidence.${basis}`)}</Chip>
}

export function TierChip({ tier }: { tier: PlanCve['tier'] }) {
  const { t } = useTranslation('findings')
  return <Chip tone={tier === 'likely' ? 'warn' : 'off'} title={t(`plan.tier.${tier}Hint`)}>{t(`plan.tier.${tier}`)}</Chip>
}

function yearAgo() {
  return new Date(Date.now() - 365 * 86_400_000).toISOString().slice(0, 10)
}

/** How many CVEs of an item, and how many items, show before "Show all" (D-623): an item can fix thousands (a Windows cumulative
 *  update fixed 2,786 on the N100), and the server already sorts them likely first, then by severity. */
export const PLAN_FIRST = 50

function CveList({ item }: { item: PlanItem }) {
  const { t } = useTranslation('findings')
  const old = yearAgo()
  const [all, setAll] = useState(false)
  const cves = all ? item.cves : item.cves.slice(0, PLAN_FIRST)
  const body = useRef<HTMLTableSectionElement>(null)
  // review r1 #6 of #808: the button goes away, so focus moves to the first CVE it revealed, not back to the top of the page
  useEffect(() => { if (all) body.current?.querySelectorAll('a')[PLAN_FIRST]?.focus() }, [all])
  return (
    <div className="mt-2 overflow-x-auto rounded-md border border-rule bg-surface">
      <table className="w-full min-w-[640px] text-sm">
        <caption className="sr-only">{t('plan.cve.caption', { software: item.software, device: item.asset.name })}</caption>
        <thead className="text-left text-[12px] text-muted">
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
              <td className="whitespace-nowrap px-3 py-2 text-[13px]">
                {fmtDay(c.published)}
                {c.published < old ? <span className="block text-[12px] text-muted">{t('plan.cve.old')}</span> : null}
              </td>
              <td className="whitespace-nowrap px-3 py-2 text-right text-[13px] tabular-nums">{c.epss === null ? '–' : fmtPercent(c.epss)}</td>
              <td className="px-3 py-2"><EvidenceChip basis={c.basis} /></td>
            </tr>
          ))}
        </tbody>
      </table>
      {cves.length < item.cves.length ? (
        <div className="flex flex-wrap items-center gap-3 border-t border-rule px-3 py-2">
          <p className="text-[13px] text-muted">{t('plan.firstCves', { shown: cves.length, count: item.cves.length })}</p>
          <Button variant="secondary" size="sm" onClick={() => setAll(true)}>{t('plan.showAllCves', { count: item.cves.length })}</Button>
        </div>
      ) : null}
      <Legend item={item} />
    </div>
  )
}

/** What the chips of this list mean, as text (review r1 #15 of #803: a `title` alone is out of reach of keyboard and touch). */
function Legend({ item }: { item: PlanItem }) {
  const { t } = useTranslation('findings')
  const tiers = [...new Set(item.cves.map((c) => c.tier))]
  const bases = [...new Set(item.cves.map((c) => c.basis))]
  const row = (key: string, term: string, hint: string) => (
    <div key={key}><dt className="inline font-medium">{term}</dt><dd className="inline">{': '}{hint}</dd></div>
  )
  return (
    <dl className="grid gap-1 border-t border-rule px-3 py-2 text-[12px] text-muted">
      {tiers.map((x) => row(`tier-${x}`, t(`plan.tier.${x}`), t(`plan.tier.${x}Hint`)))}
      {bases.map((x) => row(`basis-${x}`, t(`plan.evidence.${x}`), t(`plan.evidence.${x}Hint`)))}
    </dl>
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
    <ul ref={list} aria-label={t('plan.listLabel')} className="grid min-w-0 divide-y divide-rule rounded-md border border-rule bg-surface">
      {shown.map((i) => (
        <li key={i.group} className="grid min-w-0 gap-1 px-4 py-3">
          <p className="text-sm">
            {showDevice ? <><Link to={`/devices/${i.asset.id}`} className="font-medium text-accent underline-offset-4 hover:underline">{i.asset.name}</Link>{': '}</> : null}
            <span className="font-medium">{action(i)}</span>{': '}
            {likelyOnly ? <span className="text-warn">{t('plan.fixesOnlyLikely', { count: i.cves.length })}</span> : (
              <>
                {t('plan.fixes', { count: i.cves.length })}
                {i.likely > 0 ? <> <span className="text-warn">{t('plan.fixesLikely', { count: i.likely })}</span></> : null}
              </>
            )}
          </p>
          <details className="min-w-0">
            <summary className="w-fit cursor-pointer text-[13px] text-accent underline-offset-4 hover:underline">{t('plan.show', { count: i.cves.length })}</summary>
            <CveList item={i} />
          </details>
        </li>
      ))}
    </ul>
    {shown.length < items.length ? (
      <Button variant="secondary" size="sm" className="mt-3" onClick={() => setAll(true)}>{t('plan.showAllItems', { count: items.length })}</Button>
    ) : null}
    </>
  )
}

/** Why the list is empty or partial (D-613 states, review r1 #4 of #803): first that this version does not compare yet (then nothing
 *  invites anyone to turn feeds on: they would load ~105,000 NVD records for nothing), else the feeds module off, a feed off or still
 *  loading. null when the data is there and compared. */
export function PlanDataState({ plan, compact = false }: { plan: Plan; compact?: boolean }) {
  const { t } = useTranslation('findings')
  if (!plan.compared) {
    return compact ? <p className="text-sm text-muted">{t('plan.state.notCompared')}</p> : (
      <Notice tone="accent" title={t('plan.state.notComparedTitle')} info={t('plan.state.notComparedInfo')}><p>{t('plan.state.notCompared')}</p></Notice>
    )
  }
  const { epss, recent } = plan.data
  if (epss === 'module_off' || recent === 'module_off') {
    const link = <Link to="/settings/modules" className="text-sm text-accent underline underline-offset-4">{t('plan.state.openModules')}</Link>
    return compact ? <p className="text-sm text-muted">{t('plan.state.moduleOff')} {link}</p> : (
      <Notice tone="off" title={t('plan.state.moduleOffTitle')} actions={link}><p>{t('plan.state.moduleOff')}</p></Notice>
    )
  }
  const name = (f: 'epss' | 'recent') => t(`plan.feed.${f}`)
  const off = (['epss', 'recent'] as const).filter((f) => plan.data[f] === 'off')
  const loading = (['epss', 'recent'] as const).filter((f) => plan.data[f] === 'loading')
  const feedsLink = <Link to="/settings/feeds" className="text-accent underline underline-offset-4" />
  if (epss === 'off' && recent === 'off') {
    return compact ? <p className="text-sm text-muted"><Trans t={t} i18nKey="plan.state.offShort" components={{ a: feedsLink }} /></p> : (
      <Notice tone="off" title={t('plan.state.offTitle')} info={t('plan.state.offBodyInfo')} actions={<Link to="/settings/feeds" className="text-sm text-accent underline underline-offset-4">{t('plan.state.openFeeds')}</Link>}>
        <p>{t('plan.state.offBody')}</p>
      </Notice>
    )
  }
  const parts: string[] = []
  if (off.length) parts.push(t('plan.state.someOff', { feeds: off.map(name).join(t('plan.and')) }))
  if (loading.length) parts.push(t('plan.state.loading', { feeds: loading.map(name).join(t('plan.and')) }))
  if (!parts.length) return null
  return compact ? <p className="text-sm text-muted">{parts.join(' ')} <Link to="/settings/feeds" className="text-accent underline underline-offset-4">{t('plan.state.openFeeds')}</Link></p> : (
    <Notice tone="off" title={t('plan.state.partialTitle')} info={loading.length ? t('plan.state.loadingInfo') : undefined} actions={<Link to="/settings/feeds" className="text-sm text-accent underline underline-offset-4">{t('plan.state.openFeeds')}</Link>}>
      <p>{parts.join(' ')}</p>
    </Notice>
  )
}
