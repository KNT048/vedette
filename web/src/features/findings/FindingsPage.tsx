// Findings (S-MIT-1, S-TIER-1): one screen for what to fix and what was done. By device (default) and By fix are the open findings
// grouped two ways, with one status filter, each followed by the possible findings (CVEs Vedette cannot decide, counted apart);
// AI proposals lists what a check proposed about possible CVEs, for a person to confirm or reject (shown while there are some);
// Handled is what was done, by whom and how; Ignored devices holds what a person chose not to watch. The recommended updates are
// the open findings with the status "Update recommended" (`/plan` opens them here).
import { useSearchParams, Navigate } from 'react-router'
import { useTranslation } from 'react-i18next'
import { PageHeader } from '@/components/common/PageHeader'
import { PageTabs } from '@/components/common/PageFrame'
import { RequireModule } from '@/components/common/States'
import { useOverview } from './api'
import { ByDevice } from './ByDevice'
import { ByFix } from './ByFix'
import { HandledTab } from './HandledTab'
import { IgnoredTab } from './IgnoredTab'
import { usePossibleCheckWatch } from './Possible'
import { ProposalsTab } from './Proposals'
import { statusesOf } from './StatusFilter'

/**
 * The query of an older link (the earlier tabs To fix, All open, Accepted, Needs your input; `?cve=`, `?by=fix`) in this screen's
 * words, or null when the query is already this screen's. To fix of one device and All open are By device; Accepted is Handled,
 * filtered; Needs your input is By device, whose possible findings hold its questions.
 */
export function newQuery(p: URLSearchParams): URLSearchParams | null {
  const n = new URLSearchParams(p)
  const tab = p.get('tab')
  let changed = false
  const put = (k: string, v: string | null) => { changed = true; if (v === null) n.delete(k); else n.set(k, v) }
  if (p.get('by') === 'fix') { put('by', null); put('tab', 'fix') }
  else if (tab === 'fix' && p.get('device')) put('tab', 'device')
  else if (tab === 'open' || tab === 'input') put('tab', 'device')
  else if (tab === 'accepted') { put('tab', 'handled'); put('resolution', 'accepted') }
  if (p.get('cve')) { put('by-device.q', p.get('cve')!.toUpperCase()); put('cve', null); if (!n.get('tab') || n.get('tab') === 'handled') put('tab', 'device') }
  for (const k of ['severity', 'product', 'fix', 'notrelevant', 'input.q', 'input.page', 'input.size']) if (p.has(k)) put(k, null)
  const s = p.get('status')
  if (s !== null && statusesOf(s).join(',') !== s) put('status', statusesOf(s).join(',') || null)
  return changed ? n : null
}

function Screen() {
  const { t } = useTranslation('findings')
  const [params, setParams] = useSearchParams()
  const overview = useOverview()
  const status = statusesOf(params.get('status')).join(',')
  const device = params.get('device') ?? ''
  const setDevice = (id: string) => setParams((prev) => { const p = new URLSearchParams(prev); if (id) p.set('device', id); else p.delete('device'); return p }, { replace: true, preventScrollReset: true })
  const o = overview.data
  usePossibleCheckWatch() // a check of possible findings runs in the background: its end is said here, whatever the tab
  const proposals = o?.possible.proposals ?? 0
  const fixed = newQuery(params)
  if (fixed) return <Navigate replace to={{ search: `?${fixed}`, hash: params.get('tab') === 'input' ? '#possible' : undefined }} />
  return (
    <>
      <PageHeader
        title={t('common:shell.findings')}
        meta={!o ? null : o.open.findings === 0 ? t('titleNone') : t('page.title', { count: o.open.findings })}
        stories={['S-MIT-1', 'S-TIER-1']}
        info={<><p>{t('page.info')}</p><p>{t('page.infoStatus')}</p></>}
      />
      <PageTabs label={t('tabs.label')} tabs={[
        { id: 'device', label: t('tabs.device'), panel: <ByDevice status={status} device={device} onDevice={setDevice} /> },
        { id: 'fix', label: t('tabs.fix'), panel: <ByFix status={status} /> },
        // shown while proposals wait (or a link opens it): an empty tab nobody can fill without an AI profile would only be noise
        ...(proposals || params.get('tab') === 'proposals' ? [{ id: 'proposals', label: t('tabs.proposals'), panel: <ProposalsTab />, badge: proposals ? { count: proposals, label: t('tabs.proposalsBadge') } : undefined }] : []),
        { id: 'handled', label: t('tabs.handled'), panel: <HandledTab device={device} /> },
        { id: 'ignored', label: t('tabs.ignored'), panel: <IgnoredTab /> },
      ]} />
    </>
  )
}

export default function FindingsPage() {
  return <RequireModule module="findings" page><Screen /></RequireModule>
}

/** `/plan`, the earlier Recommended updates page: the open findings whose status is Update recommended, by device. */
export function PlanRedirect() {
  return <Navigate replace to="/findings?tab=device&status=update_recommended" />
}
