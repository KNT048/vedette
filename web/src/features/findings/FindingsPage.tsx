// Findings (S-MIT-1, S-TIER-1): one screen for what to fix and what was done. By device (default) and By fix are the open findings
// grouped two ways, with one status filter; Needs your input is the queue of what only a person can settle; Handled is what was
// done, by whom and how; Ignored devices holds what a person chose not to watch. The recommended updates are the open findings
// with the status "Update recommended" (`/plan` opens them here).
import { useSearchParams, Navigate } from 'react-router'
import { useTranslation } from 'react-i18next'
import { PageHeader } from '@/components/common/PageHeader'
import { PageTabs } from '@/components/common/PageFrame'
import { RequireModule, SampleDataNote } from '@/components/common/States'
import { useOverview } from './api'
import { ByDevice } from './ByDevice'
import { ByFix } from './ByFix'
import { HandledTab } from './HandledTab'
import { IgnoredTab } from './IgnoredTab'
import { InputTab } from './InputTab'
import { statusesOf } from './StatusFilter'

/**
 * The query of an older link (the earlier tabs To fix, All open, Accepted; `?cve=`, `?by=fix`) in this screen's words, or null
 * when the query is already this screen's. To fix of one device and All open are By device; Accepted is Handled, filtered.
 */
export function newQuery(p: URLSearchParams): URLSearchParams | null {
  const n = new URLSearchParams(p)
  const tab = p.get('tab')
  let changed = false
  const put = (k: string, v: string | null) => { changed = true; if (v === null) n.delete(k); else n.set(k, v) }
  if (p.get('by') === 'fix') { put('by', null); put('tab', 'fix') }
  else if (tab === 'fix' && p.get('device')) put('tab', 'device')
  else if (tab === 'open') put('tab', 'device')
  else if (tab === 'accepted') { put('tab', 'handled'); put('resolution', 'accepted') }
  if (p.get('cve')) { put('by-device.q', p.get('cve')!.toUpperCase()); put('cve', null); if (!n.get('tab') || n.get('tab') === 'handled') put('tab', 'device') }
  for (const k of ['severity', 'product', 'fix', 'notrelevant']) if (p.has(k)) put(k, null)
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
  const fixed = newQuery(params)
  if (fixed) return <Navigate replace to={{ search: `?${fixed}` }} />
  return (
    <>
      <PageHeader
        title={t('common:shell.findings')}
        meta={!o ? null : o.open.findings === 0 ? t('titleNone') : t('page.title', { count: o.open.findings })}
        stories={['S-MIT-1', 'S-TIER-1']}
        info={<><p>{t('page.info')}</p><p>{t('page.infoStatus')}</p></>}
        actions={<SampleDataNote />}
      />
      <PageTabs label={t('tabs.label')} tabs={[
        { id: 'device', label: t('tabs.device'), panel: <ByDevice status={status} device={device} onDevice={setDevice} /> },
        { id: 'fix', label: t('tabs.fix'), panel: <ByFix status={status} /> },
        { id: 'input', label: t('tabs.input'), panel: <InputTab device={device} onDevice={setDevice} />, badge: o?.input ? { count: o.input, label: t('tabs.inputBadge') } : undefined },
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
