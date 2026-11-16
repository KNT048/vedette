import { useEffect, useRef } from 'react'
import { Link } from 'react-router'
import { useTranslation } from 'react-i18next'
import { toast } from 'sonner'
import { Notice, PageHeader } from '@/components/common/PageHeader'
import { PageTabs } from '@/components/common/PageFrame'
import { SampleDataNote } from '@/components/common/States'
import { fmtDateTime } from '@/lib/format'
import { useModuleEnabled } from '@/lib/modules'
import { useEngines, useRuns } from './api'
import { EnginesTab } from './EnginesTab'
import { HistoryTab } from './HistoryTab'
import { ProbesTab } from './ProbesTab'
import { SafetyTab } from './SafetyTab'
import { CredentialedTab } from './CredentialedTab'
import { CREDENTIALED_IN_UI } from '@/lib/credentialed'

/** Says once when a LAN scan ends (done, stopped, auto-stopped), so a stop is always seen (S-SCAN-4). */
function useRunEndToast() {
  const { t } = useTranslation('scan')
  const runs = useRuns()
  const list = runs.data?.items
  const live = list?.find((r) => r.status === 'running' || r.status === 'stopping')
  const liveId = useRef<string | null>(null)
  useEffect(() => {
    if (live) { liveId.current = live.id; return }
    const prev = liveId.current
    if (!prev) return
    liveId.current = null
    const r = list?.find((x) => x.id === prev)
    if (!r) return
    if (r.status === 'stopped') toast.success(t('toast.stopped', { done: r.done, total: r.total }))
    else if (r.status === 'auto_stopped') toast.warning(t('toast.autoStopped'))
    else toast.success(t('toast.done', { count: r.matched }))
  }, [live, list, t])
}

function Page() {
  const { t } = useTranslation('scan')
  const q = useEngines()
  useRunEndToast()
  const d = q.data
  const on = d?.items.filter((e) => e.enabled).length ?? 0
  const next = d?.items.map((e) => e.next_run).filter((x): x is string => !!x).sort()[0]
  const meta = !d ? null : d.running.length ? t('page.metaRunning', { count: d.running.length }) : next ? t('page.meta', { on, total: d.items.length, time: fmtDateTime(next) }) : t('page.metaNoNext', { on, total: d.items.length })
  return (
    <>
      <PageHeader title={t('page.title')} meta={meta} info={<><p>{t('page.info')}</p><p>{t('page.infoContext')}</p></>} actions={<SampleDataNote />} stories={['S-SCAN-1', 'S-SCAN-2', 'S-SCAN-3', 'S-SCAN-4']} />
      <PageTabs label={t('page.tabs')} tabs={[
        { id: 'engines', label: t('page.tab.engines'), panel: <EnginesTab q={q} /> },
        { id: 'safety', label: t('page.tab.safety'), panel: <SafetyTab /> },
        { id: 'history', label: t('page.tab.history'), panel: <HistoryTab /> },
        { id: 'probes', label: t('page.tab.probes'), panel: <ProbesTab /> },
        // D-417: not offered in v1 (no backend); kept for after v1
        ...(CREDENTIALED_IN_UI ? [{ id: 'credentialed', label: t('page.tab.credentialed'), panel: <CredentialedTab /> }] : []),
      ]} />
    </>
  )
}

/**
 * #850, Settings › Scanning (S-SCAN-4): every engine of the box on one page, grouped by what it does, with one shared safety block,
 * the run history and the probe log. The section belongs to core so it never disappears with a Preview module; its reads are the
 * scan module's today, so while that module is off the page says so (the engine read moves to a v1 owner with the backend, #850).
 */
export default function ScanningSettings() {
  const { t } = useTranslation('scan')
  const scan = useModuleEnabled('scan')
  if (scan === undefined) return null
  if (!scan) {
    return (
      <>
        <PageHeader title={t('page.title')} />
        <Notice tone="off" title={t('page.scanOff')} info={t('page.scanOffInfo')} actions={<Link to="/settings/modules" className="text-sm text-accent underline-offset-4 hover:underline">{t('engine.openModules')}</Link>} />
      </>
    )
  }
  return <Page />
}
