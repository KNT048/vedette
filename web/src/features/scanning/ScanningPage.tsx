import { useEffect, useRef } from 'react'
import { Navigate, useSearchParams } from 'react-router'
import { useTranslation } from 'react-i18next'
import { toast } from 'sonner'
import { DependencyLink } from '@/components/common/DependencyLink'
import { PageHeader } from '@/components/common/PageHeader'
import { PageTabs } from '@/components/common/PageFrame'
import { QueryState, SampleDataNote } from '@/components/common/States'
import { CredentialedTab } from '@/features/scan/CredentialedTab'
import { RescanLog } from '@/features/scan/RescanLog'
import { ProbesTab } from '@/features/scan/ProbesTab'
import { useRuns } from '@/features/scan/api'
import { CREDENTIALED_IN_UI } from '@/lib/credentialed'
import { fmtDateTime } from '@/lib/format'
import { useModuleEnabled } from '@/lib/modules'
import { useScanning } from './api'
import { EnginesTab } from './EnginesTab'
import { runHref } from './places'
import { runningLabel } from './runningLabel'
import { RunsTab } from './RunsTab'
import { SafetyTab } from './SafetyTab'
import type { Scanning } from './types'

/** Says once when a LAN vulnerability check ends (done, stopped, auto-stopped), so a stop is always seen (S-SCAN-4). */
function useRunEndToast(on: boolean) {
  const { t } = useTranslation('scan')
  const runs = useRuns(on)
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
    const reason = (r.stop_reason ?? '').replace(/\.$/, '')
    if (r.status === 'stopped' || r.status === 'auto_stopped') {
      const text = t(reason ? 'toast.endedEarly' : 'toast.endedEarlyNoReason', { done: r.done, total: r.total, reason })
      if (r.stop_reason?.startsWith('You pressed Stop')) toast.success(text)
      else toast.warning(text)
    }
    else toast.success(t('toast.done', { count: r.matched }))
  }, [live, list, t])
}

/** The rescan log and the probe log belong to the vulnerability checks (scan module, Preview): while it is off they say so, with its switch. */
function NucleiOnly({ children }: { children: React.ReactNode }) {
  const { t } = useTranslation('scanning')
  const on = useModuleEnabled('scan')
  if (on === undefined) return null
  if (!on) return <DependencyLink reason={t('nucleiOff')} to="/settings/scanning?tab=engines#engine-nuclei-switch" label={t('nucleiOffLink')} />
  return <>{children}</>
}

function Page({ d }: { d: Scanning }) {
  const { t } = useTranslation('scanning')
  const scanOn = useModuleEnabled('scan') === true
  useRunEndToast(scanOn)
  const on = d.engines.filter((e) => e.enabled).length
  const next = d.engines.map((e) => e.next_run_at).filter((x): x is string => !!x).sort()[0]
  const meta = d.running.length ? t('page.metaRunning', { what: runningLabel(t, d.running) }) : next ? t('page.meta', { on, total: d.engines.length, time: fmtDateTime(next) }) : t('page.metaNoNext', { on, total: d.engines.length })
  return (
    <>
      <PageHeader title={t('common:shell.scanning')} meta={<span className="inline-flex flex-wrap items-center gap-2">{meta}<SampleDataNote /></span>} info={<><p>{t('page.info')}</p><p>{t('page.infoContext')}</p></>} stories={['S-SCAN-1', 'S-SCAN-2', 'S-SCAN-3', 'S-SCAN-4', 'S-INV-1']} />
      <PageTabs label={t('page.tabs')} tabs={[
        { id: 'engines', label: t('page.tab.engines'), panel: <EnginesTab d={d} /> },
        { id: 'safety', label: t('page.tab.safety'), panel: <SafetyTab s={d.safety} /> },
        // Every run of every engine, vulnerability checks included (core lists them whatever module is on); under it the log of the automatic rescans
        { id: 'runs', label: t('page.tab.runs'), panel: <><RunsTab /><NucleiOnly><RescanLog /></NucleiOnly></> },
        { id: 'probes', label: t('page.tab.probes'), panel: <NucleiOnly><ProbesTab /></NucleiOnly> },
        // Not offered in v1 (no backend); kept for after v1
        ...(CREDENTIALED_IN_UI ? [{ id: 'credentialed', label: t('page.tab.credentialed'), panel: <CredentialedTab /> }] : []),
      ]} />
    </>
  )
}

/** The History tab became Runs: an old link opens its run (`job=`, `run=`), the runs of its device (`asset=`), or the Runs tab. */
function historyMoved(params: URLSearchParams): string | null {
  if (params.get('tab') !== 'history') return null
  const job = params.get('job') ?? params.get('run')
  if (job) return runHref(job, 'settings')
  const p = new URLSearchParams(params)
  p.set('tab', 'runs')
  const asset = p.get('asset')
  if (asset) p.set('runs.device', asset)
  p.delete('asset')
  return `/settings/scanning?${p}`
}

/**
 * #850, Settings › Scanning (S-SCAN-4): every engine of the box on one page, grouped by what it does, with the one shared
 * safety block, the vulnerability checks' history and probe log. GET /scanning is served by core, so the page answers whatever
 * engine module is off; each engine's own switch turns its module on.
 */
export default function ScanningPage() {
  const q = useScanning()
  const [params] = useSearchParams()
  const moved = historyMoved(params)
  if (moved) return <Navigate to={moved} replace />
  return <QueryState query={q}>{(d) => <Page d={d} />}</QueryState>
}
