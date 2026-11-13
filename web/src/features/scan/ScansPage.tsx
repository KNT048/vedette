import { useEffect, useRef } from 'react'
import { useTranslation } from 'react-i18next'
import { toast } from 'sonner'
import { PageHeader } from '@/components/common/PageHeader'
import { PageTabs } from '@/components/common/PageFrame'
import { RequireModule, SampleDataNote } from '@/components/common/States'
import { fmtDateTime, fmtRelative } from '@/lib/format'
import { useRuns, useScanConfig } from './api'
import { RunsTab } from './RunsTab'
import { SafetyTab } from './SafetyTab'
import { AutoTab } from './AutoTab'
import { ProbesTab } from './ProbesTab'
import { CredentialedTab } from './CredentialedTab'
import { CREDENTIALED_IN_UI } from '@/lib/credentialed'

function Shell() {
  const { t } = useTranslation('scan')
  const runs = useRuns()
  const cfg = useScanConfig()
  const list = runs.data?.items
  const live = list?.find((r) => r.status === 'running' || r.status === 'stopping')
  const last = list?.find((r) => r.status !== 'running' && r.status !== 'stopping')

  // Báo một lần khi lần quét kết thúc (xong, dừng, tự dừng) để việc dừng luôn nhìn thấy được.
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

  const title = !list ? t('titleLoading')
    : !live && !last && cfg.data && !cfg.data.can_scan ? t(cfg.data.scope.commitment ? 'titleScannerDown' : 'titleSetup')
    : live ? (live.status === 'stopping' ? t('titleStopping') : t('titleRunning', { done: live.done, total: live.total }))
    : !last ? t('titleNone')
    : last.status === 'done' ? t('titleDone', { time: fmtRelative(last.ended_at), total: last.total, count: last.matched })
    : t('titleStopped', { time: fmtRelative(last.ended_at), done: last.done, total: last.total })

  return (
    <>
      <PageHeader
        title={title}
        stories={['S-SCAN-1', 'S-SCAN-2', 'S-SCAN-3', 'S-SCAN-4', 'S-SCAN-5']}
        meta={!cfg.data ? null : !cfg.data.can_scan ? (cfg.data.scope.commitment ? (cfg.data.block_reason ?? t('metaScannerDown')) : t('metaSetup')) : !cfg.data.scope.networks.length ? t('metaSetup') : t('meta', { networks: cfg.data.scope.networks.join(', '), next: cfg.data.next_run ? fmtDateTime(cfg.data.next_run) : cfg.data.schedule_blocked_reason ? t('noScheduleZone') : t('noSchedule') })}
        actions={<SampleDataNote />}
      />
      <PageTabs label={t('tabs.label')} tabs={[
        { id: 'runs', label: t('tabs.runs'), panel: <RunsTab /> },
        { id: 'safety', label: t('tabs.safety'), panel: <SafetyTab /> },
        { id: 'auto', label: t('tabs.auto'), panel: <AutoTab /> },
        { id: 'probes', label: t('tabs.probes'), panel: <ProbesTab /> },
        ...(CREDENTIALED_IN_UI ? [{ id: 'credentialed', label: t('tabs.credentialed'), panel: <CredentialedTab /> }] : []),
      ]} />
    </>
  )
}

export default function ScansPage() {
  return <RequireModule module="scan"><Shell /></RequireModule>
}
