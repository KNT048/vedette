import { useEffect, useRef } from 'react'
import { useSearchParams } from 'react-router'
import { useTranslation } from 'react-i18next'
import { toast } from 'sonner'
import { PageHeader } from '@/components/common/PageHeader'
import { RequireModule, SampleDataNote } from '@/components/common/States'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs'
import { fmtDateTime, fmtRelative } from '@/lib/format'
import { useRuns, useScanConfig } from './api'
import { RunsTab } from './RunsTab'
import { SafetyTab } from './SafetyTab'
import { AutoTab } from './AutoTab'
import { ProbesTab } from './ProbesTab'
import { CredentialedTab } from './CredentialedTab'

const TABS = ['runs', 'safety', 'auto', 'probes', 'credentialed'] as const
type Tab = (typeof TABS)[number]

function Shell() {
  const { t } = useTranslation('scan')
  const [params, setParams] = useSearchParams()
  const raw = params.get('tab')
  const tab: Tab = (TABS as readonly string[]).includes(raw ?? '') ? (raw as Tab) : 'runs'
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
      <Tabs value={tab} onValueChange={(v) => { const p = new URLSearchParams(params); p.set('tab', v); setParams(p, { replace: true }) }}>
        <TabsList className="overflow-x-auto" aria-label={t('tabs.label')}>
          {TABS.map((k) => <TabsTrigger key={k} value={k} className="shrink-0 whitespace-nowrap">{t(`tabs.${k}`)}</TabsTrigger>)}
        </TabsList>
        <TabsContent value="runs"><RunsTab /></TabsContent>
        <TabsContent value="safety"><SafetyTab /></TabsContent>
        <TabsContent value="auto"><AutoTab /></TabsContent>
        <TabsContent value="probes"><ProbesTab /></TabsContent>
        <TabsContent value="credentialed"><CredentialedTab /></TabsContent>
      </Tabs>
    </>
  )
}

export default function ScansPage() {
  return <RequireModule module="scan"><Shell /></RequireModule>
}
