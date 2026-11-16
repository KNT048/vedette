import { lazy, Suspense, type ComponentType } from 'react'
import type { Feature } from '@/app/feature'
import { Loading } from '@/components/common/States'
import { ScansRunningIndicator } from './ScanNow'

const ScanningSettings = lazy(() => import('./ScanningSettings'))

// Module scan: quét xác nhận an toàn (S-SCAN-1..4). #850: no menu entry; its page is Settings › Scanning, a core section so it
// stays when this Preview module is off, and Scan now sits where the person is (ScanNowButton, ScansRunningIndicator).
export const feature: Feature = {
  id: 'scan',
  routes: [{ path: 'scans', lazy: () => import('./ScansMoved').then((m) => ({ Component: m.default })) }],
  // #850: "1 scan running" in the shell (phone top bar, sidebar foot); it reads nothing while the scan module is off
  slots: { 'shell.status': ScansRunningIndicator as ComponentType<Record<string, unknown>> },
  settings: [{ id: 'scanning', label: 'scan:settings.nav', module: 'core', minRole: 'viewer', order: 22, element: <Suspense fallback={<Loading />}><ScanningSettings /></Suspense> }],
}

