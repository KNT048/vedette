import { lazy, Suspense, type ComponentType } from 'react'
import type { Feature } from '@/app/feature'
import { Loading } from '@/components/common/States'
import { ScansRunningIndicator } from './ScanNow'

const ScanningPage = lazy(() => import('./ScanningPage'))

// Settings › Scanning (#850, D-627): a core section (GET /scanning is core's), so it never disappears with an engine's module.
// The page owner is the UI (AI-Mlee); contract.ts and the first mocks came with the backend (AI-Trưởng, #857).
export const feature: Feature = {
  id: 'scanning',
  routes: [],
  // "1 scan running" in the shell (phone top bar, sidebar foot): every engine's runs, the public scans included
  slots: { 'shell.status': ScansRunningIndicator as ComponentType<Record<string, unknown>> },
  settings: [{ id: 'scanning', label: 'scanning:nav', module: 'core', minRole: 'viewer', order: 22, element: <Suspense fallback={<Loading />}><ScanningPage /></Suspense> }],
}
