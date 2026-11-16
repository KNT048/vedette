import { lazy, Suspense, type ComponentType } from 'react'
import type { Feature } from '@/app/feature'
import { Loading } from '@/components/common/States'
import { ScansRunningIndicator } from './ScanNow'
import { DeviceActions, DevicesActions } from './DeviceActions'

const ScanningPage = lazy(() => import('./ScanningPage'))

// Settings › Scanning (#850, D-627): a core section (GET /scanning is core's), so it never disappears with an engine's module.
// The page owner is the UI (AI-Mlee); contract.ts and the first mocks came with the backend (AI-Trưởng, #857).
export const feature: Feature = {
  id: 'scanning',
  routes: [],
  // "1 scan running" in the shell (phone top bar, sidebar foot): every engine's runs, the public scans included
  // the scan buttons of the Devices list and the device page (#850 H3; slots of features/inventory, #849)
  slots: {
    'shell.status': ScansRunningIndicator as ComponentType<Record<string, unknown>>,
    'devices.actions': DevicesActions as unknown as ComponentType<Record<string, unknown>>,
    'device.actions': DeviceActions as unknown as ComponentType<Record<string, unknown>>,
  },
  settings: [{ id: 'scanning', label: 'scanning:nav', module: 'core', minRole: 'viewer', order: 22, element: <Suspense fallback={<Loading />}><ScanningPage /></Suspense> }],
}
