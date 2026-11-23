import { lazy, Suspense, type ComponentType } from 'react'
import { Navigate } from 'react-router'
import type { Feature } from '@/app/feature'
import { Loading } from '@/components/common/States'
import { ScansRunningIndicator } from './ScanNow'
import { DevicesActions } from './DeviceActions'
import { LastChecks } from './LastChecks'
import { runsHref } from './places'

const ScanningPage = lazy(() => import('./ScanningPage'))

// Settings › Scanning: a core section (GET /scanning is core's), so it never disappears with an engine's module.
// contract.ts and the first mocks came with the backend (#857).
export const feature: Feature = {
  id: 'scanning',
  routes: [
    // One run of any engine; every "Open the run" comes here. /runs alone is the list, on its tab of Settings › Scanning.
    { path: 'runs/:id', lazy: () => import('./RunPage').then((m) => ({ Component: m.default })) },
    { path: 'runs', element: <Navigate to={runsHref()} replace /> },
  ],
  // "1 scan running" in the shell (phone top bar, sidebar foot): every engine's runs, the public scans included
  // the scan buttons of the Devices list (#850 H3; slot of features/inventory, #849); the device page's buttons are in Last checks
  slots: {
    'shell.status': ScansRunningIndicator as ComponentType<Record<string, unknown>>,
    'devices.actions': DevicesActions as unknown as ComponentType<Record<string, unknown>>,
    // The last device check, vulnerability check and SNMP read of the device, on its Overview tab
    'device.panels': LastChecks as ComponentType<Record<string, unknown>>,
  },
  settings: [{ id: 'scanning', label: 'common:shell.scanning', module: 'core', minRole: 'viewer', order: 22, element: <Suspense fallback={<Loading />}><ScanningPage /></Suspense> }],
}
