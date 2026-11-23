import { lazy, Suspense } from 'react'
import { Laptop } from 'lucide-react'
import type { Feature } from '@/app/feature'
import { Loading } from '@/components/common/States'

const DeclaredSoftware = lazy(() => import('./DeclaredSoftwareSection'))

// The inventory module (S-INV-1..4): the device list (Devices, To review), detail, Add a device, sensors, agents;
// Settings › Declared software (#849): products declared without a device.
export const feature: Feature = {
  id: 'inventory',
  routes: [
    { path: 'devices', lazy: () => import('./DevicesPage').then((m) => ({ Component: m.default })) },
    { path: 'devices/setup', lazy: () => import('./SetupPage').then((m) => ({ Component: m.default })) },
    { path: 'devices/:id', lazy: () => import('./DevicePage').then((m) => ({ Component: m.default })) },
  ],
  nav: [{ to: '/devices', label: 'common:shell.devices', icon: Laptop, module: 'inventory', group: 'assets', order: 10 }],
  settings: [{ id: 'declared-software', label: 'common:shell.declared', module: 'inventory', minRole: 'viewer', order: 27, element: <Suspense fallback={<Loading />}><DeclaredSoftware /></Suspense> }],
}
