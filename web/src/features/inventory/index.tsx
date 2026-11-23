import { lazy, Suspense } from 'react'
import { Laptop } from 'lucide-react'
import type { Feature } from '@/app/feature'
import { Loading } from '@/components/common/States'

const DeclaredSoftware = lazy(() => import('./DeclaredSoftwareSection'))

// Module inventory (S-INV-1..4): danh sách thiết bị (Devices, To review), chi tiết, Add a device, phạm vi và cảm biến, agent;
// Settings › Declared software (#849): sản phẩm khai mà không có thiết bị.
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
