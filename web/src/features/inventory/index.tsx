import { Laptop } from 'lucide-react'
import type { Feature } from '@/app/feature'

// Module inventory (S-INV-1..4): danh sách thiết bị, chi tiết, khai tay, chưa duyệt, phạm vi và cảm biến, agent.
export const feature: Feature = {
  id: 'inventory',
  routes: [
    { path: 'devices', lazy: () => import('./DevicesPage').then((m) => ({ Component: m.default })) },
    { path: 'devices/setup', lazy: () => import('./SetupPage').then((m) => ({ Component: m.default })) },
    { path: 'devices/:id', lazy: () => import('./DevicePage').then((m) => ({ Component: m.default })) },
  ],
  nav: [{ to: '/devices', label: 'inventory:nav.devices', icon: Laptop, module: 'inventory', group: 'assets', order: 10 }],
}
