import { ShieldAlert } from 'lucide-react'
import type { Feature } from '@/app/feature'
import { DevicePanel } from './DevicePanel'

// Module findings (D-57 (6)): danh sách + chi tiết phát hiện. Phần "Làm gì" (S-MIT-1) là của module mitigation, tắt thì chỉ phần đó hiện ModuleOff.
// Cung cấp slot device.panels cho trang thiết bị.
export const feature: Feature = {
  id: 'findings',
  routes: [
    { path: 'findings', lazy: () => import('./FindingsPage').then((m) => ({ Component: m.default })) },
    { path: 'findings/:id', lazy: () => import('./FindingPage').then((m) => ({ Component: m.default })) },
  ],
  nav: [{ to: '/findings', label: 'findings:nav.findings', icon: ShieldAlert, module: 'findings', group: 'monitor', order: 20 }],
  slots: { 'device.panels': DevicePanel },
}
