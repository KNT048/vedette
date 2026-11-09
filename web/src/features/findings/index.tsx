import { ShieldAlert } from 'lucide-react'
import type { Feature } from '@/app/feature'
import { DevicePanel } from './DevicePanel'

// Module mitigation: Phát hiện + "Làm gì" (S-MIT-1/2/3, S-SCAN-3, S-AI-2). Cung cấp slot device.panels cho trang thiết bị.
export const feature: Feature = {
  id: 'findings',
  routes: [
    { path: 'findings', lazy: () => import('./FindingsPage').then((m) => ({ Component: m.default })) },
    { path: 'findings/:id', lazy: () => import('./FindingPage').then((m) => ({ Component: m.default })) },
  ],
  nav: [{ to: '/findings', label: 'findings:nav.findings', icon: ShieldAlert, module: 'mitigation', group: 'monitor', order: 20 }],
  slots: { 'device.panels': DevicePanel },
}
