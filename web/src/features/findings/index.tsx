import { ShieldAlert } from 'lucide-react'
import type { Feature } from '@/app/feature'

// Module findings: danh sách + chi tiết phát hiện. Phần "Làm gì" (S-MIT-1) là của module mitigation, tắt thì chỉ phần đó hiện ModuleOff.
// The device page shows a device's findings in its Findings tab (DevicePanel.tsx).
export const feature: Feature = {
  id: 'findings',
  routes: [
    { path: 'findings', lazy: () => import('./FindingsPage').then((m) => ({ Component: m.default })) },
    { path: 'findings/:id', lazy: () => import('./FindingPage').then((m) => ({ Component: m.default })) },
    // The earlier Recommended updates page: its updates are the findings with the status Update recommended, under Findings
    { path: 'plan', lazy: () => import('./FindingsPage').then((m) => ({ Component: m.PlanRedirect })) },
  ],
  nav: [
    { to: '/findings', label: 'findings:nav.findings', icon: ShieldAlert, module: 'findings', group: 'monitor', order: 20 },
  ],
}
