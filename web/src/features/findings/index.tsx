import { ShieldAlert } from 'lucide-react'
import type { Feature } from '@/app/feature'

// Module findings: the findings list and detail. The "What to do" part belongs to the mitigation module; when it is off, only that part shows ModuleOff.
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
    { to: '/findings', label: 'common:shell.findings', icon: ShieldAlert, module: 'findings', group: 'monitor', order: 20 },
  ],
}
