import { FileText } from 'lucide-react'
import type { Feature } from '@/app/feature'

// Module reports (S-REP-1, S-REP-2). Trang in dùng route riêng: /reports/print/weekly[/:id], /reports/print/pdpl.
export const feature: Feature = {
  id: 'reports',
  routes: [
    { path: 'reports', lazy: () => import('./ReportsPage').then((m) => ({ Component: m.default })) },
    { path: 'reports/print/weekly', lazy: () => import('./PrintPage').then((m) => ({ Component: m.WeeklyPrintPage })) },
    { path: 'reports/print/weekly/:id', lazy: () => import('./PrintPage').then((m) => ({ Component: m.WeeklyPrintPage })) },
    { path: 'reports/print/pdpl', lazy: () => import('./PrintPage').then((m) => ({ Component: m.PdplPrintPage })) },
  ],
  nav: [{ to: '/reports', label: 'reports:nav.reports', icon: FileText, module: 'reports', group: 'assist', order: 20 }],
}
