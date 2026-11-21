import { FileText } from 'lucide-react'
import type { Feature } from '@/app/feature'

// Module reports (S-REP-1, S-REP-2). A sent report opens on its own page, exactly as sent; the assessment prints from /reports/print/pdpl.
export const feature: Feature = {
  id: 'reports',
  routes: [
    { path: 'reports', lazy: () => import('./ReportsPage').then((m) => ({ Component: m.default })) },
    { path: 'reports/sent/:id', lazy: () => import('./SentPage').then((m) => ({ Component: m.default })) },
    { path: 'reports/print/pdpl', lazy: () => import('./PrintPage').then((m) => ({ Component: m.PdplPrintPage })) },
  ],
  nav: [{ to: '/reports', label: 'reports:nav.reports', icon: FileText, module: 'reports', group: 'assist', order: 20 }],
}
