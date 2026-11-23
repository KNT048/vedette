import { Globe } from 'lucide-react'
import type { Feature } from '@/app/feature'

// The exposure module (S-EXP-1). Scans only after ownership is verified and a consent text exists (LEGAL §3).
export const feature: Feature = {
  id: 'exposure',
  routes: [
    { path: 'exposure', lazy: () => import('./ExposurePage').then((m) => ({ Component: m.default })) },
    { path: 'exposure/:id', lazy: () => import('./TargetPage').then((m) => ({ Component: m.default })) },
  ],
  nav: [{ to: '/exposure', label: 'common:shell.exposure', icon: Globe, module: 'exposure', group: 'assets', order: 20 }],
}
