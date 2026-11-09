import { Globe } from 'lucide-react'
import type { Feature } from '@/app/feature'

// Module exposure (S-EXP-1). Quét chỉ khi đã xác thực sở hữu và có văn bản đồng ý (LEGAL §3).
export const feature: Feature = {
  id: 'exposure',
  routes: [
    { path: 'exposure', lazy: () => import('./ExposurePage').then((m) => ({ Component: m.default })) },
    { path: 'exposure/:id', lazy: () => import('./TargetPage').then((m) => ({ Component: m.default })) },
  ],
  nav: [{ to: '/exposure', label: 'exposure:nav', icon: Globe, module: 'exposure', group: 'assets', order: 20 }],
}
