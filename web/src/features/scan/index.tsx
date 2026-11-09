import { ScanSearch } from 'lucide-react'
import type { Feature } from '@/app/feature'

// Module scan: quét xác nhận an toàn (S-SCAN-1..4) và quét có tài khoản (S-SCAN-5, module scan-credentialed).
export const feature: Feature = {
  id: 'scan',
  routes: [{ path: 'scans', lazy: () => import('./ScansPage').then((m) => ({ Component: m.default })) }],
  nav: [{ to: '/scans', label: 'scan:nav.scans', icon: ScanSearch, module: 'scan', group: 'assets', order: 30 }],
}
