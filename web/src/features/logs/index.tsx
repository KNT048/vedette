import { ScrollText } from 'lucide-react'
import type { Feature } from '@/app/feature'
import SiemSettings from './SiemSettings'

// Module logs (S-LOG-1..4). Cắm slot `logs.panels` ở LogsPage (module ai đặt digest AI vào đó).
export const feature: Feature = {
  id: 'logs',
  routes: [{ path: 'logs', lazy: () => import('./LogsPage').then((m) => ({ Component: m.default })) }],
  nav: [{ to: '/logs', label: 'logs:nav.logs', icon: ScrollText, module: 'logs', group: 'detect', order: 20 }],
  settings: [{ id: 'siem', label: 'logs:siem.nav', module: 'logs', minRole: 'admin', order: 50, element: <SiemSettings /> }],
}
