import { ScrollText } from 'lucide-react'
import type { Feature } from '@/app/feature'
import SiemSettings from './SiemSettings'

// The logs module (S-LOG-1..4). Plugs into the slot `logs.panels` in LogsPage (the ai module puts the AI digest there).
export const feature: Feature = {
  id: 'logs',
  routes: [{ path: 'logs', lazy: () => import('./LogsPage').then((m) => ({ Component: m.default })) }],
  nav: [{ to: '/logs', label: 'logs:nav.logs', icon: ScrollText, module: 'logs', group: 'detect', order: 20 }],
  settings: [{ id: 'siem', label: 'logs:siem.nav', module: 'logs', minRole: 'admin', order: 50, element: <SiemSettings /> }],
}
