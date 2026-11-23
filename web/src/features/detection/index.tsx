import { ShieldAlert } from 'lucide-react'
import type { Feature } from '@/app/feature'

// Intrusion detection: what watches the network and its true state, the alerts of IPS and IDS events, one alert in full.
// The overview answers while any detection module is off, so the page belongs to core and is always in the Detect group.
export const feature: Feature = {
  id: 'detection',
  routes: [
    { path: 'detection', lazy: () => import('./DetectionPage').then((m) => ({ Component: m.default })) },
    { path: 'detection/alerts/:id', lazy: () => import('./AlertPage').then((m) => ({ Component: m.default })) },
  ],
  nav: [{ to: '/detection', label: 'common:shell.detection', icon: ShieldAlert, module: 'core', group: 'detect', order: 5 }],
}
