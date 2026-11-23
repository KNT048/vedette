import { Radar } from 'lucide-react'
import type { Feature } from '@/app/feature'
import DevicePanel from './DevicePanel'

// The honeypot module (S-HP-1, S-HP-2). Provides the slot device.panels: trap hits from a device.
export const feature: Feature = {
  id: 'honeypot',
  routes: [
    { path: 'honeypot', lazy: () => import('./HoneypotPage').then((m) => ({ Component: m.default })) },
    { path: 'honeypot/hits/:id', lazy: () => import('./HitPage').then((m) => ({ Component: m.default })) },
  ],
  nav: [{ to: '/honeypot', label: 'honeypot:nav', icon: Radar, module: 'honeypot', group: 'detect', order: 10 }],
  slots: { 'device.panels': DevicePanel },
}
