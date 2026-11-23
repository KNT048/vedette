import { Radar } from 'lucide-react'
import type { Feature } from '@/app/feature'
import DevicePanel from './DevicePanel'

// Module honeypot (S-HP-1, S-HP-2). Cung cấp slot device.panels: lần chạm bẫy từ thiết bị.
export const feature: Feature = {
  id: 'honeypot',
  routes: [
    { path: 'honeypot', lazy: () => import('./HoneypotPage').then((m) => ({ Component: m.default })) },
    { path: 'honeypot/hits/:id', lazy: () => import('./HitPage').then((m) => ({ Component: m.default })) },
  ],
  nav: [{ to: '/honeypot', label: 'common:shell.honeypot', icon: Radar, module: 'honeypot', group: 'detect', order: 10 }],
  slots: { 'device.panels': DevicePanel },
}
