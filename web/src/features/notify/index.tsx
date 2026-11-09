import { lazy, Suspense, type ComponentType } from 'react'
import { Bell } from 'lucide-react'
import type { Feature } from '@/app/feature'
import { Loading } from '@/components/common/States'
import ChannelsSettings from './ChannelsSettings'

// Module notify (S-ALERT-1, S-ALERT-3, S-NOT-1). D-52: incidents at /incidents (trap, bad address, log anomaly, unknown device); old /alerts redirects.
// Vulnerability notices show on the finding (slot finding.panels). Channels, quiet hours, grouping and the sent-message history live in Settings, section `channels`.
const FindingNotices = lazy(() => import('./FindingNotices'))
const wrap = (C: ComponentType<Record<string, unknown>>): ComponentType<Record<string, unknown>> =>
  function Wrapped(props) { return <Suspense fallback={<Loading />}><C {...props} /></Suspense> }
const legacy = () => import('./LegacyRedirect').then((m) => ({ Component: m.default }))

export const feature: Feature = {
  id: 'notify',
  routes: [
    { path: 'incidents', lazy: () => import('./IncidentsPage').then((m) => ({ Component: m.default })) },
    { path: 'incidents/:id', lazy: () => import('./IncidentDetailPage').then((m) => ({ Component: m.default })) },
    { path: 'alerts', lazy: () => import('./LegacyIndexRedirect').then((m) => ({ Component: m.default })) },
    { path: 'alerts/:id', lazy: legacy },
  ],
  nav: [{ to: '/incidents', label: 'notify:nav.incidents', icon: Bell, module: 'notify', group: 'monitor', order: 30 }],
  settings: [{ id: 'channels', label: 'notify:channels.nav', module: 'notify', minRole: 'admin', order: 30, element: <ChannelsSettings /> }],
  slots: { 'finding.panels': wrap(FindingNotices) },
}
