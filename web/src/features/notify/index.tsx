import { lazy, Suspense, type ComponentType } from 'react'
import { Bell } from 'lucide-react'
import type { Feature } from '@/app/feature'
import { Loading } from '@/components/common/States'
import ChannelsSettings from './ChannelsSettings'

// Module notify (S-ALERT-1, S-ALERT-3, S-NOT-1). incidents at /incidents (trap, bad address, log anomaly, unknown device); old /alerts redirects.
// Vulnerability notices show on the finding (slot finding.panels). Channels, quiet hours and grouping live in Settings, section `channels`
// (tabs Channels and Settings); the sent-message history is its page /settings/channels/history.
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
    // the send history of Settings › Alert channels, a page of its own (outside the settings frame, as a scan run is)
    { path: 'settings/channels/history', lazy: () => import('./HistoryPage').then((m) => ({ Component: m.default })) },
  ],
  nav: [{ to: '/incidents', label: 'common:shell.incidents', icon: Bell, module: 'notify', group: 'monitor', order: 30 }],
  settings: [{ id: 'channels', label: 'common:shell.channels', module: 'notify', minRole: 'admin', order: 30, element: <ChannelsSettings /> }],
  slots: { 'finding.panels': wrap(FindingNotices) },
}
