import { lazy, Suspense, type ComponentType } from 'react'
import { Siren } from 'lucide-react'
import type { Feature } from '@/app/feature'
import { Loading } from '@/components/common/States'

// Module response: rules without AI (S-RESP-3), AI proposals (S-RESP-1), approved execution (S-RESP-2, HIGH RISK, off by default), action catalog (S-RESP-4).
// D-40, D-41, D-44, D-46, D-47, D-48. Public route approve/:token is the page behind an emailed approval link.
const ResponseSettings = lazy(() => import('./ResponseSettings'))
const FindingPanel = lazy(() => import('./FindingPanel'))
const wrap = (C: ComponentType<Record<string, unknown>>): ComponentType<Record<string, unknown>> =>
  function Wrapped(props) { return <Suspense fallback={<Loading />}><C {...props} /></Suspense> }

export const feature: Feature = {
  id: 'response',
  publicRoutes: [{ path: 'approve/:token', lazy: () => import('./ApprovePage').then((m) => ({ Component: m.default })) }],
  routes: [
    { path: 'response', lazy: () => import('./ResponsePage').then((m) => ({ Component: m.default })) },
    // the confirm link sent to a chat approver (D-447 Zalo, D-414 Telegram): one page, signed in as the person it names
    { path: 'link/telegram', lazy: () => import('./ChatLinkPage').then((m) => ({ Component: m.default })) },
    { path: 'link/zalo', lazy: () => import('./ChatLinkPage').then((m) => ({ Component: m.default })) },
  ],
  nav: [{ to: '/response', label: 'response:nav.response', icon: Siren, module: 'response', group: 'detect', order: 30 }],
  settings: [{ id: 'response', label: 'response:settings.nav', module: 'response', minRole: 'admin', order: 45, element: <Suspense fallback={<Loading />}><ResponseSettings /></Suspense> }],
  slots: { 'finding.panels': wrap(FindingPanel) },
}
