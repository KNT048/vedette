import { lazy, Suspense, type ComponentType } from 'react'
import { Bot } from 'lucide-react'
import type { Feature } from '@/app/feature'
import { Loading } from '@/components/common/States'

// Module ai (S-AI-1, S-AI-3..6). Cài đặt, khung CVE và khung log tải lười để không kéo code AI vào trang chủ.
const AiSettings = lazy(() => import('./AiSettings'))
const CvePanels = lazy(() => import('./CvePanels'))
const LogsPanel = lazy(() => import('./LogsPanel'))
const wrap = (C: ComponentType<Record<string, unknown>>): ComponentType<Record<string, unknown>> =>
  function Wrapped(props) { return <Suspense fallback={<Loading />}><C {...props} /></Suspense> }

export const feature: Feature = {
  id: 'ai',
  routes: [{ path: 'assistant', lazy: () => import('./AssistantPage').then((m) => ({ Component: m.default })) }],
  nav: [{ to: '/assistant', label: 'ai:nav.assistant', icon: Bot, module: 'ai', group: 'assist', order: 10 }],
  settings: [{ id: 'ai', label: 'ai:settings.nav', module: 'ai', minRole: 'admin', order: 40, element: <Suspense fallback={<Loading />}><AiSettings /></Suspense> }],
  slots: { 'cve.panels': wrap(CvePanels), 'logs.panels': wrap(LogsPanel) },
}
