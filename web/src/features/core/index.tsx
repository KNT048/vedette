import { lazy, Suspense, type ComponentType } from 'react'
import type { Feature } from '@/app/feature'
import { Loading } from '@/components/common/States'

// Module core: khung Cài đặt, cài đặt ban đầu, tài khoản (S-CORE-1..4, S-MCP-1). Các mục Cài đặt nạp lười để không phình gói chính.
const section = (load: () => Promise<{ default: ComponentType }>) => {
  const C = lazy(load)
  return <Suspense fallback={<Loading />}><C /></Suspense>
}
const page = (load: () => Promise<{ default: ComponentType }>) => () => load().then((m) => ({ Component: m.default }))

export const feature: Feature = {
  id: 'core',
  publicRoutes: [{ path: 'setup', lazy: page(() => import('./SetupPage')) }],
  routes: [
    {
      path: 'settings',
      lazy: () => import('./SettingsLayout').then((m) => ({ Component: m.SettingsLayout })),
      children: [
        { index: true, lazy: () => import('./SettingsLayout').then((m) => ({ Component: m.SettingsIndex })) },
        { path: ':section', lazy: () => import('./SettingsLayout').then((m) => ({ Component: m.SettingsRoute })) },
      ],
    },
    { path: 'account', lazy: page(() => import('./AccountPage')) },
  ],
  settings: [
    { id: 'general', label: 'core:settings.general', module: 'core', minRole: 'viewer', order: 10, element: section(() => import('./GeneralSection')) },
    { id: 'modules', label: 'core:settings.modules', module: 'core', minRole: 'viewer', order: 20, element: section(() => import('./ModulesSection')) },
    { id: 'users', label: 'core:settings.users', module: 'core', minRole: 'admin', order: 60, element: section(() => import('./UsersSection')) },
    { id: 'audit', label: 'core:settings.audit', module: 'core', minRole: 'admin', order: 70, element: section(() => import('./AuditSection')) },
    { id: 'updates', label: 'core:settings.updates', module: 'core', minRole: 'viewer', order: 80, element: section(() => import('./UpdatesSection')) },
    { id: 'network', label: 'core:settings.network', module: 'core', minRole: 'viewer', order: 75, element: section(() => import('./NetworkSection')) },
    { id: 'privacy', label: 'core:settings.privacy', module: 'core', minRole: 'viewer', order: 90, element: section(() => import('./PrivacySection')) },
    { id: 'mcp', label: 'core:settings.mcp', module: 'core', minRole: 'admin', order: 100, element: section(() => import('./McpSection')) },
    { id: 'data', label: 'core:settings.data', module: 'core', minRole: 'admin', order: 110, element: section(() => import('./DataSection')) },
  ],
}
