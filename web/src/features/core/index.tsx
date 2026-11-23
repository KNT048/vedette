import { lazy, Suspense, type ComponentType } from 'react'
import type { Feature } from '@/app/feature'
import { Loading } from '@/components/common/States'

// The core module: the Settings frame, initial setup, account (S-CORE-1..4, S-MCP-1). Settings sections load lazily so the main bundle does not grow.
const section = (load: () => Promise<{ default: ComponentType }>) => {
  const C = lazy(load)
  return <Suspense fallback={<Loading />}><C /></Suspense>
}
const page = (load: () => Promise<{ default: ComponentType }>) => () => load().then((m) => ({ Component: m.default }))

export const feature: Feature = {
  id: 'core',
  publicRoutes: [{ path: 'setup', lazy: page(() => import('./SetupPage')) }, { path: 'change-password', lazy: page(() => import('./ChangePasswordPage')) }, { path: 'sso/callback', lazy: page(() => import('./SsoCallbackPage')) }],
  routes: [
    {
      path: 'settings',
      lazy: () => import('./SettingsLayout').then((m) => ({ Component: m.SettingsLayout })),
      children: [
        { index: true, lazy: () => import('./SettingsLayout').then((m) => ({ Component: m.SettingsIndex })) },
        { path: ':section', lazy: () => import('./SettingsLayout').then((m) => ({ Component: m.SettingsRoute })) },
      ],
    },
    { path: 'account', lazy: () => import('./SettingsLayout').then((m) => ({ Component: m.AccountMoved })) },
  ],
  settings: [
    { id: 'general', label: 'core:settings.general', module: 'core', minRole: 'viewer', order: 10, element: section(() => import('./GeneralSection')) },
    { id: 'modules', label: 'core:settings.modules', module: 'core', minRole: 'viewer', order: 20, element: section(() => import('./ModulesSection')) },
    { id: 'users', label: 'core:settings.users', module: 'core', minRole: 'admin', order: 60, element: section(() => import('./UsersSection')) },
    { id: 'connections', label: 'core:settings.connections', module: 'core', minRole: 'admin', order: 65, element: section(() => import('./ConnectionsSection')) },
    { id: 'audit', label: 'core:settings.audit', module: 'core', minRole: 'admin', order: 70, element: section(() => import('./AuditSection')) },
    { id: 'updates', label: 'core:settings.updates', module: 'core', minRole: 'viewer', order: 80, element: section(() => import('./UpdatesSection')) },
    { id: 'network', label: 'core:settings.network', module: 'core', minRole: 'viewer', order: 75, element: section(() => import('./NetworkSection')) },
    { id: 'privacy', label: 'core:settings.privacy', module: 'core', minRole: 'viewer', order: 90, element: section(() => import('./PrivacySection')) },
    { id: 'mcp', label: 'core:settings.mcp', module: 'core', switchOf: 'mcp-server', minRole: 'admin', order: 100, element: section(() => import('./McpSection')) },
    { id: 'data', label: 'core:settings.data', module: 'core', minRole: 'admin', order: 110, element: section(() => import('./DataSection')) },
    { id: 'account', label: 'core:settings.myAccount', module: 'core', minRole: 'viewer', order: 1000, element: section(() => import('./AccountPage')) }, // last, where the My account link was (S-CORE-3)
  ],
}
